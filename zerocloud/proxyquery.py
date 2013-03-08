import ctypes
import re
import struct
import traceback
import time
import datetime
import uuid
from hashlib import md5
from urlparse import parse_qs
from urllib import unquote
from random import shuffle, randrange

import greenlet
from eventlet import GreenPile, GreenPool, sleep, Queue
from eventlet.green import socket
from eventlet.timeout import Timeout

from swift.common.http import HTTP_CONTINUE, is_success, \
    HTTP_INSUFFICIENT_STORAGE
from swift.proxy.controllers.base import update_headers, delay_denial, \
    Controller, cors_validation
from swift.common.utils import split_path, get_logger, TRUE_VALUES, \
    get_remote_client, ContextPool
from swift.proxy.server import ObjectController, ContainerController, \
    AccountController
from swift.common.bufferedhttp import http_connect
from swift.common.exceptions import ConnectionTimeout, ChunkReadTimeout, \
    ChunkWriteTimeout
from swift.common.constraints import check_utf8, MAX_FILE_SIZE, \
    MAX_META_NAME_LENGTH, MAX_META_VALUE_LENGTH, MAX_META_COUNT, \
    MAX_META_OVERALL_SIZE
from swift.common.swob import Request, Response, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestTimeout, HTTPRequestEntityTooLarge, \
    HTTPBadRequest, HTTPUnprocessableEntity, HTTPServiceUnavailable, \
    HTTPClientDisconnect
from swiftclient.client import quote

from zerocloud.tarstream import StringBuffer, UntarStream, RECORDSIZE, \
    TarStream, REGTYPE, BLOCKSIZE, NUL, ExtractedFile

try:
    import simplejson as json
except ImportError:
    import json

ACCESS_READABLE = 0x1
ACCESS_WRITABLE = 0x1 << 1
ACCESS_RANDOM = 0x1 << 2
ACCESS_NETWORK = 0x1 << 3
ACCESS_CDR = 0x1 << 4

device_map = {
    'stdin': ACCESS_READABLE,
    'stdout': ACCESS_WRITABLE,
    'stderr': ACCESS_WRITABLE,
    'input': ACCESS_RANDOM | ACCESS_READABLE,
    'output': ACCESS_RANDOM | ACCESS_WRITABLE,
    'debug': ACCESS_NETWORK,
    'image': ACCESS_CDR
    }

TAR_MIMES = ['application/x-tar', 'application/x-gtar', 'application/x-ustar']
CLUSTER_CONFIG_FILENAME = 'boot/cluster.map'
NODE_CONFIG_FILENAME = 'boot/system.map'
CONFIG_BYTE_SIZE = 128 * 1024

def merge_headers(current, new):
    if hasattr(new, 'keys'):
        for key in new.keys():
            if not current[key.lower()]:
                current[key.lower()] = str(new[key])
            else:
                current[key.lower()] += ',' + str(new[key])
    else:
        for key, value in new:
            if not current[key.lower()]:
                current[key.lower()] = str(value)
            else:
                current[key.lower()] += ',' + str(value)

def has_control_chars(line):
    if line:
        RE_ILLEGAL = u'([\u0000-\u0008\u000b-\u000c\u000e-\u001f\ufffe-\uffff])' +\
                         u'|' +\
                         u'([%s-%s][^%s-%s])|([^%s-%s][%s-%s])|([%s-%s]$)|(^[%s-%s])' %\
                         (unichr(0xd800),unichr(0xdbff),unichr(0xdc00),unichr(0xdfff),
                          unichr(0xd800),unichr(0xdbff),unichr(0xdc00),unichr(0xdfff),
                          unichr(0xd800),unichr(0xdbff),unichr(0xdc00),unichr(0xdfff),
                             )
        if re.search(RE_ILLEGAL, line):
            return True
        if re.search(r"[\x01-\x1F\x7F]", line):
            return True
    return False

def update_metadata(request, meta_data):
    if not meta_data:
        return None
    meta_count = 0
    meta_size = 0
    for key,value in meta_data.iteritems():
        meta_count += 1
        meta_size += len(key) + len(value)
        if len(key) > MAX_META_NAME_LENGTH:
            return 'Metadata name too long; max %d' % MAX_META_NAME_LENGTH
        elif len(value) > MAX_META_VALUE_LENGTH:
            return 'Metadata value too long; max %d' % MAX_META_VALUE_LENGTH
        elif meta_count > MAX_META_COUNT:
            return 'Too many metadata items; max %d' % MAX_META_COUNT
        elif meta_size > MAX_META_OVERALL_SIZE:
            return 'Total metadata too large; max %d' % MAX_META_OVERALL_SIZE
        request.headers['x-object-meta-%s' % key] = value

class CachedBody(object):

    def __init__(self, read_iter, cache=None, cache_size=CONFIG_BYTE_SIZE,
                 total_size=None):
        self.read_iter = read_iter
        self.total_size = total_size
        if cache:
            self.cache = cache
        else:
            self.cache = []
            size = 0
            for chunk in read_iter:
                self.cache.append(chunk)
                size += len(chunk)
                if size >= cache_size:
                    break

    def __iter__(self):
        if self.total_size:
            for chunk in self.cache:
                self.total_size -= len(chunk)
                if self.total_size < 0:
                    yield chunk[:self.total_size]
                    break
                else:
                    yield  chunk
            if self.total_size > 0:
                for chunk in self.read_iter:
                    self.total_size -= len(chunk)
                    if self.total_size < 0:
                        yield chunk[:self.total_size]
                        break
                    else:
                        yield  chunk
            for chunk in self.read_iter:
                pass
        else:
            for chunk in self.cache:
                yield chunk
            for chunk in self.read_iter:
                yield chunk

class FinalBody(object):

    def __init__(self, app_iter):
        self.app_iters = [app_iter]

    def __iter__(self):
        for app_iter in self.app_iters:
            for chunk in app_iter:
                yield chunk

    def append(self, app_iter):
        self.app_iters.append(app_iter)


class SequentialResponseBody(object):

    def __init__(self, response, size):
        self.response = response
        self.pos = 0
        self.size = size
        self.max_transfer = self.size.pop(0)

    def read(self, size=None):
        try:
            if size is None or (self.pos + size > self.max_transfer):
                size = self.max_transfer - self.pos
            self.pos += size
            return self.response.read(size)
        except Exception:
            raise

    def next_response(self):
        if len(self.size) > 0:
            self.pos = 0
            self.max_transfer = self.size.pop(0)

    def get_content_length(self):
        return self.max_transfer

class NameService(object):

    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def start(self, pool, peers):
        self.sock.bind(('', 0))
        self.peers = peers
        self.thread = pool.spawn(self._run)
        return self.sock.getsockname()[1]

    def _run(self):
        bind_map = {}
        conn_map = {}
        peer_map = {}
        while 1:
            try:
                message,peer_address = self.sock.recvfrom(65535)
                offset = 0
                peer_id = struct.unpack_from('!I', message, offset)[0]
                offset += 4
                count = struct.unpack_from('!I', message, offset)[0]
                offset += 4
                for i in range(count):
                    connecting_host, _junk, port = struct.unpack_from('!IIH', message, offset)[0:3]
                    bind_map.setdefault(peer_id, {})[connecting_host] = port
                    offset += 10
                conn_map[peer_id] = ctypes.create_string_buffer(message[offset:])
                peer_map.setdefault(peer_id, {})[0] = peer_address[0]
                peer_map.setdefault(peer_id, {})[1] = peer_address[1]

                if len(peer_map) == self.peers:
                    for peer_id in peer_map.iterkeys():
                        reply = conn_map[peer_id]
                        offset = 0
                        count = struct.unpack_from('!I', reply, offset)[0]
                        offset += 4
                        for i in range(count):
                            connecting_host = struct.unpack_from('!I', reply, offset)[0]
                            port = bind_map[connecting_host][peer_id]
                            struct.pack_into('!4sH', reply, offset + 4,
                                socket.inet_pton(socket.AF_INET, peer_map[connecting_host][0]), port)
                            offset += 10
                        self.sock.sendto(reply, (peer_map[peer_id][0], peer_map[peer_id][1]))
            except greenlet.GreenletExit:
                return
            except Exception:
                print traceback.format_exc()
                pass

    def stop(self):
        self.thread.kill()
        self.sock.close()

class ProxyQueryMiddleware(object):

    def __init__(self, app, conf, logger=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='proxy-query')
        self.app.zerovm_maxnexe = int(conf.get('zerovm_maxnexe', 256 * 1048576))
        self.app.zerovm_maxiops = int(conf.get('zerovm_maxiops', 1024 * 1048576))
        self.app.zerovm_maxoutput = int(conf.get('zerovm_maxoutput', 1024 * 1048576))
        self.app.zerovm_maxinput = int(conf.get('zerovm_maxinput', 1024 * 1048576))
        self.app.zerovm_maxconfig = int(conf.get('zerovm_maxconfig', 65536))
        self.app.zerovm_ns_hostname = conf.get('zerovm_ns_hostname')
        self.app.zerovm_ns_maxpool = int(conf.get('zerovm_ns_maxpool', 1000))
        self.app.zerovm_ns_thrdpool = GreenPool(self.app.zerovm_ns_maxpool)

        self.app.max_upload_time = int(conf.get('max_upload_time', 86400))
        self.app.network_chunk_size = int(conf.get('network_chunk_size', 65536))
        self.app.cdr_account = conf.get('user_stats_account', 'userstats')
        self.app.version = 'v1'
        self.app.zerovm_uses_newest = conf.get('zerovm_uses_newest', 'f').lower() in TRUE_VALUES
        self.app.zerovm_use_cors = conf.get('zerovm_use_cors', 'f').lower() in TRUE_VALUES
        self.app.zerovm_accounting_enabled = conf.get('zerovm_accounting_enabled', 'f').lower() in TRUE_VALUES
        self.app.zerovm_content_type = conf.get('zerovm_default_content_type', 'application/octet-stream')

    def __call__(self, env, start_response):

        req = Request(env)
        if 'x-zerovm-execute' in req.headers or req.path.startswith('/exec/'):
            controller = None
            if req.content_length and req.content_length < 0:
                return HTTPBadRequest(request=req,
                    body='Invalid Content-Length')(env, start_response)
            try:
                version, account, container, obj = split_path(req.path, 1, 4, True)
                path_parts = dict(version=version,
                    account_name=account,
                    container_name=container,
                    object_name=obj)
                if account:
                    controller = self.get_controller(account, container, obj)
            except ValueError:
                return HTTPNotFound(request=req)(env, start_response)

            if not check_utf8(req.path_info):
                return HTTPPreconditionFailed(request=req, body='Invalid UTF8')(env, start_response)
            if not controller:
                return HTTPPreconditionFailed(request=req, body='Bad URL')(env, start_response)

            if 'swift.trans_id' not in req.environ:
                # if this wasn't set by an earlier middleware, set it now
                trans_id = 'tx' + uuid.uuid4().hex
                req.environ['swift.trans_id'] = trans_id
                self.logger.txn_id = trans_id
            req.headers['x-trans-id'] = req.environ['swift.trans_id']
            controller.trans_id = req.environ['swift.trans_id']
            self.logger.client_ip = get_remote_client(req)
            if path_parts['version']:
                req.path_info_pop()
            handler = controller.zerovm_query
#            if 'swift.authorize' in req.environ:
#                resp = req.environ['swift.authorize'](req)
#                if not resp:
#                    del req.environ['swift.authorize']
#                else:
#                    if not getattr(handler, 'delay_denial', None):
#                        return resp(env, start_response)
            start_time = time.time()
            res = handler(req)
            perf = time.time() - start_time
            if 'x-nexe-cdr-line' in res.headers:
                res.headers['x-nexe-cdr-line'] = '%.3f, %s' % (perf, res.headers['x-nexe-cdr-line'])
        else:
            return self.app(env, start_response)
        return res(env, start_response)

    def get_controller(self, account, container, obj):
        return ClusterController(self.app, account, container, obj)


class ZvmNode(object):
    def __init__(self, nid, name, nexe_path, args=None, env=None):
        self.id = nid
        self.name = name
        self.exe = nexe_path
        self.args = args
        self.env = env
        self.channels = []
        self.connect = []
        self.bind = []

    def add_channel(self, device, access, path=None,
                    content_type='application/octet-stream', meta_data=None):
        channel = ZvmChannel(device, access, path, content_type, meta_data)
        self.channels.append(channel)

    def get_channel(self, device=None, path=None):
        if device:
            for chan in self.channels:
                if chan.device == device:
                    return chan
        if path:
            for chan in self.channels:
                if chan.path == path:
                    return chan
        return None

    def add_connections(self, nodes, connect_list):
        for bind_name in connect_list:
            if nodes.get(bind_name):
                bind_node = nodes.get(bind_name)
                if bind_node is self:
                    raise Exception('Cannot bind to itself: %s' % bind_name)
                bind_node.bind.append(self.name)
                self.connect.append(bind_name)
            elif nodes.get(bind_name + '-1'):
                i = 1
                bind_node = nodes.get(bind_name + '-' + str(i))
                while bind_node:
                    if not bind_node is self:
                        bind_node.bind.append(self.name)
                        self.connect.append(bind_name + '-' + str(i))
                    i += 1
                    bind_node = nodes.get(bind_name + '-' + str(i))
            else:
                raise Exception('Non-existing node in connect %s' % bind_name)


class ZvmChannel(object):
    def __init__(self, device, access, path=None,
                 content_type='application/octet-stream', meta_data=None):
        self.device = device
        self.access = access
        self.path = path
        self.content_type = content_type
        self.meta = meta_data if meta_data else {}


class ZvmResponse(object):
    def __init__(self, name, status,
                 nexe_status, nexe_retcode, nexe_etag):
        self.name = name
        self.status = status
        #self.body = body
        self.nexe_status = nexe_status
        self.nexe_retcode = nexe_retcode
        self.nexe_etag = nexe_etag


class NodeEncoder(json.JSONEncoder):

    def default(self, o):
        if isinstance(o, ZvmNode) or isinstance(o, ZvmChannel):
            return o.__dict__
        elif isinstance(o, Response):
            return str(o.__dict__)
        return json.JSONEncoder.default(self, o)


class ClusterController(Controller):

    server_type = _('Object')

    def __init__(self, app, account_name, container_name, obj_name,
                 **kwargs):
        Controller.__init__(self, app)
        self.account_name = unquote(account_name)
        self.container_name = unquote(container_name) if container_name else None
        self.obj_name = unquote(obj_name) if obj_name else None
        self.nodes = {}

    def copy_request(self, request):
        env = request.environ.copy()
        return Request(env)

    def get_local_address(self, node):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect((node['ip'], node['port']))
        result = s.getsockname()[0]
        s.shutdown(socket.SHUT_RDWR)
        s.close()
        return result

    def get_random_nodes(self):
        partition_count = self.app.object_ring.partition_count
        part = randrange(0, partition_count)
        nodes = self.app.object_ring.get_part_nodes(part)
        return part, nodes

    def list_account(self, req, account, mask=None, marker=None):
        new_req = req.copy_get()
        new_req.query_string = 'format=json'
        if marker:
            new_req.query_string += '&marker=' + marker
        resp = AccountController(self.app, account).GET(new_req)
        if resp.status_int == 204:
            data = resp.body
            return []
        if resp.status_int < 200 or resp.status_int >= 300:
            raise Exception('Error querying object server')
        data = json.loads(resp.body)
        if marker:
            return data
        ret = []
        while data:
            for item in data:
                if not mask or mask.match(item['name']):
                    ret.append(item['name'])
            marker = data[-1]['name']
            data = self.list_account(req, account, None, marker)
        return ret

    def list_container(self, req, account, container, mask=None, marker=None):
        new_req = req.copy_get()
        new_req.path_info += '/' + quote(container)
        new_req.query_string = 'format=json'
        if marker:
            new_req.query_string += '&marker=' + marker
        resp = ContainerController(self.app, account, container).GET(new_req)
        if resp.status_int == 204:
            data = resp.body
            return []
        if resp.status_int < 200 or resp.status_int >= 300:
            raise Exception('Error querying object server')
        data = json.loads(resp.body)
        if marker:
            return data
        ret = []
        while data:
            for item in data:
                if not mask or mask.match(item['name']):
                    ret.append(item['name'])
            marker = data[-1]['name']
            data = self.list_container(req, account, container,
                None, marker)
        return ret

    def parse_cluster_config(self, req, cluster_config):
        try:
            nid = 1
            for node in cluster_config:
                node_name = node.get('name')
                if not node_name:
                    return HTTPBadRequest(request=req,
                        body='Must specify node name')
                if has_control_chars(node_name):
                    return HTTPBadRequest(request=req,
                        body='Invalid node name')
                nexe = node.get('exec')
                if not nexe:
                    return HTTPBadRequest(request=req,
                        body='Must specify exec stanza for %s' % node_name)
                nexe_path = nexe.get('path')
                if not nexe_path:
                    return HTTPBadRequest(request=req,
                        body='Must specify executable path for %s' % node_name)
                nexe_args = nexe.get('args')
                nexe_env = nexe.get('env')
                if has_control_chars('%s %s %s' % (nexe_path, nexe_args, nexe_env)):
                    return HTTPBadRequest(request=req,
                        body='Invalid nexe property')
                node_count = node.get('count', 1)
                if not isinstance(node_count, int):
                    return HTTPBadRequest(request=req,
                        body='Invalid node count')
                file_list = node.get('file_list')
                read_list = []
                write_list = []
                other_list = []

                if file_list:
                    for f in file_list:
                        device = f.get('device')
                        if has_control_chars(device):
                            return HTTPBadRequest(request=req,
                                body='Bad device name')
                        path = f.get('path')
                        if has_control_chars(path):
                            return HTTPBadRequest(request=req,
                                body='Bad device path')
                        if not device:
                            return HTTPBadRequest(request=req,
                                body='Must specify device for file in %s'
                                % node_name)
                        access = device_map.get(device, -1)
                        if access < 0:
                            return HTTPBadRequest(request=req,
                                body='Unknown device %s in %s'
                                % (device, node_name))
                        if access & ACCESS_READABLE:
                            read_list.insert(0, f)
                        elif access & ACCESS_CDR:
                            read_list.append(f)
                        elif access & ACCESS_WRITABLE:
                            write_list.append(f)
                        else:
                            other_list.append(f)

                    read_group = 0
                    for f in read_list:
                        device = f.get('device')
                        access = device_map.get(device)
                        path = f.get('path')
                        if path and '*' in path:
                            read_group = 1
                            list = []
                            try:
                                container, object = split_path(
                                    path, 1, 2, True)
                            except ValueError:
                                return HTTPBadRequest(request=req,
                                    body='Invalid path %s in %s'
                                    % (path, node_name))
                            if '*' in container:
                                container = re.escape(container).replace(
                                    '\\*', '.*'
                                )
                                mask = re.compile(container)
                                try:
                                    containers = self.list_account(req,
                                        self.account_name, mask)
                                except Exception:
                                    return HTTPBadRequest(request=req,
                                        body='Error querying object server '
                                             'for account %s'
                                            % self.account_name)
                                if object:
                                    if '*' in object:
                                        object = re.escape(object).replace(
                                            '\\*', '.*'
                                        )
                                    mask = re.compile(object)
                                else:
                                    mask = None
                                for c in containers:
                                    try:
                                        obj_list = self.list_container(req,
                                            self.account_name, c, mask)
                                    except Exception:
                                        return HTTPBadRequest(request=req,
                                            body='Error querying object server '
                                                 'for container %s' % c)
                                    for obj in obj_list:
                                        list.append('/' + c + '/' + obj)
                            else:
                                object = re.escape(object).replace(
                                    '\\*', '.*'
                                )
                                mask = re.compile(object)
                                try:
                                    for obj in self.list_container(req,
                                        self.account_name, container, mask):
                                        list.append('/' + container + '/' + obj)
                                except Exception:
                                    return HTTPBadRequest(request=req,
                                        body='Error querying object server '
                                             'for container %s' % container)
                            if not list:
                                return HTTPBadRequest(request=req,
                                    body='No objects found in path %s' % path)
                            for i in range(len(list)):
                                new_name = self.create_name(node_name, i+1)
                                new_path = list[i]
                                new_node = self.nodes.get(new_name)
                                if not new_node:
                                    new_node = ZvmNode(nid, new_name,
                                        nexe_path, nexe_args, nexe_env)
                                    nid += 1
                                    self.nodes[new_name] = new_node
                                new_node.add_channel(device, access,
                                    path=new_path)
                            node_count = len(list)
                        elif path:
                            if node_count > 1:
                                for i in range(1, node_count + 1):
                                    new_name = self.create_name(node_name, i)
                                    new_path = path
                                    new_node = self.nodes.get(new_name)
                                    if not new_node:
                                        new_node = ZvmNode(nid, new_name,
                                            nexe_path, nexe_args, nexe_env)
                                        nid += 1
                                        self.nodes[new_name] = new_node
                                    new_node.add_channel(device, access,
                                        path=new_path)
                            else:
                                new_node = self.nodes.get(node_name)
                                if not new_node:
                                    new_node = ZvmNode(nid, node_name, nexe_path,
                                        nexe_args, nexe_env)
                                    nid += 1
                                    self.nodes[node_name] = new_node
                                new_node.add_channel(device, access, path=path)
                        else:
                            return HTTPBadRequest(request=req,
                                body='Readable file must have a path')

                    for f in write_list:
                        device = f.get('device')
                        access = device_map.get(device)
                        path = f.get('path')
                        content_type = f.get('content_type', self.app.zerovm_content_type)
                        meta = f.get('meta', None)
                        if path and '*' in path:
                            if read_group:
                                read_mask = read_list[0].get('path')
                                read_count = read_mask.count('*')
                                write_count = path.count('*')
                                if read_count != write_count:
                                    return HTTPBadRequest(request=req,
                                        body='Wildcards in input %s cannot be'
                                             ' resolved into output %s'
                                            % (read_mask, path))
                                read_mask = re.escape(read_mask).replace(
                                    '\\*', '(.*)'
                                )
                                read_mask = re.compile(read_mask)
                                for i in range(1, node_count + 1):
                                    new_name = self.create_name(node_name, i)
                                    new_path = path
                                    new_node = self.nodes.get(new_name)
                                    read_path = new_node.channels[0].path
                                    m = read_mask.match(read_path)
                                    for j in range(1, m.lastindex + 1):
                                        new_path = new_path.replace('*',
                                            m.group(j), 1)
                                    new_node.add_channel(device, access,
                                        path=new_path, content_type=content_type,
                                        meta_data=meta)
                            else:
                                for i in range(1, node_count + 1):
                                    new_name = self.create_name(node_name, i)
                                    new_path = path
                                    new_path = new_path.replace('*', new_name)
                                    new_node = self.nodes.get(new_name)
                                    if not new_node:
                                        new_node = ZvmNode(nid, new_name,
                                            nexe_path, nexe_args, nexe_env)
                                        nid += 1
                                        self.nodes[new_name] = new_node
                                    new_node.add_channel(device, access,
                                        path=new_path, content_type=content_type,
                                        meta_data=meta)
                        elif path:
                            if node_count > 1:
                                return HTTPBadRequest(request=req,
                                    body='Single path %s for multiple node '
                                         'definition: %s, please use wildcard'
                                    % (path, node_name))
                            new_node = self.nodes.get(node_name)
                            if not new_node:
                                new_node = ZvmNode(nid, node_name, nexe_path,
                                    nexe_args, nexe_env)
                                nid += 1
                                self.nodes[node_name] = new_node
                            new_node.add_channel(device, access,
                                path=path, content_type=content_type,
                                meta_data=meta)
                        else:
                            if 'stdout' not in device \
                            and 'stderr' not in device:
                                return HTTPBadRequest(request=req,
                                    body='Immediate response is not available '
                                         'for device %s' % device)
                            if node_count > 1:
                                for i in range(1, node_count + 1):
                                    new_name = self.create_name(node_name, i)
                                    new_node = self.nodes.get(new_name)
                                    new_node.add_channel(device, access,
                                        content_type=f.get('content_type', 'text/html'))
                            else:
                                new_node = self.nodes.get(node_name)
                                if not new_node:
                                    new_node = ZvmNode(nid, node_name,
                                        nexe_path, nexe_args, nexe_env)
                                    nid += 1
                                    self.nodes[node_name] = new_node
                                new_node.add_channel(device, access,
                                    content_type=f.get('content_type', 'text/html'))

                    for f in other_list:
                        # only debug channel is here, for now
                        device = f.get('device')
                        if not 'debug' in device:
                            return HTTPBadRequest(request=req,
                                body='Bad device name %s' % device)
                        access = device_map.get(device)
                        path = f.get('path')
                        if not path:
                            return HTTPBadRequest(request=req,
                                body='Path required for device %s' % device)
                        if node_count > 1:
                            for i in range(1, node_count + 1):
                                new_name = self.create_name(node_name, i)
                                new_node = self.nodes.get(new_name)
                                if not new_node:
                                    new_node = ZvmNode(nid, new_name,
                                        nexe_path, nexe_args, nexe_env)
                                    nid += 1
                                    self.nodes[new_name] = new_node
                                new_node.add_channel(device, access, path=path)
                        else:
                            new_node = self.nodes.get(node_name)
                            if not new_node:
                                new_node = ZvmNode(nid, node_name, nexe_path,
                                    nexe_args, nexe_env)
                                nid += 1
                                self.nodes[node_name] = new_node
                            new_node.add_channel(device, access, path=path)

        except Exception:
            print traceback.format_exc()
            return HTTPUnprocessableEntity(request=req)

        for node in cluster_config:
            connect = node.get('connect')
            if not connect:
                continue
            node_name = node.get('name')
            if self.nodes.get(node_name):
                connect_node = self.nodes.get(node_name)
                try:
                    connect_node.add_connections(self.nodes, connect)
                except Exception:
                    return HTTPBadRequest(request=req,
                        body='Invalid connect string for node %s' % node_name)
            elif self.nodes.get(node_name + '-1'):
                j = 1
                connect_node = self.nodes.get(self.create_name(node_name, j))
                while connect_node:
                    try:
                        connect_node.add_connections(self.nodes, connect)
                    except Exception, e:
                        return HTTPBadRequest(request=req,
                            body='Invalid connect string for node %s: %s'
                                % (connect_node.name, e))
                    j += 1
                    connect_node = self.nodes.get(
                        self.create_name(node_name, j))
            else:
                return HTTPBadRequest(request=req,
                    body='Non existing node in connect string for node %s'
                        % node_name)

        for node in self.nodes.itervalues():
            tmp = []
            for dst in node.bind:
                dst_id = self.nodes.get(dst).id
                tmp.append(
                ','.join(['tcp:%d:0' % dst_id,
                          '/dev/in/' + dst,
                          '0',
                          str(self.app.zerovm_maxiops),
                          str(self.app.zerovm_maxinput),
                          '0,0'])
                )
            node.bind = tmp
            tmp = []
            for dst in node.connect:
                dst_id = self.nodes.get(dst).id
                tmp.append(
                ','.join(['tcp:%d:' % dst_id,
                          '/dev/out/' + dst,
                          '0,0,0',
                          str(self.app.zerovm_maxiops),
                          str(self.app.zerovm_maxoutput)])
                )
            node.connect = tmp

        #for n in self.nodes.itervalues():
        #    print n.__dict__

        return None

    @delay_denial
    @cors_validation
    def zerovm_query(self, req):
        user_image = None
        if req.method in 'GET':
        # We need to create system map from GET request
            if not self.container_name or not self.obj_name:
                return HTTPNotFound(request=req, headers=req.headers)
            nexe = '/%s/%s' % (self.container_name, self.obj_name)
            node = ZvmNode(1, 'get', nexe)
            conf = parse_qs(req.query_string)
            req.path_info = '/' + self.account_name
            req.method = 'POST'
            req.headers['x-zerovm-execute'] = '1.0'
            if conf.get('args', None):
                node.args = conf['args'][0]
            if conf.get('env', None):
                for key, val in conf['env'].split(':'):
                    node.env[key] = val
            if conf.get('file', None):
                node.add_channel('stdin', device_map.get('stdin'),
                    path=conf['file'][0])
            node.add_channel('stdout', device_map.get('stdout'),
                content_type=conf.get('content_type', None)[0])
            self.nodes['get'] = node
        elif req.method in 'POST':
            if 'content-type' not in req.headers:
                return HTTPBadRequest(request=req,
                    body='Must specify Content-Type')
            upload_expiration = time.time() + self.app.max_upload_time
            etag = md5()
            cluster_config = ''
            req.bytes_transferred = 0
            path_list = [StringBuffer(CLUSTER_CONFIG_FILENAME),
                         StringBuffer(NODE_CONFIG_FILENAME)]
            read_iter = iter(lambda:
                req.environ['wsgi.input']
                .read(self.app.network_chunk_size), '')
            if req.headers['content-type'].split(';')[0].strip() in TAR_MIMES:
            # Buffer first blocks of tar file and search for the system map
                if not 'content-length' in req.headers:
                    return HTTPBadRequest(request=req,
                        body='Must specify Content-Length')

                cached_body = CachedBody(read_iter)
                user_image = iter(cached_body)
                untar_stream = UntarStream(cached_body.cache, path_list)
                for chunk in untar_stream:
                    req.bytes_transferred += len(chunk)
                    etag.update(chunk)
                for buffer in path_list:
                    if buffer.is_closed:
                        cluster_config = buffer.body
                        break
                if not cluster_config:
                    return HTTPBadRequest(request=req,
                        body='System boot map was not found in request')
                try:
                    cluster_config = json.loads(cluster_config)
                except Exception:
                    return HTTPUnprocessableEntity(body='Cound not parse system map')
                error = self.parse_cluster_config(req, cluster_config)
                if error:
                    self.app.logger.warn(
                        _('ERROR Error parsing config: %s'), cluster_config)
                    return error
            elif req.headers['content-type'].split(';')[0].strip() in 'application/json':
            # System map was sent as a POST body
                for chunk in read_iter:
                    req.bytes_transferred += len(chunk)
                    if time.time() > upload_expiration:
                        return HTTPRequestTimeout(request=req)
                    if req.bytes_transferred > self.app.zerovm_maxconfig:
                        return HTTPRequestEntityTooLarge(request=req)
                    etag.update(chunk)
                    cluster_config += chunk
                if 'content-length' in req.headers and \
                   int(req.headers['content-length']) != req.bytes_transferred:
                    return HTTPClientDisconnect(request=req, body='application/json post unfinished')
                etag = etag.hexdigest()
                if 'etag' in req.headers and\
                   req.headers['etag'].lower() != etag:
                    return HTTPUnprocessableEntity(request=req)
                try:
                    cluster_config = json.loads(cluster_config)
                except Exception:
                    return HTTPUnprocessableEntity(body='Cound not parse system map')
                error = self.parse_cluster_config(req, cluster_config)
                if error:
                    self.app.logger.warn(
                        _('ERROR Error parsing config: %s'), cluster_config)
                    return error
            elif req.headers['content-type'].startswith('text/'):
            # We got a text file in POST request
            # assume that it is a script and create system map
                return HTTPBadRequest(request=req,
                    body='Unsupported Content-Type')
            else:
                return HTTPBadRequest(request=req,
                    body='Unsupported Content-Type')
            req.path_info = '/' + self.account_name
        else:
            return HTTPBadRequest(request=req,
                body='Invalid request')

        node_list = []
        for k in sorted(self.nodes.iterkeys()):
            node_list.append(self.nodes[k])

        #for n in node_list:
        #    print n.__dict__

        image_resp = None
        if user_image:
            image_resp = Response(app_iter=user_image,
                headers={'Content-Length':req.headers['content-length']})
            image_resp.nodes = []

        data_sources = []
        pile = GreenPile(len(node_list))
        partition, obj_nodes = self.get_random_nodes()
        if self.app.zerovm_ns_hostname:
            addr = self.app.zerovm_ns_hostname
        else:
            for n in obj_nodes:
                addr = self.get_local_address(n)
                if addr:
                    break
        if not addr:
            return HTTPServiceUnavailable(
                body='Cannot find own address, check zerovm_ns_hostname')
        ns_server = None
        ns_port = None
        if len(node_list) > 1:
            ns_server = NameService()
            if self.app.zerovm_ns_thrdpool.free() <= 0:
                return HTTPServiceUnavailable(body='Cluster slot not available',
                    request=req)
            ns_port = ns_server.start(self.app.zerovm_ns_thrdpool, len(self.nodes))
        for node in node_list:
            if ns_server:
                node.name_service = 'udp:%s:%d' % (addr, ns_port)
            sysmap = json.dumps(node, cls=NodeEncoder)
            #print sysmap
            sysmap_iter = iter([sysmap])
            sysmap_resp = Response(app_iter=sysmap_iter,
            headers={'Content-Length':str(len(sysmap))})
            data_sources.insert(0, sysmap_resp)
            node.last_data = sysmap_resp
            sysmap_resp.nodes = [{'node':node, 'dev':'sysmap'}]
            nexe_headers = {
                'x-nexe-system': node.name,
                'x-nexe-status': 'ZeroVM did not run',
                'x-nexe-retcode' : 0,
                'x-nexe-etag': '',
                'x-nexe-validation': 0,
                'x-nexe-cdr-line': '0 0 0 0 0 0 0 0 0 0 0 0'
            }
            path_info = req.path_info
            top_channel = node.channels[0]
            if top_channel.path and top_channel.path[0] == '/' and \
               (top_channel.access & (ACCESS_READABLE | ACCESS_CDR)):
                path_info += top_channel.path
                account, container, obj = split_path(path_info, 1, 3, True)
                partition, obj_nodes = self.app.object_ring.get_nodes(
                    account, container, obj)
            else:
                partition, obj_nodes = self.get_random_nodes()
            exec_request = Request.blank(path_info,
                environ=req.environ, headers=req.headers)
            exec_request.path_info = path_info
            exec_request.content_length = None
            exec_request.etag = None
            exec_request.headers['content-type'] = TAR_MIMES[0]
            exec_request.headers['transfer-encoding'] = 'chunked'
            exec_request.headers['x-account-name'] = self.account_name
            if 'swift.authorize' in exec_request.environ:
                aresp = exec_request.environ['swift.authorize'](exec_request)
                if aresp:
                    return aresp

            channels = []
            if node.exe[0] == '/':
                channels.append(ZvmChannel('boot', None, node.exe))
            if len(node.channels) > 1:
                for ch in node.channels[1:]:
                    if ch.path and ch.path[0] == '/' and \
                       (ch.access & (ACCESS_READABLE | ACCESS_CDR)):
                        channels.append(ch)

            for ch in channels:
                source_resp = None
                load_from = req.path_info + ch.path
                for resp in data_sources:
                    if resp.request and load_from == resp.request.path_info:
                        source_resp = resp
                        break
                if not source_resp:
                    source_req = req.copy_get()
                    source_req.path_info = load_from
                    if self.app.zerovm_uses_newest:
                        source_req.headers['X-Newest'] = 'true'
                    acct, src_container_name, src_obj_name =\
                        split_path(load_from, 1, 3, True)
                    container_info = self.container_info(acct, src_container_name)
                    source_req.acl = container_info['read_acl']
                    #if 'boot' in ch.device:
                    #    source_req.acl = container_info['exec_acl']
                    source_resp =\
                        ObjectController(self.app, acct,
                            src_container_name, src_obj_name)\
                        .GET(source_req)
                    if source_resp.status_int >= 300:
                        update_headers(source_resp, nexe_headers)
                        return source_resp
                    source_resp.nodes = []
                    data_sources.append(source_resp)
                node.last_data = source_resp
                source_resp.nodes.append({'node':node, 'dev':ch.device})
            if image_resp:
                node.last_data = image_resp
                image_resp.nodes.append({'node':node, 'dev':'image'})
            node_iter = self.iter_nodes(partition, obj_nodes, self.app.object_ring)
            pile.spawn(self._connect_exec_node, node_iter, partition,
                exec_request, self.app.logger.thread_locals, node,
                nexe_headers)
        if image_resp:
            data_sources.append(image_resp)

        conns = [conn for conn in pile if conn]
        if len(conns) < len(node_list):
            self.app.logger.exception(
                _('ERROR Cannot find suitable node to execute code on'))
            return HTTPServiceUnavailable(
                body='Cannot find suitable node to execute code on')

        for data_src in data_sources:
            data_src.conns = []
            for node in data_src.nodes:
                for conn in conns:
                    if conn.cnode is node['node']:
                        conn.last_data = node['node'].last_data
                        data_src.conns.append({'conn':conn, 'dev':node['dev']})

        #chunked = req.headers.get('transfer-encoding')
        chunked = True
        try:
            with ContextPool(len(node_list)) as pool:
                for conn in conns:
                    conn.failed = False
                    conn.queue = Queue(self.app.put_queue_depth)
                    conn.tar_stream = TarStream()
                    pool.spawn(self._send_file, conn, req.path)

                for data_src in data_sources:
                    data_src.bytes_transferred = 0
                    for conn in data_src.conns:
                        info = conn['conn'].tar_stream.create_tarinfo(
                            REGTYPE, conn['dev'],
                            data_src.content_length)
                        for chunk in conn['conn'].tar_stream._serve_chunk(info):
                            if not conn['conn'].failed:
                                conn['conn'].queue.put('%x\r\n%s\r\n' %
                                                       (len(chunk), chunk)
                                if chunked else chunk)
                    while True:
                        with ChunkReadTimeout(self.app.client_timeout):
                            try:
                                data = next(data_src.app_iter)
                            except StopIteration:
                                blocks, remainder = divmod(data_src.bytes_transferred,
                                    BLOCKSIZE)
                                if remainder > 0:
                                    nulls = NUL * (BLOCKSIZE - remainder)
                                    for conn in data_src.conns:
                                        for chunk in conn['conn'].tar_stream._serve_chunk(nulls):
                                            if not conn['conn'].failed:
                                                conn['conn'].queue.put('%x\r\n%s\r\n' % (len(chunk), chunk)
                                                if chunked else chunk)
                                            else:
                                                return HTTPServiceUnavailable(request=req)
                                for conn in data_src.conns:
                                    if conn['conn'].last_data is data_src:
                                        if conn['conn'].tar_stream.data:
                                            data = conn['conn'].tar_stream.data
                                            if not conn['conn'].failed:
                                                conn['conn'].queue.put('%x\r\n%s\r\n'
                                                                       % (len(data),data)
                                                if chunked else data)
                                            else:
                                                return HTTPServiceUnavailable(request=req)
                                        if chunked:
                                            conn['conn'].queue.put('0\r\n\r\n')
                                break
                        data_src.bytes_transferred += len(data)
                        if data_src.bytes_transferred > MAX_FILE_SIZE:
                            return HTTPRequestEntityTooLarge(request=req)
                        for conn in data_src.conns:
                            for chunk in conn['conn'].tar_stream._serve_chunk(data):
                                if not conn['conn'].failed:
                                    conn['conn'].queue.put('%x\r\n%s\r\n' % (len(chunk), chunk)
                                    if chunked else chunk)
                                else:
                                    return HTTPServiceUnavailable(request=req)
                    if data_src.bytes_transferred < data_src.content_length:
                        return HTTPClientDisconnect(request=req, body='data source %s dead' % data_src.__dict__)
                for conn in conns:
                    if conn.queue.unfinished_tasks:
                        conn.queue.join()
                    conn.tar_stream = None
        except ChunkReadTimeout, err:
            self.app.logger.warn(
                _('ERROR Client read timeout (%ss)'), err.seconds)
            self.app.logger.increment('client_timeouts')
            return HTTPRequestTimeout(request=req)
        except (Exception, Timeout):
            self.app.logger.exception(
                _('ERROR Exception causing client disconnect'))
            return HTTPClientDisconnect(request=req, body='exception')

        for conn in conns:
            pile.spawn(self._process_response, conn, req)

        conns = [conn for conn in pile if conn]
        final_body = None
        final_response = Response(request=req)
        req.cdr_log = []
        for conn in conns:
            resp = conn.resp
            if resp:
                for key in conn.nexe_headers.keys():
                    if resp.headers.get(key):
                        conn.nexe_headers[key] = resp.headers.get(key)
            if conn.error:
                conn.nexe_headers['x-nexe-error'] = conn.error

            #print [final_response.headers, conn.nexe_headers]
            if self.app.zerovm_accounting_enabled:
                self._store_accounting_data(req, conn)
            merge_headers(final_response.headers, conn.nexe_headers)
            if resp and resp.content_length > 0:
                if final_body:
                    final_body.append(resp.app_iter)
                    final_response.content_length += resp.content_length
                else:
                    final_body = FinalBody(resp.app_iter)
                    final_response.app_iter = final_body
                    final_response.content_length = resp.content_length
                    final_response.content_type = resp.content_type
        if ns_server:
            ns_server.stop()
        if self.app.zerovm_accounting_enabled:
            self._store_accounting_data(req)
        if self.app.zerovm_use_cors and self.container_name:
            container_info = self.container_info(self.account_name, self.container_name)
            if container_info.get('cors', None):
                if container_info['cors'].get('allow_origin', None):
                    final_response.headers['access-control-allow-origin'] = container_info['cors']['allow_origin']
                if container_info['cors'].get('expose_headers', None):
                    final_response.headers['access-control-expose-headers'] = container_info['cors']['expose_headers']
        return final_response

    def create_name(self, node_name, i):
        return node_name + '-' + str(i)

    def _process_response(self, conn, request):
        conn.error = None
        try:
            with Timeout(self.app.node_timeout):
                if conn.resp:
                    server_response = conn.resp
                else:
                    server_response = conn.getresponse()
        except (Exception, Timeout):
            self.exception_occurred(conn.node, _('Object'),
                _('Trying to get final status of POST to %s')
                % request.path_info)
            conn.error = 'Timeout: trying to get final status of POST to %s' % request.path_info
            #conn.resp = HTTPClientDisconnect(body=conn.path,
            #    headers=conn.nexe_headers)
            return conn
        if server_response.status != 200:
            conn.error = '%d %s %s' % \
                         (server_response.status,
                          server_response.reason,
                          server_response.read())
            return conn
        resp = Response(status='%d %s' %
                            (server_response.status,
                             server_response.reason),
            app_iter=iter(lambda:
                server_response.read(self.app.network_chunk_size),''),
            headers = dict(server_response.getheaders()))
        conn.resp = resp
        if resp.content_length == 0:
            return conn
        node = conn.cnode
        untar_stream = UntarStream(resp.app_iter)
        bytes_transferred = 0
        while True:
            try:
                data = next(untar_stream.tar_iter)
            except StopIteration:
                break
            untar_stream.update_buffer(data)
            info = untar_stream.get_next_tarinfo()
            while info:
                if 'sysmap' in info.name:
                    untar_stream.to_write = info.size
                    untar_stream.offset_data = info.offset_data
                    self._load_channel_data(node, ExtractedFile(untar_stream))
                    info = untar_stream.get_next_tarinfo()
                    continue
                chan = node.get_channel(device=info.name)
                if not chan:
                    conn.error = 'Channel name %s not found' % info.name
                    return conn
                if not chan.path:
                    app_iter = iter(CachedBody(
                        untar_stream.tar_iter,
                        cache=[untar_stream.block[info.offset_data:]],
                        total_size=info.size))
                    resp.app_iter = app_iter
                    resp.content_length = info.size
                    resp.content_type = chan.content_type
                    return conn
                dest_header = unquote(chan.path)
                acct = request.path_info.split('/', 2)[1]
                dest_header = '/' + acct + dest_header
                dest_container_name, dest_obj_name =\
                    dest_header.split('/', 3)[2:]
                dest_req = Request.blank(dest_header,
                    environ=request.environ, headers=request.headers)
                dest_req.path_info = dest_header
                dest_req.method = 'PUT'
                dest_req.headers['content-length'] = info.size
                untar_stream.to_write = info.size
                untar_stream.offset_data = info.offset_data
                dest_req.environ['wsgi.input'] =\
                    ExtractedFile(untar_stream)
                dest_req.headers['content-type'] = chan.content_type
                error = update_metadata(dest_req, chan.meta)
                if error:
                    conn.error = error
                    return conn
                dest_resp = \
                    ObjectController(self.app, acct,
                    dest_container_name, dest_obj_name).PUT(dest_req)
                if dest_resp.status_int >= 300:
                    conn.error = 'Status %s when putting %s' \
                                 % (dest_resp.status, dest_header)
                    return conn
                info = untar_stream.get_next_tarinfo()
            bytes_transferred += len(data)
        untar_stream = None
        resp.content_length = 0
        return conn

    def _connect_exec_node(self, obj_nodes, part, request,
                          logger_thread_locals, cnode, nexe_headers):
        self.app.logger.thread_locals = logger_thread_locals
        for node in obj_nodes:
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    if (request.content_length > 0) or 'transfer-encoding' in request.headers:
                        request.headers['Expect'] = '100-continue'
                    #request.headers['Connection'] = 'close'
                    conn = http_connect(node['ip'], node['port'],
                        node['device'], part, request.method,
                        request.path_info, request.headers)
                with Timeout(self.app.node_timeout):
                    resp = conn.getexpect()
                if resp.status == HTTP_CONTINUE:
                    conn.resp = None
                    conn.node = node
                    conn.cnode = cnode
                    conn.nexe_headers = nexe_headers
                    return conn
                elif is_success(resp.status):
                    conn.resp = resp
                    conn.node = node
                    conn.cnode = cnode
                    conn.nexe_headers = nexe_headers
                    return conn
                elif resp.status == HTTP_INSUFFICIENT_STORAGE:
                    self.error_limit(node)
                else:
                    self.app.logger.warn('Obj server failed with: %d %s' % (resp.status, resp.reason))
            except:
                self.exception_occurred(node, _('Object'),
                    _('Expect: 100-continue on %s') % request.path_info)

    def _send_file(self, conn, path):
        while True:
            chunk = conn.queue.get()
            if not conn.failed:
                try:
                    with ChunkWriteTimeout(self.app.node_timeout):
                        conn.send(chunk)
                except (Exception, ChunkWriteTimeout):
                    conn.failed = True
                    self.exception_occurred(conn.node, _('Object'),
                        _('Trying to write to %s') % path)
            conn.queue.task_done()

    def _store_accounting_data(self, request, connection=None):
        txn_id = request.environ['swift.trans_id']
        acc_object = datetime.datetime.utcnow().strftime('%Y/%m/%d.log')
        if connection:
#            cdr = []
#            for n in connection.nexe_headers['x-nexe-cdr-line'].split():
#                try:
#                    cdr.append(int(float(n) * 1000))
#                except ValueError:
#                    cdr.append(int(n))
#            try:
#                request.cdr_summary = [x + y for (x, y) in zip(request.cdr_summary, cdr)]
#            except AttributeError:
#                request.cdr_summary = cdr
            body = '%s %s %s (%s) [%s]\n' % (datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                                   txn_id, connection.nexe_headers['x-nexe-system'],
                                   connection.nexe_headers['x-nexe-cdr-line'],
                                   connection.nexe_headers['x-nexe-status'])
            request.cdr_log.append(body)
        else:
#            try:
#                summary = ' '.join([str(n) for n in request.cdr_summary])
#            except AttributeError:
#                return
#            body = '%s %s === (%s) [Done]\n' % (datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
#                                   txn_id, summary)
#            request.cdr_log.append(body)
            body = ''.join(request.cdr_log)
            append_req = Request.blank('/%s/%s/%s/%s' % (self.app.version,
                                                         self.app.cdr_account,
                                                         self.account_name,
                                                         acc_object),
                headers={'X-Append-To': '-1',
                         'Content-Length': len(body),
                         'Content-Type': 'text/plain'},
                body=body
            )
            append_req.method = 'POST'
            resp = append_req.get_response(self.app)
            if resp.status_int >= 300:
                self.app.logger.warn(
                    _('ERROR Cannot write stats for account %s'), self.account_name)

    def _load_channel_data(self, node, file):
        config = json.loads(file.read())
        for new_ch in config['channels']:
            old_ch = node.get_channel(device=new_ch['device'])
            if old_ch:
                old_ch.content_type = new_ch['content_type']
                if new_ch.get('meta', None):
                    for k,v in new_ch.get('meta').iteritems():
                        old_ch.meta[k] = v


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def query_filter(app):
        return ProxyQueryMiddleware(app, conf)

    return query_filter
