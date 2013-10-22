from copy import deepcopy, copy
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
    HTTP_INSUFFICIENT_STORAGE, is_client_error
from swift.proxy.controllers.base import update_headers, delay_denial, \
    Controller, cors_validation
from swift.common.utils import split_path, get_logger, TRUE_VALUES, \
    get_remote_client, ContextPool, cache_from_env, normalize_timestamp
from swift.proxy.server import ObjectController, ContainerController, \
    AccountController
from swift.common.bufferedhttp import http_connect
from swift.common.exceptions import ConnectionTimeout, ChunkReadTimeout, \
    ChunkWriteTimeout
from swift.common.constraints import check_utf8, MAX_FILE_SIZE
from swift.common.swob import Request, Response, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestTimeout, HTTPRequestEntityTooLarge, \
    HTTPBadRequest, HTTPUnprocessableEntity, HTTPServiceUnavailable, \
    HTTPClientDisconnect, wsgify
from swiftclient.client import quote
from zerocloud.common import has_control_chars, DEVICE_MAP, \
    ACCESS_READABLE, ACCESS_CDR, ACCESS_WRITABLE, ACCESS_RANDOM, \
    CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME, TAR_MIMES, \
    POST_TEXT_OBJECT_SYSTEM_MAP, POST_TEXT_ACCOUNT_SYSTEM_MAP, \
    merge_headers, update_metadata, DEFAULT_EXE_SYSTEM_MAP, STREAM_CACHE_SIZE, \
    ZvmNode, ZvmChannel, parse_location, is_zvm_path, is_swift_path, is_cache_path, \
    NodeEncoder, is_image_path, can_run_as_daemon, SwiftPath

from zerocloud.tarstream import StringBuffer, UntarStream, \
    TarStream, REGTYPE, BLOCKSIZE, NUL, ExtractedFile, Path

try:
    import simplejson as json
except ImportError:
    import json


class CachedBody(object):

    def __init__(self, read_iter, cache=None, cache_size=STREAM_CACHE_SIZE,
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
                    yield chunk
            if self.total_size > 0:
                for chunk in self.read_iter:
                    self.total_size -= len(chunk)
                    if self.total_size < 0:
                        yield chunk[:self.total_size]
                        break
                    else:
                        yield chunk
            for _junk in self.read_iter:
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


class NameService(object):

    INT_FMT = '!I'
    INPUT_RECORD_FMT = '!IH'
    OUTPUT_RECORD_FMT = '!4sH'
    INT_SIZE = struct.calcsize(INT_FMT)
    INPUT_RECORD_SIZE = struct.calcsize(INPUT_RECORD_FMT)
    OUTPUT_RECORD_SIZE = struct.calcsize(OUTPUT_RECORD_FMT)

    def __init__(self, peers):
        self.port = None
        self.hostaddr = None
        self.peers = peers
        self.sock = None
        self.thread = None
        #print "NameServer got %d peers" % self.peers

    def start(self, pool):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', 0))
        self.thread = pool.spawn(self._run)
        (self.hostaddr, self.port) = self.sock.getsockname()

    def _run(self):
        bind_map = {}
        conn_map = {}
        peer_map = {}
        while 1:
            try:
                message, peer_address = self.sock.recvfrom(65535)
                offset = 0
                peer_id = struct.unpack_from(NameService.INT_FMT, message, offset)[0]
                offset += NameService.INT_SIZE
                bind_count = struct.unpack_from(NameService.INT_FMT, message, offset)[0]
                offset += NameService.INT_SIZE
                connect_count = struct.unpack_from(NameService.INT_FMT, message, offset)[0]
                offset += NameService.INT_SIZE
                for i in range(bind_count):
                    connecting_host, port = struct.unpack_from(NameService.INPUT_RECORD_FMT, message, offset)[0:2]
                    offset += NameService.INPUT_RECORD_SIZE
                    bind_map.setdefault(peer_id, {})[connecting_host] = port
                conn_map[peer_id] = (connect_count, offset, ctypes.create_string_buffer(message))
                peer_map.setdefault(peer_id, {})[0] = peer_address[0]
                peer_map.setdefault(peer_id, {})[1] = peer_address[1]

                if len(peer_map) == self.peers:
                    for peer_id in peer_map.iterkeys():
                        #out = ''
                        (connect_count, offset, reply) = conn_map[peer_id]
                        for i in range(connect_count):
                            connecting_host = struct.unpack_from(NameService.INT_FMT, reply, offset)[0]
                            port = bind_map[connecting_host][peer_id]
                            connect_to = peer_map[connecting_host][0]
                            if connect_to == peer_map[peer_id][0]:  # both on the same host
                                connect_to = '127.0.0.1'
                            struct.pack_into(NameService.OUTPUT_RECORD_FMT, reply, offset,
                                             socket.inet_pton(socket.AF_INET, connect_to), port)
                            offset += NameService.OUTPUT_RECORD_SIZE
                            #out += ' %d -> %d:%d\n' % (connecting_host, peer_id, port)
                        self.sock.sendto(reply, (peer_map[peer_id][0], peer_map[peer_id][1]))
                        #print out
            except greenlet.GreenletExit:
                return
            except Exception:
                print traceback.format_exc()
                pass

    def stop(self):
        self.thread.kill()
        self.sock.close()


class ProxyQueryMiddleware(object):

    def parse_daemon_config(self, daemon_list):
        result = []
        request = Request.blank('/daemon', environ={'REQUEST_METHOD': 'POST'},
                                headers={'Content-Type': 'application/json'})
        fake_controller = self.get_controller('daemon', None, None)
        socks = {}
        for sock, conf_file in zip(*[iter(daemon_list)] * 2):
            if socks.get(sock, None):
                self.logger.warning('Duplicate daemon config for uuid %s' % sock)
                continue
            socks[sock] = 1
            try:
                json_config = json.load(open(conf_file))
            except IOError:
                self.logger.warning('Cannot load daemon config file: %s' % conf_file)
                continue
            fake_controller.nodes = {}
            error = fake_controller.parse_cluster_config(request, json_config)
            if error:
                self.logger.warning('Daemon config %s error: %s' % (conf_file, error.body))
                continue
            if len(fake_controller.nodes) != 1:
                self.logger.warning('Bad daemon config %s: too many nodes' % conf_file)
            for node in fake_controller.nodes.itervalues():
                if node.bind or node.connect:
                    self.logger.warning('Bad daemon config %s: network channels are present' % conf_file)
                    continue
                if not is_image_path(node.exe):
                    self.logger.warning('Bad daemon config %s: exe path must be in image file' % conf_file)
                    continue
                image = None
                for sysimage in self.app.zerovm_sysimage_devices:
                    if node.exe.image in sysimage:
                        image = sysimage
                        break
                if not image:
                    self.logger.warning('Bad daemon config %s: exe is not in sysimage device' % conf_file)
                    continue
                node.channels = sorted(node.channels, key=lambda ch: ch.device)
                result.append((sock, node))
                self.logger.info('Loaded daemon config %s with UUID %s' % (conf_file, sock))
        return result

    def __init__(self, app, conf, logger=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='proxy-query')
        # header for "execute by POST"
        self.app.zerovm_execute = 'x-zerovm-execute'
        # execution engine version
        self.app.zerovm_execute_ver = '1.0'
        # total maximum iops for channel read or write operations, per zerovm session
        self.app.zerovm_maxiops = int(conf.get('zerovm_maxiops', 1024 * 1048576))
        # total maximum bytes for a channel write operations, per zerovm session
        self.app.zerovm_maxoutput = int(conf.get('zerovm_maxoutput', 1024 * 1048576))
        # total maximum bytes for a channel read operations, per zerovm session
        self.app.zerovm_maxinput = int(conf.get('zerovm_maxinput', 1024 * 1048576))
        # maximum size of a system map file
        self.app.zerovm_maxconfig = int(conf.get('zerovm_maxconfig', 65536))
        # name server hostname or ip, will be autodetected if not set
        self.app.zerovm_ns_hostname = conf.get('zerovm_ns_hostname')
        # name server thread pool size
        self.app.zerovm_ns_maxpool = int(conf.get('zerovm_ns_maxpool', 1000))
        self.app.zerovm_ns_thrdpool = GreenPool(self.app.zerovm_ns_maxpool)
        # max time to wait for upload to finish, used in POST requests
        self.app.max_upload_time = int(conf.get('max_upload_time', 86400))
        # network chunk size for all network ops
        self.app.network_chunk_size = int(conf.get('network_chunk_size', 65536))
        # use newest files when running zerovm executables, default - False
        self.app.zerovm_uses_newest = conf.get('zerovm_uses_newest', 'f').lower() in TRUE_VALUES
        # use executable validation info, stored on PUT or POST, to shave some time on zerovm startup
        self.app.zerovm_prevalidate = conf.get('zerovm_prevalidate', 'f').lower() in TRUE_VALUES
        # use CORS workaround to POST execute commands, default - False
        self.app.zerovm_use_cors = conf.get('zerovm_use_cors', 'f').lower() in TRUE_VALUES
        # Accounting: enable or disabe execution accounting data, default - disabled
        self.app.zerovm_accounting_enabled = conf.get('zerovm_accounting_enabled', 'f').lower() in TRUE_VALUES
        # Accounting: system account for storing accounting data
        self.app.cdr_account = conf.get('user_stats_account', 'userstats')
        # Accounting: storage API version
        self.app.version = 'v1'
        # default content-type for unknown files
        self.app.zerovm_content_type = conf.get('zerovm_default_content_type', 'application/octet-stream')
        # names of sysimage devices, no sysimage devices exist by default
        self.app.zerovm_sysimage_devices = [i.strip() for i in conf.get('zerovm_sysimage_devices', '').split()
                                            if i.strip()]
        # GET support: container for content-type association storage
        self.app.zerovm_registry_path = '.zvm'
        # GET support: API version for "open" command
        self.app.zerovm_open_version = 'open'
        # GET support: API version for "open with" command
        self.app.zerovm_openwith_version = 'open-with'
        # GET support: allowed commands
        self.app.zerovm_allowed_commands = [self.app.zerovm_open_version, self.app.zerovm_openwith_version]
        # GET support: cache config files for this amount of seconds
        self.app.zerovm_cache_config_timeout = 60
        # list of daemons we need to lazy load (first request will start the daemon)
        daemon_list = [i.strip() for i in conf.get('zerovm_daemons', '').split() if i.strip()]
        self.app.zerovm_daemons = self.parse_daemon_config(daemon_list)

    @wsgify
    def __call__(self, req):
        try:
            version, account, container, obj = split_path(req.path, 1, 4, True)
            path_parts = dict(version=version,
                              account_name=account,
                              container_name=container,
                              object_name=obj)
        except ValueError:
            return HTTPNotFound(request=req)
        if account and \
                (self.app.zerovm_execute in req.headers
                 or version in self.app.zerovm_allowed_commands):
            if req.content_length and req.content_length < 0:
                return HTTPBadRequest(request=req,
                                      body='Invalid Content-Length')
            if not check_utf8(req.path_info):
                return HTTPPreconditionFailed(request=req, body='Invalid UTF8')
            controller = self.get_controller(account, container, obj)
            if not controller:
                return HTTPPreconditionFailed(request=req, body='Bad URL')
            if 'swift.trans_id' not in req.environ:
                # if this wasn't set by an earlier middleware, set it now
                trans_id = 'tx' + uuid.uuid4().hex
                req.environ['swift.trans_id'] = trans_id
                self.logger.txn_id = trans_id
            req.headers['x-trans-id'] = req.environ['swift.trans_id']
            controller.trans_id = req.environ['swift.trans_id']
            self.logger.client_ip = get_remote_client(req)
            if path_parts['version']:
                controller.command = path_parts['version']
                req.path_info_pop()
            if not self.app.zerovm_execute in req.headers:
                req.headers[self.app.zerovm_execute] = self.app.zerovm_execute_ver
            try:
                handler = getattr(controller, req.method)
            except AttributeError:
                return HTTPPreconditionFailed(request=req, body='Bad HTTP method')
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
            return res
        return self.app

    def get_controller(self, account, container, obj):
        return ClusterController(self.app, account, container, obj)


class ClusterController(ObjectController):

    def __init__(self, app, account_name, container_name, obj_name,
                 **kwargs):
        ObjectController.__init__(self, app, account_name, container_name or '', obj_name or '')
        self.nodes = {}
        self.command = None

    def get_daemon_socket(self, config):
        for daemon_sock, daemon_conf in self.app.zerovm_daemons:
            if can_run_as_daemon(config, daemon_conf):
                return daemon_sock
        return None

    def get_random_partition(self):
        partition_count = self.app.object_ring.partition_count
        part = randrange(0, partition_count)
        return part

    def iter_nodes(self, partition, nodes, ring, handoff=True):
        """
        Node iterator that will first iterate over the normal nodes for a
        partition and then the handoff partitions for the node.

        :param partition: partition to iterate nodes for
        :param nodes: list of node dicts from the ring
        :param ring: ring to get handoff nodes from
        :param handoff: disable handoff for free-standing executors
        """
        for node in nodes:
            if not self.error_limited(node):
                yield node
        handoffs = 0
        for node in ring.get_more_nodes(partition):
            if not self.error_limited(node):
                if handoff:
                    handoffs += 1
                    if self.app.log_handoffs:
                        self.app.logger.increment('handoff_count')
                        self.app.logger.warning(
                            'Handoff requested (%d)' % handoffs)
                        if handoffs == len(nodes):
                            self.app.logger.increment('handoff_all_count')
                yield node

    def list_account(self, req, account, mask=None, marker=None):
        new_req = req.copy_get()
        new_req.path_info = '/' + quote(account)
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
        new_req.path_info = '/' + quote(account) + '/' + quote(container)
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
                if item['name'][-1] == '/':
                    continue
                if not mask or mask.match(item['name']):
                    ret.append(item['name'])
            marker = data[-1]['name']
            data = self.list_container(req, account, container,
                                       None, marker)
        return ret

    def _build_connect_string(self, node, node_count):
        tmp = []
        for (dst, dst_dev) in node.bind:
            dst_id = self.nodes.get(dst).id
            dst_repl = self.nodes.get(dst).replicate
            proto = ';'.join(map(
                lambda i: 'tcp:%d:0' % (dst_id + i * node_count),
                range(dst_repl)
            ))
            tmp.append(
                ','.join([proto,
                          dst_dev,
                          '0,0',  # type = 0, sequential, etag = 0, not needed
                          str(self.app.zerovm_maxiops),
                          str(self.app.zerovm_maxinput),
                          '0,0'])
            )
        node.bind = tmp
        tmp = []
        for (dst, dst_dev) in node.connect:
            dst_id = self.nodes.get(dst).id
            dst_repl = self.nodes.get(dst).replicate
            proto = ';'.join(map(
                lambda i: 'tcp:%d:' % (dst_id + i * node_count),
                range(dst_repl)
            ))
            tmp.append(
                ','.join([proto,
                          dst_dev,
                          '0,0',  # type = 0, sequential, etag = 0, not needed
                          '0,0',
                          str(self.app.zerovm_maxiops),
                          str(self.app.zerovm_maxoutput)])
            )
        node.connect = tmp

    def parse_cluster_config(self, req, cluster_config):
        try:
            nid = 1
            connect_devices = {}
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
                nexe_path = parse_location(nexe.get('path'))
                if not nexe_path:
                    return HTTPBadRequest(request=req,
                                          body='Must specify executable path for %s' % node_name)
                if is_zvm_path(nexe_path):
                    return HTTPBadRequest(request=req,
                                          body='Executable path cannot be a zvm path, in %s' % node_name)
                nexe_args = nexe.get('args')
                nexe_env = nexe.get('env')
                if has_control_chars('%s %s %s' % (nexe_path.url, nexe_args, nexe_env)):
                    return HTTPBadRequest(request=req,
                                          body='Invalid nexe property')
                node_count = node.get('count', 1)
                if not isinstance(node_count, int):
                    return HTTPBadRequest(request=req,
                                          body='Invalid node count')
                node_replicate = node.get('replicate', 1)
                file_list = node.get('file_list')
                read_list = []
                write_list = []
                other_list = []
                # connect_devices = {}

                if file_list:
                    for f in file_list:
                        device = f.get('device')
                        if has_control_chars(device):
                            return HTTPBadRequest(request=req,
                                                  body='Bad device name')
                        path = parse_location(f.get('path'))
                        # comment it out for now, the path should not go into manifest anyway
                        # if has_control_chars(path):
                        #     return HTTPBadRequest(request=req,
                        #                           body='Bad device path')
                        if not device:
                            return HTTPBadRequest(request=req,
                                                  body='Must specify device for file in %s'
                                                       % node_name)
                        if is_zvm_path(path):
                            if not connect_devices.get(node_name, None):
                                connect_devices[node_name] = {}
                            connect_devices[node_name][path.host] = ('/dev/' + device, path.device)
                            continue
                        access = DEVICE_MAP.get(device, -1)
                        if access < 0:
                            if device in self.app.zerovm_sysimage_devices:
                                other_list.append(f)
                                continue
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
                        access = DEVICE_MAP.get(device)
                        path = parse_location(f.get('path'))
                        if not is_swift_path(path):
                            return HTTPBadRequest(request=req,
                                                  body='Readable device must be a swift object')
                        if not path.account or not path.container:
                            return HTTPBadRequest(request=req,
                                                  body='Invalid path %s in %s'
                                                       % (path.url, node_name))
                        mode = f.get('mode', None)
                        if '*' in path.path:
                            read_group = 1
                            temp_list = []
                            if '*' in path.container:
                                container = re.escape(path.container).replace('\\*', '.*')
                                mask = re.compile(container)
                                try:
                                    containers = self.list_account(req, path.account, mask)
                                except Exception:
                                    return HTTPBadRequest(request=req,
                                                          body='Error querying object server '
                                                               'for account %s'
                                                               % path.account)
                                if path.obj:
                                    obj = path.obj
                                    if '*' in obj:
                                        obj = re.escape(obj).replace('\\*', '.*')
                                    mask = re.compile(obj)
                                else:
                                    mask = None
                                for c in containers:
                                    try:
                                        obj_list = self.list_container(req, path.account, c, mask)
                                    except Exception:
                                        return HTTPBadRequest(request=req,
                                                              body='Error querying object server '
                                                                   'for container %s' % c)
                                    for obj in obj_list:
                                        temp_list.append(SwiftPath.init(path.account, c, obj))
                            else:
                                obj = re.escape(path.obj).replace('\\*', '.*')
                                mask = re.compile(obj)
                                try:
                                    for obj in self.list_container(req, path.account, path.container, mask):
                                        temp_list.append(SwiftPath.init(path.account, path.container, obj))
                                except Exception:
                                    return HTTPBadRequest(request=req,
                                                          body='Error querying object server '
                                                               'for container %s' % path.container)
                            if not temp_list:
                                return HTTPBadRequest(request=req,
                                                      body='No objects found in path %s' % path.url)
                            read_mask = re.escape(path.path).replace('\\*', '(.*)')
                            read_mask = re.compile(read_mask)
                            for i in range(len(temp_list)):
                                new_name = _create_node_name(node_name, i+1)
                                new_path = temp_list[i]
                                new_node = self.nodes.get(new_name)
                                if not new_node:
                                    new_node = ZvmNode(nid, new_name,
                                                       nexe_path, nexe_args, nexe_env, node_replicate)
                                    nid += 1
                                    self.nodes[new_name] = new_node
                                new_node.add_channel(device, access,
                                                     path=new_path, mode=mode)
                                new_match = read_mask.match(new_path.path)
                                new_node.wildcards = map(lambda idx: new_match.group(idx),
                                                         range(1, new_match.lastindex + 1))
                            node_count = len(temp_list)
                        else:
                            if node_count > 1:
                                for i in range(1, node_count + 1):
                                    new_name = _create_node_name(node_name, i)
                                    new_path = SwiftPath.init(path.account, path.container, path.obj)
                                    new_node = self.nodes.get(new_name)
                                    if not new_node:
                                        new_node = ZvmNode(nid, new_name,
                                                           nexe_path, nexe_args, nexe_env, node_replicate)
                                        nid += 1
                                        self.nodes[new_name] = new_node
                                    new_node.add_channel(device, access,
                                                         path=new_path, mode=mode)
                            else:
                                new_node = self.nodes.get(node_name)
                                path = SwiftPath.init(path.account, path.container, path.obj)
                                if not new_node:
                                    new_node = ZvmNode(nid, node_name, nexe_path,
                                                       nexe_args, nexe_env, node_replicate)
                                    nid += 1
                                    self.nodes[node_name] = new_node
                                new_node.add_channel(device, access, path=path, mode=mode)

                    for f in write_list:
                        device = f.get('device')
                        access = DEVICE_MAP.get(device)
                        path = parse_location(f.get('path'))
                        content_type = f.get('content_type', self.app.zerovm_content_type)
                        meta = f.get('meta', None)
                        mode = f.get('mode', None)
                        if path and '*' in path.url:
                            if read_group:
                                for i in range(1, node_count + 1):
                                    new_name = _create_node_name(node_name, i)
                                    new_url = path.url
                                    new_node = self.nodes.get(new_name)
                                    for wc in new_node.wildcards:
                                        new_url = new_url.replace('*', wc, 1)
                                    if new_url.count('*') > 0:
                                        return HTTPBadRequest(request=req,
                                                              body='Wildcards in input cannot be'
                                                                   ' resolved into output path %s'
                                                                   % path)
                                    new_path = parse_location(new_url)
                                    new_node.add_channel(device, access,
                                                         path=new_path, content_type=content_type,
                                                         meta_data=meta, mode=mode)
                            else:
                                for i in range(1, node_count + 1):
                                    new_name = _create_node_name(node_name, i)
                                    new_url = path.url
                                    new_url = new_url.replace('*', new_name)
                                    new_node = self.nodes.get(new_name)
                                    if not new_node:
                                        new_node = ZvmNode(nid, new_name,
                                                           nexe_path, nexe_args, nexe_env, node_replicate)
                                        nid += 1
                                        self.nodes[new_name] = new_node
                                    new_path = parse_location(new_url)
                                    new_node.add_channel(device, access,
                                                         path=new_path, content_type=content_type,
                                                         meta_data=meta, mode=mode)
                                    new_node.wildcards = [new_name] * path.url.count('*')
                        elif path:
                            if node_count > 1:
                                return HTTPBadRequest(request=req,
                                                      body='Single path %s for multiple node '
                                                           'definition: %s, please use wildcard'
                                                           % (path.url, node_name))
                            new_node = self.nodes.get(node_name)
                            if not new_node:
                                new_node = ZvmNode(nid, node_name, nexe_path,
                                                   nexe_args, nexe_env, node_replicate)
                                nid += 1
                                self.nodes[node_name] = new_node
                            new_node.add_channel(device, access,
                                                 path=path, content_type=content_type,
                                                 meta_data=meta, mode=mode)
                        else:
                            if 'stdout' not in device \
                                    and 'stderr' not in device:
                                return HTTPBadRequest(request=req,
                                                      body='Immediate response is not available '
                                                           'for device %s' % device)
                            if node_count > 1:
                                for i in range(1, node_count + 1):
                                    new_name = _create_node_name(node_name, i)
                                    new_node = self.nodes.get(new_name)
                                    if not new_node:
                                        new_node = ZvmNode(nid, new_name,
                                                           nexe_path, nexe_args, nexe_env, node_replicate)
                                        nid += 1
                                        self.nodes[new_name] = new_node
                                    new_node.add_channel(device, access,
                                                         content_type=f.get('content_type', 'text/html'),
                                                         mode=mode)
                            else:
                                new_node = self.nodes.get(node_name)
                                if not new_node:
                                    new_node = ZvmNode(nid, node_name,
                                                       nexe_path, nexe_args, nexe_env, node_replicate)
                                    nid += 1
                                    self.nodes[node_name] = new_node
                                new_node.add_channel(device, access,
                                                     content_type=f.get('content_type', 'text/html'),
                                                     mode=mode)

                    for f in other_list:
                        device = f.get('device')
                        path = None
                        if device in self.app.zerovm_sysimage_devices:
                            access = ACCESS_RANDOM | ACCESS_READABLE
                        else:
                            access = DEVICE_MAP.get(device)
                            path = parse_location(f.get('path'))
                            if not path:
                                return HTTPBadRequest(request=req,
                                                      body='Path required for device %s' % device)
                        if node_count > 1:
                            for i in range(1, node_count + 1):
                                new_name = _create_node_name(node_name, i)
                                new_node = self.nodes.get(new_name)
                                if not new_node:
                                    new_node = ZvmNode(nid, new_name,
                                                       nexe_path, nexe_args, nexe_env, node_replicate)
                                    nid += 1
                                    self.nodes[new_name] = new_node
                                new_node.add_channel(device, access, path=path)
                        else:
                            new_node = self.nodes.get(node_name)
                            if not new_node:
                                new_node = ZvmNode(nid, node_name, nexe_path,
                                                   nexe_args, nexe_env, node_replicate)
                                nid += 1
                                self.nodes[node_name] = new_node
                            new_node.add_channel(device, access, path=path)

        except Exception:
            print traceback.format_exc()
            return HTTPUnprocessableEntity(request=req)

        for node in cluster_config:
            connect = node.get('connect')
            node_name = node.get('name')
            src = connect_devices.get(node_name, None)
            if not connect:
                if src:
                    connect = [connected_node for connected_node in src.iterkeys()]
                else:
                    continue
            if self.nodes.get(node_name):
                connect_node = self.nodes.get(node_name)
                try:
                    for bind_name in connect:
                        src_dev = None
                        dst_dev = None
                        if src:
                            devices = src.get(bind_name, None)
                            if devices:
                                (src_dev, dst_dev) = devices
                        connect_node.add_connection(bind_name, self.nodes, src_dev, dst_dev)
                except Exception:
                    return HTTPBadRequest(request=req,
                                          body='Invalid connect string for node %s' % node_name)
            elif self.nodes.get(node_name + '-1'):
                j = 1
                connect_node = self.nodes.get(_create_node_name(node_name, j))
                while connect_node:
                    try:
                        for bind_name in connect:
                            src_dev = None
                            dst_dev = None
                            if src:
                                devices = src.get(bind_name, None)
                                if devices:
                                    (src_dev, dst_dev) = devices
                            connect_node.add_connection(bind_name, self.nodes, src_dev, dst_dev)
                    except Exception, e:
                        return HTTPBadRequest(request=req,
                                              body='Invalid connect string for node %s: %s'
                                                   % (connect_node.name, e))
                    j += 1
                    connect_node = self.nodes.get(
                        _create_node_name(node_name, j))
            else:
                return HTTPBadRequest(request=req,
                                      body='Non existing node in connect string for node %s'
                                           % node_name)

        #node_count = len(self.nodes)
        #for node in self.nodes.itervalues():
        #    self.build_connect_string(node, node_count)
        #for n in self.nodes.itervalues():
        #    print n.__dict__

        return None

    def _get_own_address(self):
        if self.app.zerovm_ns_hostname:
            addr = self.app.zerovm_ns_hostname
        else:
            addr = None
            partition_count = self.app.object_ring.partition_count
            part = randrange(0, partition_count)
            nodes = self.app.object_ring.get_part_nodes(part)
            for n in nodes:
                addr = _get_local_address(n)
                if addr:
                    break
        return addr

    def _make_exec_requests(self, pile, exec_requests):
        for exec_request in exec_requests:
            node = exec_request.node
            try:
                account, container, obj = split_path(node.path_info, 3, 3, True)
                partition, nodes = self.app.object_ring.get_nodes(account, container, obj)
                node_iter = self.iter_nodes(partition, nodes, self.app.object_ring)
                exec_request.path_info = node.path_info
                if node.replicate > 1:
                    container_info = self.container_info(account, container)
                    container_partition = container_info['partition']
                    containers = container_info['nodes']
                    exec_headers = self._backend_requests(exec_request, node.replicate,
                                                          container_partition, containers)
                    if node.skip_validation:
                        for hdr in exec_headers:
                            hdr['x-zerovm-valid'] = 'true'
                    i = 0
                    pile.spawn(self._connect_exec_node, node_iter, partition,
                               exec_request, self.app.logger.thread_locals, node,
                               exec_headers[i])
                    for repl_node in node.replicas:
                        i += 1
                        pile.spawn(self._connect_exec_node, node_iter, partition,
                                   exec_request, self.app.logger.thread_locals, repl_node,
                                   exec_headers[i])
                else:
                    if node.skip_validation:
                        exec_request.headers['x-zerovm-valid'] = 'true'
                    pile.spawn(self._connect_exec_node, node_iter, partition,
                               exec_request, self.app.logger.thread_locals, node,
                               exec_request.headers)
            except ValueError:
                partition = self.get_random_partition()
                nodes = self.app.object_ring.get_part_nodes(partition)
                node_iter = self.iter_nodes(partition, nodes, self.app.object_ring, handoff=False)
                if node.skip_validation:
                    exec_request.headers['x-zerovm-valid'] = 'true'
                pile.spawn(self._connect_exec_node, node_iter, partition,
                           exec_request, self.app.logger.thread_locals, node,
                           exec_request.headers)
                for repl_node in node.replicas:
                    partition = self.get_random_partition()
                    nodes = self.app.object_ring.get_part_nodes(partition)
                    node_iter = self.iter_nodes(partition, nodes, self.app.object_ring, handoff=False)
                    pile.spawn(self._connect_exec_node, node_iter, partition,
                               exec_request, self.app.logger.thread_locals, repl_node,
                               exec_request.headers)
        return [conn for conn in pile if conn]

    def _spawn_file_senders(self, conns, pool, req):
        for conn in conns:
            conn.failed = False
            conn.queue = Queue(self.app.put_queue_depth)
            conn.tar_stream = TarStream()
            pool.spawn(self._send_file, conn, req.path)

    def _get_remote_objects(self, node):
        channels = []
        if is_swift_path(node.exe):
            channels.append(ZvmChannel('boot', None, node.exe))
        if len(node.channels) > 1:
            for ch in node.channels[1:]:
                if is_swift_path(ch.path) \
                    and (ch.access & (ACCESS_READABLE | ACCESS_CDR)) \
                        and ch.device not in self.app.zerovm_sysimage_devices:
                    channels.append(ch)
        return channels

    def _create_request_for_remote_object(self, data_sources, channel, exe_resp, req, nexe_headers, node):
        source_resp = None
        load_from = channel.path.path
        for resp in data_sources:
            if resp.request and load_from == resp.request.path_info:
                source_resp = resp
                break
        if not source_resp:
            if exe_resp and load_from == exe_resp.request.path_info:
                source_resp = exe_resp
            else:
                source_req = req.copy_get()
                source_req.path_info = load_from
                if self.app.zerovm_uses_newest:
                    source_req.headers['X-Newest'] = 'true'
                if self.app.zerovm_prevalidate and 'boot' in channel.device:
                    source_req.headers['X-Zerovm-Valid'] = 'true'
                acct, src_container_name, src_obj_name =\
                    split_path(load_from, 1, 3, True)
                container_info = self.container_info(acct, src_container_name)
                source_req.acl = container_info['read_acl']
                #if 'boot' in ch.device:
                #    source_req.acl = container_info['exec_acl']
                source_resp = \
                    ObjectController(self.app,
                                     acct,
                                     src_container_name,
                                     src_obj_name).GET(source_req)
                if source_resp.status_int >= 300:
                    update_headers(source_resp, nexe_headers)
                    source_resp.body = 'Error %s while fetching %s' \
                                       % (source_resp.status, source_req.path_info)
                    return source_resp
            source_resp.nodes = []
            data_sources.append(source_resp)
        node.last_data = source_resp
        source_resp.nodes.append({'node': node, 'dev': channel.device})
        if source_resp.headers.get('x-zerovm-valid', None) and 'boot' in channel.device:
            node.skip_validation = True
        for repl_node in node.replicas:
            repl_node.last_data = source_resp
            source_resp.nodes.append({'node': repl_node, 'dev': channel.device})

    @delay_denial
    @cors_validation
    def POST(self, req, exe_resp=None, cluster_config=''):
        user_image = None
        user_image_length = 0
        if 'content-type' not in req.headers:
            return HTTPBadRequest(request=req,
                                  body='Must specify Content-Type')
        upload_expiration = time.time() + self.app.max_upload_time
        etag = md5()
        req.bytes_transferred = 0
        path_list = [StringBuffer(CLUSTER_CONFIG_FILENAME),
                     StringBuffer(NODE_CONFIG_FILENAME)]
        read_iter = iter(lambda: req.environ['wsgi.input'].read(self.app.network_chunk_size), '')
        if req.headers['content-type'].split(';')[0].strip() in TAR_MIMES:
            # we must have Content-Length set for tar-based requests
            # as it will be impossible to stream them otherwise
            if not 'content-length' in req.headers:
                return HTTPBadRequest(request=req,
                                      body='Must specify Content-Length')
            # buffer first blocks of tar file and search for the system map
            cached_body = CachedBody(read_iter)
            user_image = iter(cached_body)
            user_image_length = req.headers['content-length']
            untar_stream = UntarStream(cached_body.cache, path_list)
            for chunk in untar_stream:
                req.bytes_transferred += len(chunk)
                etag.update(chunk)
            for buf in path_list:
                if buf.is_closed:
                    cluster_config = buf.body
                    break
            if not cluster_config:
                return HTTPBadRequest(request=req,
                                      body='System boot map was not found in request')
            try:
                cluster_config = json.loads(cluster_config)
            except Exception:
                return HTTPUnprocessableEntity(body='Could not parse system map')
        elif req.headers['content-type'].split(';')[0].strip() in 'application/json':
        # System map was sent as a POST body
            if not cluster_config:
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
                return HTTPUnprocessableEntity(body='Could not parse system map')
        else:
            # assume the posted data is a script and try to execute
            if not 'content-length' in req.headers:
                return HTTPBadRequest(request=req,
                                      body='Must specify Content-Length')
            cached_body = CachedBody(read_iter)
            # all scripts must start with shebang
            if not cached_body.cache[0].startswith('#!'):
                return HTTPBadRequest(request=req,
                                      body='Unsupported Content-Type')
            buf = ''
            shebang = None
            for chunk in cached_body.cache:
                i = chunk.find('\n')
                if i > 0:
                    shebang = buf + chunk[0:i]
                    break
                buf += chunk
            if not shebang:
                return HTTPBadRequest(request=req,
                                      body='Cannot find shebang (#!) in script')
            command_line = re.split('\s+', re.sub('^#!\s*(.*)', '\\1', shebang))
            sysimage = None
            location = parse_location(command_line[0])
            if is_swift_path(location):
                exe_path = location.url
            elif len(command_line) > 1:
                exe_path = command_line[1]
                if exe_path.startswith('/'):
                    exe_path = exe_path[1:]
                sysimage = command_line[0]
            else:
                exe_path = command_line[0]
                try:
                    sysimage = self.app.zerovm_sysimage_devices[0]
                except IndexError:
                    return HTTPBadRequest(request=req,
                                          body='Cannot find interpreter: %s' % command_line[0])
            params = {'exe_path': exe_path}
            req.path_info_pop()
            if self.container_name and self.object_name:
                template = POST_TEXT_OBJECT_SYSTEM_MAP
                location = SwiftPath.init(self.account_name,
                                          self.container_name,
                                          self.object_name)
                config = _config_from_template(params, template, location.url)
            else:
                template = POST_TEXT_ACCOUNT_SYSTEM_MAP
                config = _config_from_template(params, template, '')

            try:
                cluster_config = json.loads(config)
            except Exception:
                return HTTPUnprocessableEntity(body='Could not parse system map')
            if sysimage:
                cluster_config[0]['file_list'].append({'device': sysimage})
            string_path = Path(REGTYPE, 'script', int(req.headers['content-length']), cached_body)
            stream = TarStream(path_list=[string_path])
            user_image = iter(stream)
            user_image_length = stream.get_total_stream_length()

        error = self.parse_cluster_config(req, cluster_config)
        if error:
            self.app.logger.warn(
                _('ERROR Error parsing config: %s'), cluster_config)
            return error
        req.path_info = '/' + self.account_name

        node_list = []
        for k in sorted(self.nodes.iterkeys()):
            node = self.nodes[k]
            top_channel = node.channels[0]
            if top_channel and is_swift_path(top_channel.path):
                if top_channel.access & (ACCESS_READABLE | ACCESS_CDR):
                    node.path_info = top_channel.path.path
                elif top_channel.access & ACCESS_WRITABLE and node.replicate > 0:
                    node.path_info = top_channel.path.path
                    node.replicate = self.app.object_ring.replica_count
            if node.replicate == 0:
                node.replicate = 1
            node_list.append(node)

        # for n in node_list:
        #     print json.dumps(n, cls=NodeEncoder)

        image_resp = None
        if user_image:
            image_resp = Response(app_iter=user_image,
                                  headers={'Content-Length': user_image_length})
            image_resp.nodes = []
            for n in node_list:
                n.add_channel('image', ACCESS_CDR, removable='yes')

        data_sources = []
        addr = self._get_own_address()
        if not addr:
            return HTTPServiceUnavailable(
                body='Cannot find own address, check zerovm_ns_hostname')
        node_count = _total_node_count(node_list)
        ns_server = None
        if node_count > 1:
            ns_server = NameService(node_count)
            if self.app.zerovm_ns_thrdpool.free() <= 0:
                return HTTPServiceUnavailable(body='Cluster slot not available',
                                              request=req)
            ns_server.start(self.app.zerovm_ns_thrdpool)
            if not ns_server.port:
                return HTTPServiceUnavailable(body='Cannot bind name service')
        exec_requests = []
        for node in node_list:
            nexe_headers = {
                'x-nexe-system': node.name,
                'x-nexe-status': 'ZeroVM did not run',
                'x-nexe-retcode': 0,
                'x-nexe-etag': '',
                'x-nexe-validation': 0,
                'x-nexe-cdr-line': '0 0 0 0 0 0 0 0 0 0 0 0'
            }
            path_info = req.path_info
            exec_request = Request.blank(path_info,
                                         environ=req.environ,
                                         headers=req.headers)
            exec_request.path_info = path_info
            #exec_request.content_length = None
            exec_request.etag = None
            exec_request.headers['content-type'] = TAR_MIMES[0]
            #exec_request.headers['transfer-encoding'] = 'chunked'
            exec_request.headers['x-account-name'] = self.account_name
            exec_request.headers['x-timestamp'] = normalize_timestamp(time.time())
            exec_request.headers['x-zerovm-valid'] = 'false'
            exec_request.headers['x-zerovm-pool'] = 'default'
            if len(node.connect) > 0 or len(node.bind) > 0:
                # node operation depends on connection to other nodes
                exec_request.headers['x-zerovm-pool'] = 'cluster'
            if 'swift.authorize' in exec_request.environ:
                aresp = exec_request.environ['swift.authorize'](exec_request)
                if aresp:
                    return aresp
            if ns_server:
                node.name_service = 'udp:%s:%d' % (addr, ns_server.port)
                self._build_connect_string(node, len(node_list))
                if node.replicate > 1:
                    for i in range(0, node.replicate - 1):
                        node.replicas.append(deepcopy(node))
                        node.replicas[i].id = node.id + (i + 1) * len(node_list)
            node.copy_cgi_env(exec_request)
            resp = node.create_sysmap_resp()
            node.add_data_source(data_sources, resp, 'sysmap')
            for repl_node in node.replicas:
                repl_node.copy_cgi_env(exec_request)
                resp = repl_node.create_sysmap_resp()
                repl_node.add_data_source(data_sources, resp, 'sysmap')
            #print json.dumps(node, sort_keys=True, indent=2, cls=NodeEncoder)
            channels = self._get_remote_objects(node)
            for ch in channels:
                error = self._create_request_for_remote_object(data_sources, ch,
                                                               exe_resp, req,
                                                               nexe_headers, node)
                if error:
                    return error
            if image_resp:
                node.last_data = image_resp
                image_resp.nodes.append({'node': node, 'dev': 'image'})
                for repl_node in node.replicas:
                    repl_node.last_data = image_resp
                    image_resp.nodes.append({'node': repl_node, 'dev': 'image'})
            if not getattr(node, 'path_info', None):
                node.path_info = path_info
            exec_request.node = node
            exec_request.resp_headers = nexe_headers
            sock = self.get_daemon_socket(node)
            if sock:
                exec_request.headers['x-zerovm-daemon'] = str(sock)
            exec_requests.append(exec_request)

        if image_resp:
            data_sources.append(image_resp)
        tstream = TarStream()
        for data_src in data_sources:
            for n in data_src.nodes:
                if not getattr(n['node'], 'size', None):
                    n['node'].size = 0
                n['node'].size += len(tstream.create_tarinfo(ftype=REGTYPE, name=n['dev'],
                                                             size=data_src.content_length))
                n['node'].size += TarStream.get_archive_size(data_src.content_length)
        pile = GreenPile(node_count)
        conns = self._make_exec_requests(pile, exec_requests)
        if len(conns) < node_count:
            self.app.logger.exception(
                _('ERROR Cannot find suitable node to execute code on'))
            return HTTPServiceUnavailable(
                body='Cannot find suitable node to execute code on')

        for conn in conns:
            if getattr(conn, 'error', None):
                return Response(body=conn.error,
                                status="%d %s" % (conn.resp.status, conn.resp.reason),
                                headers=conn.nexe_headers)

        _attach_connections_to_data_sources(conns, data_sources)

        #chunked = req.headers.get('transfer-encoding')
        chunked = False
        try:
            with ContextPool(node_count) as pool:
                self._spawn_file_senders(conns, pool, req)
                for data_src in data_sources:
                    data_src.bytes_transferred = 0
                    _send_tar_headers(chunked, data_src)
                    while True:
                        with ChunkReadTimeout(self.app.client_timeout):
                            try:
                                data = next(data_src.app_iter)
                            except StopIteration:
                                error = _finalize_tar_streams(chunked, data_src, req)
                                if error:
                                    return error
                                break
                        error = _send_data_chunk(chunked, data_src, data, req)
                        if error:
                            return error
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
            print traceback.format_exc()
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
                conn.nexe_headers['x-nexe-error'] = \
                    conn.error.replace('\n', '')

            #print [final_response.headers, conn.nexe_headers]
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
            self.app.zerovm_ns_thrdpool.spawn_n(self._store_accounting_data, req)
        if self.app.zerovm_use_cors and self.container_name:
            container_info = self.container_info(self.account_name, self.container_name)
            if container_info.get('cors', None):
                if container_info['cors'].get('allow_origin', None):
                    final_response.headers['access-control-allow-origin'] = container_info['cors']['allow_origin']
                if container_info['cors'].get('expose_headers', None):
                    final_response.headers['access-control-expose-headers'] = container_info['cors']['expose_headers']
        etag = md5(str(time.time()))
        final_response.headers['Etag'] = etag.hexdigest()
        return final_response

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
                        app_iter=iter(lambda: server_response.read(self.app.network_chunk_size), ''),
                        headers=dict(server_response.getheaders()))
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
                #print [info.name, info.size, info.offset, info.offset_data]
                if 'sysmap' in info.name:
                    untar_stream.to_write = info.size
                    untar_stream.offset_data = info.offset_data
                    _load_channel_data(node, ExtractedFile(untar_stream))
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
                # dest_header = unquote(chan.path)
                # acct = request.path_info.split('/', 2)[1]
                # dest_header = '/' + acct + dest_header
                # dest_container_name, dest_obj_name =\
                #     dest_header.split('/', 3)[2:]
                dest_req = Request.blank(chan.path.path,
                                         environ=request.environ,
                                         headers=request.headers)
                dest_req.path_info = chan.path.path
                dest_req.method = 'PUT'
                dest_req.headers['content-length'] = info.size
                untar_stream.to_write = info.size
                untar_stream.offset_data = info.offset_data
                dest_req.environ['wsgi.input'] = ExtractedFile(untar_stream)
                dest_req.headers['content-type'] = chan.content_type
                error = update_metadata(dest_req, chan.meta)
                if error:
                    conn.error = error
                    return conn
                dest_resp = \
                    ObjectController(self.app,
                                     chan.path.account,
                                     chan.path.container,
                                     chan.path.obj).PUT(dest_req)
                if dest_resp.status_int >= 300:
                    conn.error = 'Status %s when putting %s' \
                                 % (dest_resp.status, chan.path.path)
                    return conn
                info = untar_stream.get_next_tarinfo()
            bytes_transferred += len(data)
        untar_stream = None
        resp.content_length = 0
        return conn

    def _connect_exec_node(self, obj_nodes, part, request,
                           logger_thread_locals, cnode, request_headers):
        self.app.logger.thread_locals = logger_thread_locals
        for node in obj_nodes:
            try:
                with ConnectionTimeout(self.app.conn_timeout):
                    #if (request.content_length > 0) or 'transfer-encoding' in request_headers:
                    #    request_headers['Expect'] = '100-continue'
                    #request.headers['Connection'] = 'close'
                    request_headers['Expect'] = '100-continue'
                    request_headers['Content-Length'] = str(cnode.size)
                    conn = http_connect(node['ip'], node['port'],
                                        node['device'], part, request.method,
                                        request.path_info, request_headers)
                with Timeout(self.app.node_timeout):
                    resp = conn.getexpect()
                conn.node = node
                conn.cnode = cnode
                conn.nexe_headers = request.resp_headers
                if resp.status == HTTP_CONTINUE:
                    conn.resp = None
                    return conn
                elif is_success(resp.status):
                    conn.resp = resp
                    return conn
                elif resp.status == HTTP_INSUFFICIENT_STORAGE:
                    self.error_limit(node, _('ERROR Insufficient Storage'))
                elif is_client_error(resp.status):
                    conn.error = resp.read()
                    conn.resp = resp
                    return conn
                else:
                    self.app.logger.warn('Obj server failed with: %d %s' % (resp.status, resp.reason))
            except Exception:
                self.exception_occurred(node, _('Object'),
                                        _('Expect: 100-continue on %s') % request.path_info)

    def _store_accounting_data(self, request, connection=None):
        txn_id = request.environ['swift.trans_id']
        acc_object = datetime.datetime.utcnow().strftime('%Y/%m/%d.log')
        if connection:
            body = '%s %s %s (%s) [%s]\n' % (datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
                                             txn_id,
                                             connection.nexe_headers['x-nexe-system'],
                                             connection.nexe_headers['x-nexe-cdr-line'],
                                             connection.nexe_headers['x-nexe-status'])
            request.cdr_log.append(body)
            self.app.logger.info('zerovm-cdr %s %s %s (%s) [%s]'
                                 % (self.account_name,
                                    txn_id,
                                    connection.nexe_headers['x-nexe-system'],
                                    connection.nexe_headers['x-nexe-cdr-line'],
                                    connection.nexe_headers['x-nexe-status']))
        else:
            body = ''.join(request.cdr_log)
            append_req = Request.blank('/%s/%s/%s/%s' % (self.app.version,
                                                         self.app.cdr_account,
                                                         self.account_name,
                                                         acc_object),
                                       headers={'X-Append-To': '-1',
                                                'Content-Length': len(body),
                                                'Content-Type': 'text/plain'},
                                       body=body)
            append_req.method = 'POST'
            resp = append_req.get_response(self.app)
            if resp.status_int >= 300:
                self.app.logger.warn(
                    _('ERROR Cannot write stats for account %s'), self.account_name)

    @delay_denial
    @cors_validation
    def GET(self, req):
        if not self.container_name or not self.object_name:
            return HTTPNotFound(request=req, headers=req.headers)
        obj_req = req.copy_get()
        obj_req.method = 'HEAD'
        if obj_req.environ.get('QUERY_STRING'):
            obj_req.environ['QUERY_STRING'] = ''
        run = False
        if self.object_name[-len('.nexe'):] in '.nexe':
            #let's get a small speedup as it's quite possibly an executable
            obj_req.method = 'GET'
            run = True
        controller = ObjectController(
            self.app,
            self.account_name,
            self.container_name,
            self.object_name)
        handler = getattr(controller, obj_req.method, None)
        obj_resp = handler(obj_req)
        content = obj_resp.content_type.split(';')[0].strip()
        #print content
        if content in 'application/x-nexe':
            run = True
        elif run:
            # speedup did not succeed...
            for chunk in obj_resp.app_iter:
                pass
            obj_req.method = 'HEAD'
            run = False
        template = DEFAULT_EXE_SYSTEM_MAP
        error = self._get_content_config(obj_req, content)
        if error:
            return error
        if obj_req.template:
            template = obj_req.template
        elif not run:
            return HTTPNotFound(request=req,
                                body='No application registered for %s' % content)
        req.path_info_pop()
        location = SwiftPath.init(self.account_name,
                                  self.container_name,
                                  self.object_name)
        config = _config_from_template(req.params, template, location.url)
        #config = re.sub(r'\{\.[^\}]+\}', '', config)
        post_req = Request.blank('/%s' % self.account_name,
                                 environ=req.environ,
                                 headers=req.headers)
        post_req.method = 'POST'
        post_req.headers['content-type'] = 'application/json'
        exe_resp = None
        if obj_req.method in 'GET':
            exe_resp = obj_resp
        return self.POST(post_req, exe_resp=exe_resp, cluster_config=config)

    def _get_content_config(self, req, content_type):
        req.template = None
        cont = self.app.zerovm_registry_path
        obj = '%s/config' % content_type
        config_path = '/%s/%s/%s' % (self.account_name, cont, obj)
        memcache_client = cache_from_env(req.environ)
        memcache_key = 'zvmconf' + config_path
        if memcache_client:
            req.template = memcache_client.get(memcache_key)
            if req.template:
                return
        config_req = req.copy_get()
        config_req.path_info = config_path
        config_resp = ObjectController(
            self.app,
            self.account_name,
            cont,
            obj).GET(config_req)
        if config_resp.status_int == 200:
            req.template = ''
            for chunk in config_resp.app_iter:
                req.template += chunk
                if self.app.zerovm_maxconfig < len(req.template):
                    req.template = None
                    return HTTPRequestEntityTooLarge(request=config_req,
                                                     body='Config file at %s is too large' % config_path)
        if memcache_client and req.template:
            memcache_client.set(memcache_key, req.template,
                                time=float(self.app.zerovm_cache_config_timeout))


def _load_channel_data(node, extracted_file):
    config = json.loads(extracted_file.read())
    for new_ch in config['channels']:
        old_ch = node.get_channel(device=new_ch['device'])
        if old_ch:
            old_ch.content_type = new_ch['content_type']
            if new_ch.get('meta', None):
                for k, v in new_ch.get('meta').iteritems():
                    old_ch.meta[k] = v


def _total_node_count(node_list):
    count = 0
    for n in node_list:
        count += n.replicate
    return count


def _config_from_template(params, template, url):
    for k, v in params.iteritems():
        if k in 'object_path':
            continue
        ptrn = r'\{\.%s(|=[^\}]+)\}'
        ptrn = ptrn % k
        template = re.sub(ptrn, v, template)
    config = template.replace('{.object_path}', url)
    config = re.sub(r'\{\.[^=\}]+=?([^\}]*)\}', '\\1', config)
    return config


def _create_node_name(node_name, i):
    return node_name + '-' + str(i)


def _attach_connections_to_data_sources(conns, data_sources):
    for data_src in data_sources:
        data_src.conns = []
        for node in data_src.nodes:
            for conn in conns:
                if conn.cnode is node['node']:
                    conn.last_data = node['node'].last_data
                    data_src.conns.append({'conn': conn, 'dev': node['dev']})


def _queue_put(conn, data, chunked):
    conn['conn'].queue.put('%x\r\n%s\r\n'
                           % (len(data), data) if chunked else data)


def _send_tar_headers(chunked, data_src):
    for conn in data_src.conns:
        info = conn['conn'].tar_stream.create_tarinfo(ftype=REGTYPE,
                                                      name=conn['dev'],
                                                      size=data_src.content_length)
        for chunk in conn['conn'].tar_stream.serve_chunk(info):
            if not conn['conn'].failed:
                _queue_put(conn, chunk, chunked)


def _send_data_chunk(chunked, data_src, data, req):
    data_src.bytes_transferred += len(data)
    if data_src.bytes_transferred > MAX_FILE_SIZE:
        return HTTPRequestEntityTooLarge(request=req)
    for conn in data_src.conns:
        for chunk in conn['conn'].tar_stream.serve_chunk(data):
            if not conn['conn'].failed:
                _queue_put(conn, chunk, chunked)
            else:
                return HTTPServiceUnavailable(request=req)


def _finalize_tar_streams(chunked, data_src, req):
    blocks, remainder = divmod(data_src.bytes_transferred, BLOCKSIZE)
    if remainder > 0:
        nulls = NUL * (BLOCKSIZE - remainder)
        for conn in data_src.conns:
            for chunk in conn['conn'].tar_stream.serve_chunk(nulls):
                if not conn['conn'].failed:
                    _queue_put(conn, chunk, chunked)
                else:
                    return HTTPServiceUnavailable(request=req)
    for conn in data_src.conns:
        if conn['conn'].last_data is data_src:
            if conn['conn'].tar_stream.data:
                data = conn['conn'].tar_stream.data
                if not conn['conn'].failed:
                    _queue_put(conn, data, chunked)
                else:
                    return HTTPServiceUnavailable(request=req)
            if chunked:
                conn['conn'].queue.put('0\r\n\r\n')


def _get_local_address(node):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((node['ip'], node['port']))
    result = s.getsockname()[0]
    s.shutdown(socket.SHUT_RDWR)
    s.close()
    return result


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def query_filter(app):
        return ProxyQueryMiddleware(app, conf)

    return query_filter
