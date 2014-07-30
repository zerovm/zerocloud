from copy import deepcopy
import ctypes
import re
import struct
import traceback
import time
import datetime
from urllib import unquote
import uuid
from hashlib import md5
from random import randrange, choice
import greenlet
from eventlet import GreenPile, GreenPool, Queue, spawn_n
from eventlet.green import socket
from eventlet.timeout import Timeout
import zlib

from swift.common.storage_policy import POLICIES

from swift.common.request_helpers import get_sys_meta_prefix
from swift.common.wsgi import make_subrequest
from swiftclient.client import quote
from swift.common.http import HTTP_CONTINUE, is_success, \
    HTTP_INSUFFICIENT_STORAGE, is_client_error, HTTP_NOT_FOUND, \
    HTTP_REQUESTED_RANGE_NOT_SATISFIABLE
from swift.proxy.controllers.base import update_headers, delay_denial, \
    cors_validation, get_info, close_swift_conn
from swift.common.utils import split_path, get_logger, TRUE_VALUES, \
    get_remote_client, ContextPool, cache_from_env, normalize_timestamp, \
    GreenthreadSafeIterator
from swift.proxy.server import ObjectController, ContainerController, \
    AccountController
from swift.common.bufferedhttp import http_connect
from swift.common.exceptions import ConnectionTimeout, ChunkReadTimeout
from swift.common.constraints import check_utf8, MAX_FILE_SIZE, MAX_HEADER_SIZE, \
    MAX_META_NAME_LENGTH, MAX_META_VALUE_LENGTH, MAX_META_COUNT, \
    MAX_META_OVERALL_SIZE
from swift.common.swob import Request, Response, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestTimeout, HTTPRequestEntityTooLarge, \
    HTTPBadRequest, HTTPUnprocessableEntity, HTTPServiceUnavailable, \
    HTTPClientDisconnect, wsgify, HTTPNotImplemented, HeaderKeyDict, \
    HTTPException
from zerocloud.common import CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME, TAR_MIMES, \
    POST_TEXT_OBJECT_SYSTEM_MAP, POST_TEXT_ACCOUNT_SYSTEM_MAP, \
    merge_headers, DEFAULT_EXE_SYSTEM_MAP, \
    STREAM_CACHE_SIZE, parse_location, is_swift_path, \
    is_image_path, can_run_as_daemon, SwiftPath, load_server_conf, \
    expand_account_path, TIMEOUT_GRACE
from zerocloud.configparser import ClusterConfigParser, \
    ClusterConfigParsingError
from zerocloud.tarstream import StringBuffer, UntarStream, \
    TarStream, REGTYPE, BLOCKSIZE, NUL, ExtractedFile, Path, ReadError
from zerocloud.thread_pool import Zuid


ZEROVM_COMMANDS = ['open']
ZEROVM_EXECUTE = 'x-zerovm-execute'

try:
    import simplejson as json
except ImportError:
    import json

STRIP_PAX_HEADERS = ['mtime']


# Monkey patching Request to support content_type property properly
def _req_content_type_property():
    """
    Set and retrieve Request.content_type
    Strips off any charset when retrieved
    """
    def getter(self):
        if 'content-type' in self.headers:
            return self.headers.get('content-type').split(';')[0]

    def setter(self, value):
        self.headers['content-type'] = value

    return property(getter, setter,
                    doc="Retrieve and set the request Content-Type header")

Request.content_type = _req_content_type_property()


def check_headers_metadata(new_req, headers, target_type, req, add_all=False):
    prefix = 'x-%s-meta-' % target_type.lower()
    meta_count = 0
    meta_size = 0
    for key, value in headers.iteritems():
        if isinstance(value, basestring) and len(value) > MAX_HEADER_SIZE:
            raise HTTPBadRequest(body='Header value too long: %s' %
                                      key[:MAX_META_NAME_LENGTH],
                                 request=req, content_type='text/plain')
        if not key.lower().startswith(prefix):
            if add_all and key.lower() not in STRIP_PAX_HEADERS and not \
                    key.lower().startswith('x-nexe-'):
                new_req.headers[key] = value
            continue
        new_req.headers[key] = value
        key = key[len(prefix):]
        if not key:
            raise HTTPBadRequest(body='Metadata name cannot be empty',
                                 request=req, content_type='text/plain')
        meta_count += 1
        meta_size += len(key) + len(value)
        if len(key) > MAX_META_NAME_LENGTH:
            raise HTTPBadRequest(
                body='Metadata name too long: %s%s' % (prefix, key),
                request=req, content_type='text/plain')
        elif len(value) > MAX_META_VALUE_LENGTH:
            raise HTTPBadRequest(
                body='Metadata value longer than %d: %s%s' % (
                    MAX_META_VALUE_LENGTH, prefix, key),
                request=req, content_type='text/plain')
        elif meta_count > MAX_META_COUNT:
            raise HTTPBadRequest(
                body='Too many metadata items; max %d' % MAX_META_COUNT,
                request=req, content_type='text/plain')
        elif meta_size > MAX_META_OVERALL_SIZE:
            raise HTTPBadRequest(
                body='Total metadata too large; max %d'
                     % MAX_META_OVERALL_SIZE,
                request=req, content_type='text/plain')


def is_zerocloud_request(version, account, headers):
    return account and (ZEROVM_EXECUTE in headers or version in
                        ZEROVM_COMMANDS)


class GreenPileEx(GreenPile):
    def __init__(self, size_or_pool=1000):
        super(GreenPileEx, self).__init__(size_or_pool)
        self.current = None

    def next(self):
        """Wait for the next result, suspending the current greenthread until it
        is available.  Raises StopIteration when there are no more results."""
        if self.counter == 0 and self.used:
            raise StopIteration()
        try:
            if not self.current:
                self.current = self.waiters.get()
            res = self.current.wait()
            self.current = None
            return res
        finally:
            if not self.current:
                self.counter -= 1


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
        self.bind_map = {}
        self.conn_map = {}
        self.peer_map = {}
        self.int_pool = GreenPool()

    def start(self, pool):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(('', 0))
        self.thread = pool.spawn(self._run)
        (self.hostaddr, self.port) = self.sock.getsockname()

    def _run(self):
        while 1:
            try:
                start = time.time()
                message, peer_address = self.sock.recvfrom(65535)
                offset = 0
                peer_id = struct.unpack_from(NameService.INT_FMT, message,
                                             offset)[0]
                offset += NameService.INT_SIZE
                bind_count = struct.unpack_from(NameService.INT_FMT, message,
                                                offset)[0]
                offset += NameService.INT_SIZE
                connect_count = struct.unpack_from(NameService.INT_FMT,
                                                   message, offset)[0]
                offset += NameService.INT_SIZE
                for i in range(bind_count):
                    connecting_host, port = struct.unpack_from(
                        NameService.INPUT_RECORD_FMT, message, offset)[0:2]
                    offset += NameService.INPUT_RECORD_SIZE
                    self.bind_map.setdefault(peer_id, {})[connecting_host] = \
                        port
                self.conn_map[peer_id] = (connect_count,
                                          offset,
                                          ctypes.create_string_buffer(
                                              message[:]))
                self.peer_map.setdefault(peer_id, {})[0] = peer_address[0]
                self.peer_map.setdefault(peer_id, {})[1] = peer_address[1]

                if len(self.peer_map) == self.peers:
                    print "Finished name server receive in %.3f seconds" \
                          % (time.time() - start)
                    start = time.time()
                    for peer_id in self.peer_map.iterkeys():
                        (connect_count, offset, reply) = self.conn_map[peer_id]
                        for i in range(connect_count):
                            connecting_host = struct.unpack_from(
                                NameService.INT_FMT, reply, offset)[0]
                            port = self.bind_map[connecting_host][peer_id]
                            connect_to = self.peer_map[connecting_host][0]
                            if connect_to == self.peer_map[peer_id][0]:
                                # both on the same host
                                connect_to = '127.0.0.1'
                            struct.pack_into(NameService.OUTPUT_RECORD_FMT,
                                             reply, offset,
                                             socket.inet_pton(socket.AF_INET,
                                                              connect_to),
                                             port)
                            offset += NameService.OUTPUT_RECORD_SIZE
                        self.sock.sendto(reply, (self.peer_map[peer_id][0],
                                                 self.peer_map[peer_id][1]))
                    print "Finished name server send in %.3f seconds" \
                          % (time.time() - start)
            except greenlet.GreenletExit:
                return
            except Exception:
                print traceback.format_exc()
                pass

    def stop(self):
        self.thread.kill()
        self.sock.close()


class ProxyQueryMiddleware(object):

    def list_account(self, account, mask=None, marker=None, request=None):
        new_req = request.copy_get()
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
            data = self.list_account(account, mask=None, marker=marker,
                                     request=request)
        return ret

    def list_container(self, account, container, mask=None, marker=None,
                       request=None):
        new_req = request.copy_get()
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
            data = self.list_container(account, container,
                                       mask=None, marker=marker,
                                       request=request)
        return ret

    def parse_daemon_config(self, daemon_list):
        result = []
        request = Request.blank('/daemon', environ={'REQUEST_METHOD': 'POST'},
                                headers={'Content-Type': 'application/json'})
        socks = {}
        for sock, conf_file in zip(*[iter(daemon_list)] * 2):
            if socks.get(sock, None):
                self.logger.warning('Duplicate daemon config for uuid %s'
                                    % sock)
                continue
            socks[sock] = 1
            try:
                json_config = json.load(open(conf_file))
            except IOError:
                self.logger.warning('Cannot load daemon config file: %s'
                                    % conf_file)
                continue
            parser = ClusterConfigParser(self.zerovm_sysimage_devices,
                                         self.zerovm_content_type,
                                         self.parser_config,
                                         self.list_account,
                                         self.list_container,
                                         network_type=self.network_type)
            try:
                parser.parse(json_config, False, request=request)
            except ClusterConfigParsingError, e:
                self.logger.warning('Daemon config %s error: %s'
                                    % (conf_file, str(e)))
                continue
            if len(parser.nodes) != 1:
                self.logger.warning('Bad daemon config %s: too many nodes'
                                    % conf_file)
            for node in parser.nodes.itervalues():
                if node.bind or node.connect:
                    self.logger.warning('Bad daemon config %s: '
                                        'network channels are present'
                                        % conf_file)
                    continue
                if not is_image_path(node.exe):
                    self.logger.warning('Bad daemon config %s: '
                                        'exe path must be in image file'
                                        % conf_file)
                    continue
                image = None
                for sysimage in parser.sysimage_devices.keys():
                    if node.exe.image == sysimage:
                        image = sysimage
                        break
                if not image:
                    self.logger.warning('Bad daemon config %s: '
                                        'exe is not in sysimage device'
                                        % conf_file)
                    continue
                node.channels = sorted(node.channels, key=lambda ch: ch.device)
                result.append((sock, node))
                self.logger.info('Loaded daemon config %s with UUID %s'
                                 % (conf_file, sock))
        return result

    def __init__(self, app, conf, logger=None,
                 object_ring=None, container_ring=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='proxy-query')
        # let's load appropriate server config sections here
        load_server_conf(conf, ['app:proxy-server'])
        timeout = int(conf.get('zerovm_timeout',
                               conf.get('node_timeout', 10)))
        self.zerovm_timeout = timeout
        self.node_timeout = timeout + (TIMEOUT_GRACE * 2)
        self.immediate_response_timeout = float(conf.get(
            'interactive_timeout', timeout)) + (TIMEOUT_GRACE * 2)
        self.ignore_replication = conf.get(
            'zerovm_ignore_replication', 'f').lower() in TRUE_VALUES
        # network chunk size for all network ops
        self.network_chunk_size = int(conf.get('network_chunk_size',
                                               65536))
        # max time to wait for upload to finish, used in POST requests
        self.max_upload_time = int(conf.get('max_upload_time', 86400))
        self.client_timeout = float(conf.get('client_timeout', 60))
        self.put_queue_depth = int(conf.get('put_queue_depth', 10))
        self.conn_timeout = float(conf.get('conn_timeout', 0.5))
        # execution engine version
        self.zerovm_execute_ver = '1.0'
        # maximum size of a system map file
        self.zerovm_maxconfig = int(conf.get('zerovm_maxconfig', 65536))
        # name server hostname or ip, will be autodetected if not set
        self.zerovm_ns_hostname = conf.get('zerovm_ns_hostname')
        # name server thread pool size
        self.zerovm_ns_maxpool = int(conf.get('zerovm_ns_maxpool', 1000))
        self.zerovm_ns_thrdpool = GreenPool(self.zerovm_ns_maxpool)
        # use newest files when running zerovm executables, default - False
        self.zerovm_uses_newest = conf.get(
            'zerovm_uses_newest', 'f').lower() in TRUE_VALUES
        # use executable validation info, stored on PUT or POST,
        # to shave some time on zerovm startup
        self.zerovm_prevalidate = conf.get(
            'zerovm_prevalidate', 'f').lower() in TRUE_VALUES
        # use CORS workaround to POST execute commands, default - False
        self.zerovm_use_cors = conf.get(
            'zerovm_use_cors', 'f').lower() in TRUE_VALUES
        # Accounting: enable or disabe execution accounting data,
        # default - disabled
        self.zerovm_accounting_enabled = conf.get(
            'zerovm_accounting_enabled', 'f').lower() in TRUE_VALUES
        # Accounting: system account for storing accounting data
        self.cdr_account = conf.get('user_stats_account', 'userstats')
        # Accounting: storage API version
        self.version = 'v1'
        # default content-type for unknown files
        self.zerovm_content_type = conf.get(
            'zerovm_default_content_type', 'application/octet-stream')
        # names of sysimage devices, no sysimage devices exist by default
        devs = [(i.strip(), None)
                for i in conf.get('zerovm_sysimage_devices', '').split()
                if i.strip()]
        self.zerovm_sysimage_devices = dict(devs)
        # GET support: container for content-type association storage
        self.zerovm_registry_path = '.zvm'
        # GET support: cache config files for this amount of seconds
        self.zerovm_cache_config_timeout = 60
        self.parser_config = {
            'limits': {
                # total maximum iops for channel read or write operations
                # per zerovm session
                'reads': int(conf.get('zerovm_maxiops', 1024 * 1048576)),
                'writes': int(conf.get('zerovm_maxiops', 1024 * 1048576)),
                # total maximum bytes for a channel write operations
                # per zerovm session
                'rbytes': int(conf.get('zerovm_maxoutput', 1024 * 1048576)),
                # total maximum bytes for a channel read operations
                # per zerovm session
                'wbytes': int(conf.get('zerovm_maxinput', 1024 * 1048576))
            }
        }
        # storage policies that will be used for random node picking
        policies = [i.strip()
                    for i in conf.get('standalone_policies', '').split()
                    if i.strip()]
        self.standalone_policies = []
        for pol in policies:
            try:
                pol_idx = int(pol)
                policy = POLICIES.get_by_index(pol_idx)
            except ValueError:
                policy = POLICIES.get_by_name(pol)
            if policy:
                self.standalone_policies.append(policy.idx)
            else:
                self.logger.warning('Could not load storage policy: %s'
                                    % pol)
        if not self.standalone_policies:
            self.standalone_policies = [0]
        # use direct tcp connections (tcp) or intermediate broker (opaque)
        self.network_type = conf.get('zerovm_network_type', 'tcp')
        # opaque network does not support replication right now
        if self.network_type == 'opaque':
            self.ignore_replication = True
        # list of daemons we need to lazy load
        # (first request will start the daemon)
        daemon_list = [i.strip() for i in
                       conf.get('zerovm_daemons', '').split() if i.strip()]
        self.zerovm_daemons = self.parse_daemon_config(daemon_list)
        self.uid_generator = Zuid()

    @wsgify
    def __call__(self, req):
        try:
            version, account, container, obj = split_path(req.path, 1, 4, True)
        except ValueError:
            return HTTPNotFound(request=req)
        if is_zerocloud_request(version, account, req.headers):
            exec_ver = '%s/%s' % (version, self.zerovm_execute_ver)
            exec_header_ver = req.headers.get(ZEROVM_EXECUTE, exec_ver)
            req.headers[ZEROVM_EXECUTE] = exec_header_ver
            if req.content_length and req.content_length < 0:
                return HTTPBadRequest(request=req,
                                      body='Invalid Content-Length')
            if not check_utf8(req.path_info):
                return HTTPPreconditionFailed(request=req, body='Invalid UTF8')
            controller = self.get_controller(exec_header_ver, account,
                                             container, obj)
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
            if version:
                req.path_info_pop()
            try:
                handler = getattr(controller, req.method)
            except AttributeError:
                return HTTPPreconditionFailed(request=req,
                                              body='Bad HTTP method')
            # we do not deny access based on user account permissions
            # as users can allow other users to run their code and be billed
            # accordingly
            # more than that, accounts can allow anonymous people to run
            # executables, and these accounts will be billed for that
            # if 'swift.authorize' in req.environ:
            #     resp = req.environ['swift.authorize'](req)
            #     if not resp:
            #         del req.environ['swift.authorize']
            #     else:
            #         if not getattr(handler, 'delay_denial', None):
            #             return resp
            start_time = time.time()
            # each request is assigned a unique k-sorted id
            # it will be used by QoS code to assign slots/priority
            req.headers['x-zerocloud-id'] = self.uid_generator.get()
            req.headers['x-zerovm-timeout'] = self.zerovm_timeout
            try:
                res = handler(req)
            except HTTPException as error_response:
                return error_response
            perf = time.time() - start_time
            if 'x-nexe-cdr-line' in res.headers:
                res.headers['x-nexe-cdr-line'] = \
                    '%.3f, %s' % (perf, res.headers['x-nexe-cdr-line'])
            return res
        return self.app

    def get_controller(self, version, account, container, obj):
        if version == 'open/1.0':
            if container and obj:
                return RestController(self.app, account, container, obj, self,
                                      version)
            return None
        return ClusterController(self.app, account, container, obj, self,
                                 version)


def select_random_partition(ring):
    partition_count = ring.partition_count
    part = randrange(0, partition_count)
    return part


class ClusterController(ObjectController):

    header_exclusions = [get_sys_meta_prefix('account'),
                         get_sys_meta_prefix('container'),
                         get_sys_meta_prefix('object'),
                         'x-backend', 'x-auth', 'content-type',
                         'content-length']

    def __init__(self, app, account_name, container_name, obj_name, middleware,
                 command, **kwargs):
        ObjectController.__init__(self, app,
                                  account_name,
                                  container_name or '',
                                  obj_name or '')
        self.middleware = middleware
        self.command = command
        self.parser = ClusterConfigParser(
            self.middleware.zerovm_sysimage_devices,
            self.middleware.zerovm_content_type,
            self.middleware.parser_config,
            self.middleware.list_account,
            self.middleware.list_container,
            network_type=self.middleware.network_type)
        self.exclusion_test = self.make_exclusion_test()
        self.image_resp = None
        self.cgi_env = None
        self.exe_resp = None
        self.cluster_config = ''

    def create_cgi_env(self, req):
        headers = dict(req.headers)
        keys = filter(self.exclusion_test, headers)
        for key in keys:
            headers.pop(key)
        env = {}
        env.update(('HTTP_' + k.upper().replace('-', '_'), v)
                   for k, v in headers.items())
        env['REQUEST_METHOD'] = req.method
        env['REMOTE_USER'] = req.remote_user
        env['QUERY_STRING'] = req.query_string
        env['PATH_INFO'] = req.path_info
        env['REQUEST_URI'] = req.path_qs
        return env

    def make_exclusion_test(self):
        expr = '|'.join(self.header_exclusions)
        test = re.compile(expr, re.IGNORECASE)
        return test.match

    def get_daemon_socket(self, config):
        for daemon_sock, daemon_conf in self.middleware.zerovm_daemons:
            if can_run_as_daemon(config, daemon_conf):
                return daemon_sock
        return None

    def get_standalone_policy(self):
        policy = choice(self.middleware.standalone_policies)
        ring = self.app.get_object_ring(policy)
        return ring, policy

    def _get_own_address(self):
        if self.middleware.zerovm_ns_hostname:
            addr = self.middleware.zerovm_ns_hostname
        else:
            addr = None
            object_ring = self.app.get_object_ring(0)
            partition_count = object_ring.partition_count
            part = randrange(0, partition_count)
            nodes = object_ring.get_part_nodes(part)
            for n in nodes:
                addr = _get_local_address(n)
                if addr:
                    break
        return addr

    def _make_exec_requests(self, pile, exec_requests):
        for exec_request in exec_requests:
            node = exec_request.node
            account, container, obj = \
                split_path(node.path_info, 1, 3, True)
            if obj:
                container_info = self.container_info(
                    account, container, exec_request)
                policy_index = exec_request.headers.get(
                    'X-Backend-Storage-Policy-Index',
                    container_info['storage_policy'])
                ring = self.app.get_object_ring(policy_index)
                partition = ring.get_part(account, container, obj)
                node_iter = GreenthreadSafeIterator(
                    self.iter_nodes_local_first(ring,
                                                partition))
                exec_request.headers['X-Backend-Storage-Policy-Index'] = \
                    str(policy_index)
            elif container:
                ring = self.app.container_ring
                partition = ring.get_part(account, container)
                node_iter = GreenthreadSafeIterator(
                    self.app.iter_nodes(ring, partition))
            else:
                object_ring, policy_index = self.get_standalone_policy()
                partition = select_random_partition(object_ring)
                node_iter = GreenthreadSafeIterator(
                    self.iter_nodes_local_first(
                        object_ring,
                        partition))
                exec_request.headers['X-Backend-Storage-Policy-Index'] = \
                    str(policy_index)
            exec_request.path_info = node.path_info
            exec_request.headers['x-zerovm-access'] = node.access
            if node.replicate > 1:
                container_info = self.container_info(account, container)
                container_partition = container_info['partition']
                containers = container_info['nodes']
                exec_headers = self._backend_requests(exec_request,
                                                      node.replicate,
                                                      container_partition,
                                                      containers)
                if node.skip_validation:
                    for hdr in exec_headers:
                        hdr['x-zerovm-valid'] = 'true'
                i = 0
                pile.spawn(self._connect_exec_node,
                           node_iter,
                           partition,
                           exec_request,
                           self.app.logger.thread_locals,
                           node,
                           exec_headers[i])
                for repl_node in node.replicas:
                    i += 1
                    pile.spawn(self._connect_exec_node,
                               node_iter,
                               partition,
                               exec_request,
                               self.app.logger.thread_locals,
                               repl_node,
                               exec_headers[i])
            else:
                if node.skip_validation:
                    exec_request.headers['x-zerovm-valid'] = 'true'
                pile.spawn(self._connect_exec_node,
                           node_iter,
                           partition,
                           exec_request,
                           self.app.logger.thread_locals,
                           node,
                           exec_request.headers)
        return [conn for conn in pile if conn]

    def _spawn_file_senders(self, conns, pool, req):
        for conn in conns:
            conn.failed = False
            conn.queue = Queue(self.middleware.put_queue_depth)
            conn.tar_stream = TarStream()
            pool.spawn(self._send_file, conn, req.path)

    def _create_request_for_remote_object(self, data_sources, channel,
                                          req, nexe_headers, node):
        source_resp = None
        load_from = channel.path.path
        if is_swift_path(channel.path) and not channel.path.obj:
            return HTTPBadRequest(request=req,
                                  body='Cannot use container %s as a remote '
                                       'object reference' % load_from)
        for resp in data_sources:
            if resp.request and load_from == resp.request.path_info:
                source_resp = resp
                break
        if not source_resp:
            source_req = req.copy_get()
            source_req.path_info = load_from
            source_req.query_string = None
            if self.middleware.zerovm_uses_newest:
                source_req.headers['X-Newest'] = 'true'
            if self.middleware.zerovm_prevalidate \
                    and 'boot' in channel.device:
                source_req.headers['X-Zerovm-Valid'] = 'true'
            acct, src_container_name, src_obj_name =\
                split_path(load_from, 1, 3, True)
            container_info = self.container_info(acct, src_container_name)
            source_req.acl = container_info['read_acl']
            # left here for exec_acl support
            # if 'boot' in ch.device:
            #     source_req.acl = container_info['exec_acl']
            source_resp = \
                ObjectController(self.app,
                                 acct,
                                 src_container_name,
                                 src_obj_name).GET(source_req)
            if source_resp.status_int >= 300:
                update_headers(source_resp, nexe_headers)
                source_resp.body = 'Error %s while fetching %s' \
                                   % (source_resp.status,
                                      source_req.path_info)
                return source_resp
            source_resp.nodes = []
            data_sources.append(source_resp)
        node.last_data = source_resp
        source_resp.nodes.append({'node': node, 'dev': channel.device})
        if source_resp.headers.get('x-zerovm-valid', None) \
                and 'boot' in channel.device:
            node.skip_validation = True
        for repl_node in node.replicas:
            repl_node.last_data = source_resp
            source_resp.nodes.append({'node': repl_node,
                                      'dev': channel.device})

    def create_final_response(self, conns, req):
        final_body = None
        final_response = Response(request=req)
        req.cdr_log = []
        for conn in conns:
            resp = conn.resp
            if conn.error:
                conn.nexe_headers['x-nexe-error'] = \
                    conn.error.replace('\n', '')
            if conn.resp.status_int > final_response.status_int:
                final_response.status = conn.resp.status
            merge_headers(final_response.headers, conn.nexe_headers,
                          resp.headers)
            self._store_accounting_data(req, conn)
            if is_success(resp.status_int) and 'x-nexe-status' not in \
                    resp.headers:
                # looks like the middleware is not installed
                # or not functioning otherwise we should get something
                return HTTPServiceUnavailable(
                    request=req,
                    headers=resp.headers,
                    body='objectquery middleware is not installed '
                         'or not functioning')
            if resp and resp.headers.get('x-zerovm-daemon', None):
                final_response.headers['x-nexe-cached'] = 'true'
            if resp and resp.content_length > 0:
                if not resp.app_iter:
                    resp.app_iter = [resp.body]
                if final_body:
                    final_body.append(resp.app_iter)
                    final_response.content_length += resp.content_length
                else:
                    final_body = FinalBody(resp.app_iter)
                    final_response.app_iter = final_body
                    final_response.content_length = resp.content_length
                    final_response.content_type = resp.headers['content-type']
        if self.middleware.zerovm_accounting_enabled:
            self.middleware.zerovm_ns_thrdpool.spawn_n(
                self._store_accounting_data,
                req)
        if self.middleware.zerovm_use_cors and self.container_name:
            container_info = self.container_info(self.account_name,
                                                 self.container_name)
            if container_info.get('cors', None):
                if container_info['cors'].get('allow_origin', None):
                    final_response.headers['access-control-allow-origin'] = \
                        container_info['cors']['allow_origin']
                if container_info['cors'].get('expose_headers', None):
                    final_response.headers['access-control-expose-headers'] = \
                        container_info['cors']['expose_headers']
        etag = md5(str(time.time()))
        final_response.headers['Etag'] = etag.hexdigest()
        return final_response

    def read_system_map(self, read_iter, chunk_size, content_type, req):
        try:
            if content_type in ['application/x-gzip']:
                read_iter = gunzip_iter(read_iter, chunk_size)
            path_list = [StringBuffer(CLUSTER_CONFIG_FILENAME),
                         StringBuffer(NODE_CONFIG_FILENAME)]
            untar_stream = UntarStream(read_iter, path_list)
            for chunk in untar_stream:
                req.bytes_transferred += len(chunk)
        except (ReadError, zlib.error):
            raise HTTPUnprocessableEntity(
                request=req,
                body='Error reading %s stream'
                     % content_type)
        for buf in path_list:
            if buf.is_closed:
                self.cluster_config = buf.body
                break

    def _load_input_from_chain(self, req, chunk_size):
        data_resp = None
        if 'chain.input' in req.environ:
            chain_input = req.environ['chain.input']
            bytes_left = int(req.environ['chain.input_size']) - \
                chain_input.bytes_received
            if bytes_left > 0:
                data_resp = Response(
                    app_iter=iter(lambda: chain_input.read(
                        chunk_size), ''),
                    headers={
                        'Content-Length': bytes_left,
                        'Content-Type': req.environ['chain.input_type']})
                data_resp.nodes = []
        return data_resp

    def post_job(self, req):
        chunk_size = self.middleware.network_chunk_size
        if 'content-type' not in req.headers:
            return HTTPBadRequest(request=req,
                                  body='Must specify Content-Type')
        upload_expiration = time.time() + self.middleware.max_upload_time
        etag = md5()
        rdata = req.environ['wsgi.input']
        req_iter = iter(lambda: rdata.read(chunk_size), '')
        data_resp = None
        source_header = req.headers.get('X-Zerovm-Source')
        if source_header:
            source_loc = parse_location(unquote(source_header))
            if not is_swift_path(source_loc):
                return HTTPPreconditionFailed(
                    request=req,
                    body='X-Zerovm-Source format is '
                         'swift://account/container/object')
            if req.content_length:
                data_resp = Response(
                    app_iter=iter(lambda: rdata.read(chunk_size), ''),
                    headers={
                        'Content-Length': req.content_length,
                        'Content-Type': req.content_type})
                data_resp.nodes = []
            source_loc = expand_account_path(self.account_name, source_loc)
            source_req = make_subrequest(req.environ, method='GET',
                                         swift_source='zerocloud')
            source_req.path_info = source_loc.path
            source_req.query_string = None
            sink_req = Request.blank(req.path_info,
                                     environ=req.environ, headers=req.headers)
            source_resp = source_req.get_response(self.app)
            if not is_success(source_resp.status_int):
                return source_resp
            del sink_req.headers['X-Zerovm-Source']
            sink_req.content_length = source_resp.content_length
            sink_req.content_type = source_resp.headers['Content-Type']
            sink_req.etag = source_resp.etag
            req_iter = iter(source_resp.app_iter)
            req = sink_req
        req.bytes_transferred = 0
        req_content_type = req.content_type
        if req_content_type in ['application/x-gzip']:
            req_content_type = TAR_MIMES[0]
        if req_content_type in TAR_MIMES:
            # we must have Content-Length set for tar-based requests
            # as it will be impossible to stream them otherwise
            if 'content-length' not in req.headers:
                return HTTPBadRequest(request=req,
                                      body='Must specify Content-Length')
            headers = {'Content-Type': req.content_type,
                       'Content-Length': req.content_length}
            if not self.cluster_config:
                # buffer first blocks of tar file
                # and search for the system map
                cached_body = CachedBody(req_iter)
                self.read_system_map(cached_body.cache, chunk_size,
                                     req.content_type, req)
                if not self.cluster_config:
                    return HTTPBadRequest(request=req,
                                          body='System boot map was not '
                                               'found in request')
                req_iter = iter(cached_body)
            if not self.image_resp:
                self.image_resp = Response(app_iter=req_iter,
                                           headers=headers)
            self.image_resp.nodes = []
            try:
                cluster_config = json.loads(self.cluster_config)
            except Exception:
                return HTTPUnprocessableEntity(body='Could not parse '
                                                    'system map')
        elif req_content_type in 'application/json':
            # System map was sent as a POST body
            if not self.cluster_config:
                for chunk in req_iter:
                    req.bytes_transferred += len(chunk)
                    if time.time() > upload_expiration:
                        return HTTPRequestTimeout(request=req)
                    if req.bytes_transferred > \
                            self.middleware.zerovm_maxconfig:
                        return HTTPRequestEntityTooLarge(request=req)
                    etag.update(chunk)
                    self.cluster_config += chunk
                if 'content-length' in req.headers and \
                   int(req.headers['content-length']) != req.bytes_transferred:
                    return HTTPClientDisconnect(request=req,
                                                body='application/json '
                                                     'POST unfinished')
                etag = etag.hexdigest()
                if 'etag' in req.headers and\
                   req.headers['etag'].lower() != etag:
                    return HTTPUnprocessableEntity(request=req)
            try:
                cluster_config = json.loads(self.cluster_config)
            except Exception:
                return HTTPUnprocessableEntity(
                    body='Could not parse system map')
        else:
            # assume the posted data is a script and try to execute
            if 'content-length' not in req.headers:
                return HTTPBadRequest(request=req,
                                      body='Must specify Content-Length')
            cached_body = CachedBody(req_iter)
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
                                      body='Cannot find '
                                           'shebang (#!) in script')
            command_line = re.split('\s+',
                                    re.sub('^#!\s*(.*)', '\\1', shebang), 1)
            sysimage = None
            args = None
            exe_path = command_line[0]
            location = parse_location(exe_path)
            if not location:
                return HTTPBadRequest(request=req,
                                      body='Bad interpreter %s' % exe_path)
            if is_image_path(location):
                if 'image' == location.image:
                    return HTTPBadRequest(request=req,
                                          body='Must supply image name '
                                               'in shebang url %s'
                                               % location.url)
                sysimage = location.image
            if len(command_line) > 1:
                args = command_line[1]
            params = {'exe_path': exe_path}
            if args:
                params['args'] = args.strip() + " "
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
                return HTTPUnprocessableEntity(body='Could not parse '
                                                    'system map')
            if sysimage:
                cluster_config[0]['file_list'].append({'device': sysimage})
            string_path = Path(REGTYPE,
                               'script',
                               int(req.headers['content-length']),
                               cached_body)
            stream = TarStream(path_list=[string_path])
            stream_length = stream.get_total_stream_length()
            self.image_resp = Response(app_iter=iter(stream),
                                       headers={
                                           'Content-Length': stream_length})
            self.image_resp.nodes = []

        req.path_info = '/' + self.account_name
        try:
            replica_count = None
            if self.middleware.ignore_replication:
                replica_count = 1

            def replica_resolver(account, container):
                container_info = self.container_info(account, container, req)
                ring = self.app.get_object_ring(
                    container_info['storage_policy'])
                return ring.replica_count

            self.parser.parse(cluster_config,
                              self.image_resp is not None,
                              self.account_name,
                              replica_count,
                              replica_resolver=replica_resolver,
                              request=req)
        except ClusterConfigParsingError, e:
            self.app.logger.warn(
                'ERROR Error parsing config: %s', cluster_config)
            return HTTPBadRequest(request=req, body=str(e))

        # for n in self.parser.node_list:
        #     print n.dumps(indent=2)

        if not self.cgi_env:
            self.cgi_env = self.create_cgi_env(req)
        data_sources = []
        if self.exe_resp:
            self.exe_resp.nodes = []
            data_sources.append(self.exe_resp)
        addr = self._get_own_address()
        if not addr:
            return HTTPServiceUnavailable(
                body='Cannot find own address, check zerovm_ns_hostname')
        ns_server = None
        network_is_tcp = self.middleware.network_type == 'tcp'
        if self.parser.total_count > 1 and network_is_tcp:
            ns_server = NameService(self.parser.total_count)
            if self.middleware.zerovm_ns_thrdpool.free() <= 0:
                return HTTPServiceUnavailable(
                    body='Cluster slot not available',
                    request=req)
            ns_server.start(self.middleware.zerovm_ns_thrdpool)
            if not ns_server.port:
                return HTTPServiceUnavailable(body='Cannot bind name service')
        exec_requests = []
        load_data_resp = True
        for node in self.parser.node_list:
            nexe_headers = HeaderKeyDict({
                'x-nexe-system': node.name,
                'x-nexe-status': 'ZeroVM did not run',
                'x-nexe-retcode': 0,
                'x-nexe-etag': '',
                'x-nexe-validation': 0,
                'x-nexe-cdr-line': '0.0 0.0 0 0 0 0 0 0 0 0',
                'x-nexe-policy': ''
            })
            path_info = req.path_info
            exec_request = Request.blank(path_info,
                                         environ=req.environ,
                                         headers=req.headers)
            exec_request.path_info = path_info
            exec_request.etag = None
            exec_request.content_type = TAR_MIMES[0]
            # chunked encoding handling looks broken in Swift
            # but let's leave it here, maybe somebody will fix it
            # exec_request.content_length = None
            # exec_request.headers['transfer-encoding'] = 'chunked'
            exec_request.headers['x-account-name'] = self.account_name
            exec_request.headers['x-timestamp'] = \
                normalize_timestamp(time.time())
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
            if self.parser.total_count > 1:
                self.parser.build_connect_string(
                    node, req.headers.get('x-trans-id'))
                if node.replicate > 1:
                    for i in range(0, node.replicate - 1):
                        node.replicas.append(deepcopy(node))
                        node.replicas[i].id = \
                            node.id + (i + 1) * len(self.parser.node_list)
            node.copy_cgi_env(request=exec_request, cgi_env=self.cgi_env)
            resp = node.create_sysmap_resp()
            node.add_data_source(data_sources, resp, 'sysmap')
            for repl_node in node.replicas:
                repl_node.copy_cgi_env(request=exec_request,
                                       cgi_env=self.cgi_env)
                resp = repl_node.create_sysmap_resp()
                repl_node.add_data_source(data_sources, resp, 'sysmap')
            channels = self.parser.get_list_of_remote_objects(node)
            for ch in channels:
                error = self._create_request_for_remote_object(data_sources,
                                                               ch,
                                                               req,
                                                               nexe_headers,
                                                               node)
                if error:
                    return error
            if self.image_resp:
                node.last_data = self.image_resp
                self.image_resp.nodes.append({'node': node,
                                              'dev': 'image'})
                for repl_node in node.replicas:
                    repl_node.last_data = self.image_resp
                    self.image_resp.nodes.append({'node': repl_node,
                                                  'dev': 'image'})
            if node.data_in:
                if not data_resp and load_data_resp:
                    data_resp = self._load_input_from_chain(req, chunk_size)
                    load_data_resp = False
                if data_resp:
                    node.last_data = data_resp
                    data_resp.nodes.append({'node': node,
                                            'dev': 'stdin'})
                    for repl_node in node.replicas:
                        repl_node.last_data = data_resp
                        data_resp.nodes.append({'node': repl_node,
                                                'dev': 'stdin'})
            if not getattr(node, 'path_info', None):
                node.path_info = path_info
            exec_request.node = node
            exec_request.resp_headers = nexe_headers
            sock = self.get_daemon_socket(node)
            if sock:
                exec_request.headers['x-zerovm-daemon'] = str(sock)
            exec_requests.append(exec_request)

        if self.image_resp and self.image_resp.nodes:
            data_sources.append(self.image_resp)
        if data_resp and data_resp.nodes:
            data_sources.append(data_resp)
        tstream = TarStream()
        for data_src in data_sources:
            for n in data_src.nodes:
                if not getattr(n['node'], 'size', None):
                    n['node'].size = 0
                n['node'].size += len(tstream.create_tarinfo(
                    ftype=REGTYPE,
                    name=n['dev'],
                    size=data_src.content_length))
                n['node'].size += \
                    TarStream.get_archive_size(data_src.content_length)
        pile = GreenPileEx(self.parser.total_count)
        conns = self._make_exec_requests(pile, exec_requests)
        if len(conns) < self.parser.total_count:
            self.app.logger.exception(
                'ERROR Cannot find suitable node to execute code on')
            for conn in conns:
                close_swift_conn(getattr(conn, 'resp'))
            return HTTPServiceUnavailable(
                body='Cannot find suitable node to execute code on')

        for conn in conns:
            if hasattr(conn, 'error'):
                if hasattr(conn, 'resp'):
                    close_swift_conn(conn.resp)
                return Response(app_iter=[conn.error],
                                status="%d %s" % (conn.resp.status,
                                                  conn.resp.reason),
                                headers=conn.nexe_headers)

        _attach_connections_to_data_sources(conns, data_sources)

        # chunked encoding handling looks broken in Swift
        # but let's leave it here, maybe somebody will fix it
        # chunked = req.headers.get('transfer-encoding')
        chunked = False
        try:
            with ContextPool(self.parser.total_count) as pool:
                self._spawn_file_senders(conns, pool, req)
                for data_src in data_sources:
                    data_src.bytes_transferred = 0
                    _send_tar_headers(chunked, data_src)
                    while True:
                        with ChunkReadTimeout(self.middleware.client_timeout):
                            try:
                                data = next(data_src.app_iter)
                            except StopIteration:
                                error = _finalize_tar_streams(chunked,
                                                              data_src,
                                                              req)
                                if error:
                                    return error
                                break
                        error = _send_data_chunk(chunked, data_src, data, req)
                        if error:
                            return error
                    if data_src.bytes_transferred < data_src.content_length:
                        return HTTPClientDisconnect(
                            request=req,
                            body='data source %s dead' % data_src.__dict__)
                for conn in conns:
                    if conn.queue.unfinished_tasks:
                        conn.queue.join()
                    conn.tar_stream = None
        except ChunkReadTimeout, err:
            self.app.logger.warn(
                'ERROR Client read timeout (%ss)', err.seconds)
            self.app.logger.increment('client_timeouts')
            return HTTPRequestTimeout(request=req)
        except (Exception, Timeout):
            print traceback.format_exc()
            self.app.logger.exception(
                'ERROR Exception causing client disconnect')
            return HTTPClientDisconnect(request=req, body='exception')

        for conn in conns:
            pile.spawn(self._process_response, conn, req)
        do_defer = req.headers.get('x-zerovm-deferred', 'never').lower()
        if do_defer == 'always':
            defer_timeout = 0
        elif do_defer == 'auto':
            defer_timeout = self.middleware.immediate_response_timeout
        else:
            defer_timeout = None
        conns = []
        try:
            with Timeout(seconds=defer_timeout):
                for conn in pile:
                    if conn:
                        conns.append(conn)
        except Timeout:

            def store_deferred_response(deferred_url):
                for conn in pile:
                    if conn:
                        conns.append(conn)
                resp = self.create_final_response(conns, req)
                path = SwiftPath(deferred_url)
                container_info = get_info(self.app, req.environ.copy(),
                                          path.account, path.container,
                                          ret_not_found=True)
                if container_info['status'] == HTTP_NOT_FOUND:
                    # try to create the container
                    cont_req = Request(req.environ.copy())
                    cont_req.path_info = '/%s/%s' % (path.account,
                                                     path.container)
                    cont_req.method = 'PUT'
                    cont_resp = \
                        ContainerController(self.app,
                                            path.account,
                                            path.container).PUT(cont_req)
                    if cont_resp.status_int >= 300:
                        self.app.logger.warn(
                            'Failed to create deferred container: %s'
                            % cont_req.url)
                        return
                resp.input_iter = iter(resp.app_iter)

                def iter_read(chunk_size=None):
                    if chunk_size is None:
                        return ''.join(resp.input_iter)
                    chunk = next(resp.input_iter)
                    return chunk
                resp.read = iter_read

                deferred_put = Request(req.environ.copy())
                deferred_put.path_info = path.path
                deferred_put.method = 'PUT'
                deferred_put.environ['wsgi.input'] = resp
                deferred_put.content_length = resp.content_length
                deferred_resp = ObjectController(self.app,
                                                 path.account,
                                                 path.container,
                                                 path.obj).PUT(deferred_put)
                if deferred_resp.status_int >= 300:
                    self.app.logger.warn(
                        'Failed to create deferred object: %s : %s'
                        % (deferred_put.url, deferred_resp.status))
                report = self._create_deferred_report(resp.headers)
                resp.input_iter = iter([report])
                deferred_put = Request(req.environ.copy())
                deferred_put.path_info = path.path + '.headers'
                deferred_put.method = 'PUT'
                deferred_put.environ['wsgi.input'] = resp
                deferred_put.content_length = len(report)
                deferred_resp = \
                    ObjectController(self.app,
                                     path.account,
                                     path.container,
                                     path.obj + '.headers').PUT(deferred_put)
                if deferred_resp.status_int >= 300:
                    self.app.logger.warn(
                        'Failed to create deferred object: %s : %s'
                        % (deferred_put.url, deferred_resp.status))
            if self.container_name:
                container = self.container_name
            else:
                container = self.middleware.zerovm_registry_path
            if self.object_name:
                obj = self.object_name
            else:
                obj = 'job-%s' % uuid.uuid4()
            deferred_path = SwiftPath.init(self.account_name, container, obj)
            resp = Response(request=req,
                            body=deferred_path.url)
            spawn_n(store_deferred_response, deferred_path.url)
            if ns_server:
                ns_server.stop()
            return resp
        if ns_server:
            ns_server.stop()
        return self.create_final_response(conns, req)

    def process_server_response(self, conn, request, resp):
        conn.resp = resp
        if not is_success(resp.status_int):
            conn.error = resp.body
            return conn
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
                headers = info.get_headers()
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
                    resp.content_length = headers['Content-Length']
                    resp.content_type = headers['Content-Type']
                    check_headers_metadata(resp, headers, 'object', request,
                                           add_all=True)
                    if resp.headers.get('status'):
                        resp.status = resp.headers['status']
                        del resp.headers['status']
                    return conn
                dest_req = Request.blank(chan.path.path,
                                         environ=request.environ,
                                         headers=request.headers)
                dest_req.path_info = chan.path.path
                dest_req.query_string = None
                dest_req.method = 'PUT'
                dest_req.headers['content-length'] = headers['Content-Length']
                untar_stream.to_write = info.size
                untar_stream.offset_data = info.offset_data
                dest_req.environ['wsgi.input'] = ExtractedFile(untar_stream)
                dest_req.content_type = headers['Content-Type']
                check_headers_metadata(dest_req, headers, 'object', request)
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

    def _process_response(self, conn, request):
        conn.error = None
        chunk_size = self.middleware.network_chunk_size
        if conn.resp:
            server_response = conn.resp
            resp = Response(status='%d %s' %
                                   (server_response.status,
                                    server_response.reason),
                            app_iter=iter(lambda: server_response.read(
                                chunk_size), ''),
                            headers=dict(server_response.getheaders()))
        else:
            try:
                with Timeout(self.middleware.node_timeout):
                    server_response = conn.getresponse()
                    resp = Response(status='%d %s' %
                                           (server_response.status,
                                            server_response.reason),
                                    app_iter=iter(lambda: server_response.read(
                                        chunk_size), ''),
                                    headers=dict(server_response.getheaders()))
            except (Exception, Timeout):
                self.app.exception_occurred(
                    conn.node, 'Object',
                    'Trying to get final status of POST to %s'
                    % request.path_info)
                resp = HTTPRequestTimeout(
                    body='Timeout: trying to get final status of POST '
                         'to %s' % request.path_info)
        return self.process_server_response(conn, request, resp)

    def _connect_exec_node(self, obj_nodes, part, request,
                           logger_thread_locals, cnode, request_headers):
        self.app.logger.thread_locals = logger_thread_locals
        conn = None
        for node in obj_nodes:
            try:
                with ConnectionTimeout(self.middleware.conn_timeout):
                    request.headers['Connection'] = 'close'
                    request_headers['Expect'] = '100-continue'
                    request_headers['Content-Length'] = str(cnode.size)
                    conn = http_connect(node['ip'], node['port'],
                                        node['device'], part, request.method,
                                        request.path_info, request_headers)
                with Timeout(self.middleware.node_timeout):
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
                    self.app.error_limit(node,
                                         'ERROR Insufficient Storage')
                    conn.error = 'Insufficient Storage'
                    conn.resp = resp
                    resp.nuke_from_orbit()
                elif is_client_error(resp.status):
                    conn.error = resp.read()
                    conn.resp = resp
                    if resp.status == HTTP_NOT_FOUND:
                        conn.error = 'Error %d %s while fetching %s' \
                                     % (resp.status, resp.reason,
                                        request.path_info)
                    else:
                        return conn
                else:
                    self.app.logger.warn('Obj server failed with: %d %s'
                                         % (resp.status, resp.reason))
                    conn.error = resp.read()
                    conn.resp = resp
                    resp.nuke_from_orbit()
            except Exception:
                self.app.exception_occurred(node, 'Object',
                                            'Expect: 100-continue on %s'
                                            % request.path_info)
                if getattr(conn, 'resp'):
                    conn.resp.nuke_from_orbit()
                conn = None
        if conn:
            return conn

    def _store_accounting_data(self, request, connection=None):
        txn_id = request.environ['swift.trans_id']
        acc_object = datetime.datetime.utcnow().strftime('%Y/%m/%d.log')
        if connection:
            body = '%s %s %s (%s) [%s]\n' % (
                datetime.datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
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
            append_req = Request.blank('/%s/%s/%s/%s'
                                       % (self.middleware.version,
                                          self.middleware.cdr_account,
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
                    'ERROR Cannot write stats for account %s',
                    self.account_name)

    def _create_deferred_report(self, headers):
        # just dumps headers as a json object for now
        return json.dumps(dict(headers))

    def replica_resolver(self, path_info, request=None):
        if not request:
            return self.app.get_object_ring(0).replica_count
        try:
            account, container, obj = split_path(path_info, 3, 3, True)
        except ValueError:
            return self.app.get_object_ring(0).replica_count
        container_info = self.container_info(account, container, request)
        ring = self.app.get_object_ring(container_info['storage_policy'])
        return ring.replica_count

    @delay_denial
    @cors_validation
    def GET(self, req):
        return HTTPNotImplemented(request=req)

    @delay_denial
    @cors_validation
    def PUT(self, req):
        return HTTPNotImplemented(request=req)

    @delay_denial
    @cors_validation
    def DELETE(self, req):
        return HTTPNotImplemented(request=req)

    @delay_denial
    @cors_validation
    def HEAD(self, req):
        return HTTPNotImplemented(request=req)

    @delay_denial
    @cors_validation
    def POST(self, req):
        return self.post_job(req)


class RestController(ClusterController):

    def _get_content_config(self, req, content_type):
        req.template = None
        cont = self.middleware.zerovm_registry_path
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
        config_req.query_string = None
        config_resp = ObjectController(
            self.app,
            self.account_name,
            cont,
            obj).GET(config_req)
        if config_resp.status_int == 200:
            req.template = ''
            for chunk in config_resp.app_iter:
                req.template += chunk
                if self.middleware.zerovm_maxconfig < len(req.template):
                    req.template = None
                    return HTTPRequestEntityTooLarge(
                        request=config_req,
                        body='Config file at %s is too large' % config_path)
        if memcache_client and req.template:
            memcache_client.set(
                memcache_key,
                req.template,
                time=float(self.middleware.zerovm_cache_config_timeout))

    @delay_denial
    @cors_validation
    def GET(self, req):
        resp = self.handle_request(req)
        if resp:
            return resp
        obj_req = req.copy_get()
        obj_req.method = 'HEAD'
        obj_req.query_string = None
        run = False
        if self.object_name[-len('.nexe'):] == '.nexe':
            # let's get a small speedup as it's quite possibly an executable
            obj_req.method = 'GET'
            run = True
        controller = ObjectController(
            self.app,
            self.account_name,
            self.container_name,
            self.object_name)
        handler = getattr(controller, obj_req.method, None)
        obj_resp = handler(obj_req)
        if not is_success(obj_resp.status_int):
            return obj_resp
        content = obj_resp.content_type
        if content == 'application/x-nexe':
            run = True
        elif run:
            # speedup did not succeed...
            # still need to read the whole response
            for _junk in obj_resp.app_iter:
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
                                body='No application registered for %s'
                                     % content)
        location = SwiftPath.init(self.account_name,
                                  self.container_name,
                                  self.object_name)
        self.cluster_config = _config_from_template(req.params, template,
                                                    location.url)
        self.cgi_env = self.create_cgi_env(req)
        post_req = Request.blank('/%s' % self.account_name,
                                 environ=req.environ,
                                 headers=req.headers)
        post_req.method = 'POST'
        post_req.content_type = 'application/json'
        post_req.query_string = req.query_string
        if obj_req.method in 'GET':
            self.exe_resp = obj_resp
        return self.post_job(post_req)

    @delay_denial
    @cors_validation
    def POST(self, req):
        resp = self.handle_request(req)
        if resp:
            return resp
        return HTTPNotImplemented(request=req)

    @delay_denial
    @cors_validation
    def PUT(self, req):
        resp = self.handle_request(req)
        if resp:
            return resp
        return HTTPNotImplemented(request=req)

    @delay_denial
    @cors_validation
    def DELETE(self, req):
        resp = self.handle_request(req)
        if resp:
            return resp
        return HTTPNotImplemented(request=req)

    @delay_denial
    @cors_validation
    def HEAD(self, req):
        resp = self.handle_request(req)
        if resp:
            return resp
        return HTTPNotImplemented(request=req)

    def load_config(self, req, config_path):
        memcache_client = cache_from_env(req.environ)
        memcache_key = 'zvmapp' + config_path
        if memcache_client:
            config = memcache_client.get(memcache_key)
            if config:
                self.cluster_config = config
                return None
        config_req = req.copy_get()
        config_req.query_string = None
        buffer_length = self.middleware.zerovm_maxconfig * 2
        config_req.range = 'bytes=0-%d' % (buffer_length - 1)
        config_resp = ObjectController(
            self.app,
            self.account_name,
            self.container_name,
            self.object_name).GET(config_req)
        if config_resp.status_int == HTTP_REQUESTED_RANGE_NOT_SATISFIABLE:
            return None
        if not is_success(config_resp.status_int) or \
                config_resp.content_length > buffer_length:
            return config_resp
        if config_resp.content_type in TAR_MIMES + ['application/x-gzip']:
            chunk_size = self.middleware.network_chunk_size
            config_req.bytes_transferred = 0
            self.read_system_map(config_resp.app_iter, chunk_size,
                                 config_resp.content_type, config_req)
            if memcache_client and self.cluster_config:
                memcache_client.set(
                    memcache_key,
                    self.cluster_config,
                    time=float(self.middleware.zerovm_cache_config_timeout))
        return None

    def handle_request(self, req):
        swift_path = SwiftPath.init(self.account_name, self.container_name,
                                    self.object_name)
        error = self.load_config(req, swift_path.path)
        if error:
            return error
        # if we successfully got config, we know that we have a zapp in hand
        if self.cluster_config:
            self.cgi_env = self.create_cgi_env(req)
            req.headers['x-zerovm-source'] = swift_path.url
            req.method = 'POST'
            return self.post_job(req)
        return None


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
        if k == 'object_path':
            continue
        ptrn = r'\{\.%s(|=[^\}]+)\}'
        ptrn = ptrn % k
        template = re.sub(ptrn, v, template)
    config = template.replace('{.object_path}', url)
    config = re.sub(r'\{\.[^=\}]+=?([^\}]*)\}', '\\1', config)
    return config


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
        name = conn['dev']
        if name == 'image' and data_src.content_type == 'application/x-gzip':
            name = 'image.gz'
        info = conn['conn'].tar_stream.create_tarinfo(
            ftype=REGTYPE,
            name=name,
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


def gunzip_iter(data_iter, chunk_size):
    dec = zlib.decompressobj(16 + zlib.MAX_WBITS)
    unc_data = ''
    for chunk in data_iter:
        while dec.unconsumed_tail:
            while len(unc_data) < chunk_size and dec.unconsumed_tail:
                unc_data += dec.decompress(dec.unconsumed_tail,
                                           chunk_size - len(unc_data))
            if len(unc_data) == chunk_size:
                yield unc_data
                unc_data = ''
            if unc_data and dec.unconsumed_tail:
                chunk += dec.unconsumed_tail
                break
        unc_data += dec.decompress(chunk, chunk_size - len(unc_data))
        if len(unc_data) == chunk_size:
            yield unc_data
            unc_data = ''
    if unc_data:
        yield unc_data


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def query_filter(app):
        return ProxyQueryMiddleware(app, conf)

    return query_filter
