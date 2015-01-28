from __future__ import with_statement
from StringIO import StringIO
import json
import logging
import re
import struct
from eventlet.green import socket
import tarfile
import datetime
import random
from urllib import urlencode
import mock
import sys
import swift

import unittest
import os
import cPickle as pickle
from time import time
from swift.common.middleware import proxy_logging
from swift.common.memcached import MemcacheConnectionError
from swift.common.swob import Request, HTTPUnauthorized, HTTPForbidden
from hashlib import md5
from tempfile import mkstemp, mkdtemp
from shutil import rmtree

from eventlet import sleep, spawn, wsgi, listen, GreenPool
from gzip import GzipFile
from contextlib import contextmanager

from swift.proxy import server as proxy_server
from swift.account import server as account_server
from swift.container import server as container_server
from swift.obj import server as object_server
from swift.common.utils import mkdirs, normalize_timestamp, NullLogger, \
    hash_path
from swift.common import utils
from swift.common import storage_policy
from swift.common.storage_policy import StoragePolicy, \
    StoragePolicyCollection, POLICIES

from zerocloud import proxyquery, objectquery, chain
from test.unit import connect_tcp, readuntil2crlfs, fake_http_connect, trim, \
    debug_logger, FakeMemcache, write_fake_ring, FakeRing
from zerocloud.common import CLUSTER_CONFIG_FILENAME
from zerocloud.common import NODE_CONFIG_FILENAME
from zerocloud.common import SwiftPath
from zerocloud.configparser import ClusterConfigParser, \
    ClusterConfigParsingError


ZEROVM_DEFAULT_MOCK = 'test/unit/zerovm_mock.py'

logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

STATIC_TIME = time()
_test_coros = _test_servers = _test_sockets = _orig_container_listing_limit = \
    _testdir = _orig_SysLogHandler = _orig_POLICIES = _test_POLICIES = None
_pqm = None


class FakeMemcacheReturnsNone(FakeMemcache):

    def get(self, key):
        # Returns None as the timestamp of the container; assumes we're only
        # using the FakeMemcache for container existence checks.
        return None


class FakeMemcache(object):

    def __init__(self):
        self.store = {}
        self.error_on_incr = False
        self.init_incr_return_neg = False
        self.call = {'get': 0, 'set': 0}

    def get(self, key):
        self.call['get'] += 1
        return self.store.get(key)

    def set(self, key, value, serialize=False, time=0):
        self.call['set'] += 1
        self.store[key] = value
        return True

    def incr(self, key, delta=1, time=0):
        if self.error_on_incr:
            raise MemcacheConnectionError('Memcache restarting')
        if self.init_incr_return_neg:
            # simulate initial hit, force reset of memcache
            self.init_incr_return_neg = False
            return -10000000
        self.store[key] = int(self.store.setdefault(key, 0)) + int(delta)
        if self.store[key] < 0:
            self.store[key] = 0
        return int(self.store[key])

    def decr(self, key, delta=1, time=0):
        return self.incr(key, delta=-delta, time=time)

    @contextmanager
    def soft_lock(self, key, timeout=0, retries=5):
        yield True

    def delete(self, key):
        try:
            del self.store[key]
        except Exception:
            pass
        return True


class Utils(object):

    def create_container(self, prolis, url, auto_account=False):
        sock = connect_tcp(('localhost', prolis.getsockname()[1]))
        fd = sock.makefile()
        fd.write('PUT %s HTTP/1.1\r\nHost: localhost\r\n'
                 'Connection: close\r\nX-Storage-Token: t\r\n'
                 'Content-Length: 0\r\n'
                 '\r\n' % url)
        fd.flush()
        headers = readuntil2crlfs(fd)
        exp1 = 'HTTP/1.1 201'
        exp2 = 'HTTP/1.1 202'
        status = headers[:len(exp1)]
        self.assert_(exp1 in status or exp2 in status)

    def create_object(self, prolis, url, obj,
                      content_type='application/octet-stream'):
        sock = connect_tcp(('localhost', prolis.getsockname()[1]))
        fd = sock.makefile()
        fd.write('PUT %s HTTP/1.1\r\n'
                 'Host: localhost\r\n'
                 'Connection: close\r\n'
                 'X-Storage-Token: t\r\n'
                 'Content-Length: %s\r\n'
                 'Content-Type: %s\r\n'
                 '\r\n%s' % (url, str(len(obj)),  content_type, obj))
        fd.flush()
        headers = readuntil2crlfs(fd)
        exp = 'HTTP/1.1 201'
        self.assertEqual(headers[:len(exp)], exp)

    def get_random_numbers(self, min_num=0, max_num=10, proto='pickle'):
        numlist = [i for i in range(min_num, max_num)]
        count = max_num - min_num
        if count < 0:
            raise
        for i in range(count):
            randindex1 = random.randrange(count)
            randindex2 = random.randrange(count)
            numlist[randindex1], numlist[randindex2] =\
                numlist[randindex2], numlist[randindex1]
        if proto == 'binary':
            return struct.pack('%sI' % len(numlist), *numlist)
        else:
            return pickle.dumps(numlist, protocol=0)

    def get_sorted_numbers(self, min_num=0, max_num=10, proto='pickle'):
        numlist = [i for i in range(min_num, max_num)]
        if proto == 'binary':
            return struct.pack('%sI' % len(numlist), *numlist)
        else:
            return pickle.dumps(numlist, protocol=0)

    def authorize(self, req):
        _junk, account, container, obj = req.split_path(1, 4, True)
        perm = 'Denied'
        if not req.remote_user:
            who = 'Anonymous'
            if req.acl == '.r:*':
                perm = 'Allowed'
        elif req.remote_user == self.users[account]:
            who = 'Owner'
            perm = 'Allowed'
        else:
            who = req.remote_user
            if req.acl == req.remote_user:
                perm = 'Allowed'
        what = SwiftPath.create_url(account, container, obj)
        ver = req.headers.get('x-zerovm-execute', 'v1')
        self.actions.append('%s %s to %s %s with %s' % (perm, who, req.method,
                                                        what, ver))
        if perm == 'Denied':
            return HTTPForbidden(request=req)

    def setup_QUERY(self, mock=None):

        def set_zerovm_mock():

            (_prosrv, _acc1srv, _acc2srv, _con1srv,
             _con2srv, _obj1srv, _obj2srv) = _test_servers
            zerovm_mock = ZEROVM_DEFAULT_MOCK
            if mock:
                fd, zerovm_mock = mkstemp()
                os.write(fd, mock)
                os.close(fd)
                self.zerovm_mock = zerovm_mock
            _obj1srv.zerovm_exename = ['python', zerovm_mock]
            _obj2srv.zerovm_exename = ['python', zerovm_mock]
            _con1srv.zerovm_exename = ['python', zerovm_mock]
            _con2srv.zerovm_exename = ['python', zerovm_mock]

        self._randomnumbers = self.get_random_numbers()
        self._nexescript = ('return pickle.dumps(sorted(id))')
        self._nexescript_etag = md5()
        self._nexescript_etag.update(self._nexescript)
        self._nexescript_etag = self._nexescript_etag.hexdigest()
        set_zerovm_mock()

        (prolis, acc1lis, acc2lis, con1lis, con2lis, obj1lis, obj2lis) = \
            _test_sockets
        self.create_container(prolis, '/v1/a/c')
        self.create_container(prolis, '/v1/a/c_in1')
        self.create_container(prolis, '/v1/a/c_in2')
        self.create_container(prolis, '/v1/a/c_out1')
        self.create_container(prolis, '/v1/a/c_out2')
        self.create_container(prolis, '/v1/a/auth')
        self.create_container(prolis, '/v1/a/auth1')
        self.create_container(prolis, '/v1/a1/auth')
        self.create_container(prolis, '/v1/a1/auth1')
        self.create_object(prolis, '/v1/a/c/o', self._randomnumbers)
        self.create_object(prolis, '/v1/a/c/exe', self._nexescript)

        self.create_object(prolis, '/v1/a/c_in1/input1',
                           self.get_random_numbers(0, 10))
        self.create_object(prolis, '/v1/a/c_in1/input2',
                           self.get_random_numbers(10, 20))
        self.create_object(prolis, '/v1/a/c_in1/junk', 'junk')
        self.create_object(prolis, '/v1/a/c_in2/input1',
                           self.get_random_numbers(20, 30))
        self.create_object(prolis, '/v1/a/c_in2/input2',
                           self.get_random_numbers(30, 40))
        self.create_object(prolis, '/v1/a/c_in2/junk', 'junk')
        self.create_container(prolis, '/v1/userstats/a')

    def zerovm_request(self, user=None):
        req = Request.blank('/v1/a',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/json',
                                     'x-zerovm-execute': '1.0'})
        if user:
            self.add_auth_data(req, user)
        return req

    def zerovm_tar_request(self, user=None):
        req = Request.blank('/v1/a',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/x-gtar',
                                     'x-zerovm-execute': '1.0'})
        if user:
            self.add_auth_data(req, user)
        return req

    def object_request(self, path):
        req = Request.blank(path,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={
                                'Content-Type': 'application/octet-stream'})
        return req

    @contextmanager
    def create_tar(self, filelist):
        tarfd, tarname = mkstemp()
        os.close(tarfd)
        tar = tarfile.open(name=tarname, mode='w')
        sysmap = None
        for name, fd in filelist.iteritems():
            if name in [CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME]:
                info = tarfile.TarInfo(name)
                fd.seek(0, os.SEEK_END)
                size = fd.tell()
                info.size = size
                fd.seek(0, os.SEEK_SET)
                tar.addfile(info, fd)
                sysmap = name
                break
        if sysmap:
            del filelist[sysmap]
        for name, fd in filelist.iteritems():
            info = tarfile.TarInfo(name)
            fd.seek(0, os.SEEK_END)
            size = fd.tell()
            info.size = size
            fd.seek(0, os.SEEK_SET)
            tar.addfile(info, fd)
        tar.close()
        try:
            yield tarname
        finally:
            try:
                os.unlink(tarname)
            except OSError:
                pass

    @contextmanager
    def create_gzip(self, fname):
        gzfd, gzname = mkstemp()
        os.close(gzfd)
        gz = GzipFile(gzname, mode='wb')
        fd = open(fname, 'rb')
        gz.write(fd.read())
        gz.close()
        try:
            yield gzname
        finally:
            try:
                os.unlink(gzname)
            except OSError:
                pass

    @contextmanager
    def add_sysimage_device(self, sysimage_path, name='sysimage1'):
        _con1srv = _test_servers[3]
        _con2srv = _test_servers[4]
        _obj1srv = _test_servers[5]
        _obj2srv = _test_servers[6]
        zerovm_sysimage_devices = _pqm.zerovm_sysimage_devices
        zerovm_sysimage_devices1 = _obj1srv.parser.sysimage_devices
        zerovm_sysimage_devices2 = _obj2srv.parser.sysimage_devices
        zerovm_sysimage_devices3 = _con1srv.parser.sysimage_devices
        zerovm_sysimage_devices4 = _con2srv.parser.sysimage_devices
        _pqm.zerovm_sysimage_devices = {name: None}
        _con1srv.parser.sysimage_devices = {name: sysimage_path}
        _con2srv.parser.sysimage_devices = {name: sysimage_path}
        _obj1srv.parser.sysimage_devices = {name: sysimage_path}
        _obj2srv.parser.sysimage_devices = {name: sysimage_path}
        try:
            yield True
        finally:
            _pqm.zerovm_sysimage_devices = zerovm_sysimage_devices
            _obj1srv.parser.sysimage_devices = zerovm_sysimage_devices1
            _obj2srv.parser.sysimage_devices = zerovm_sysimage_devices2
            _con1srv.parser.sysimage_devices = zerovm_sysimage_devices3
            _con2srv.parser.sysimage_devices = zerovm_sysimage_devices4
            try:
                os.unlink(sysimage_path)
            except IOError:
                pass

    def executed_successfully(self, response):
        self.assertEqual(response.status_int, 200)
        for status in response.headers['x-nexe-status'].split(','):
            self.assertEqual(status, 'ok.')
        self.assertNotIn('x-nexe-error', response.headers)

    def check_container_integrity(self, srv, url, objdict):
        req = Request.blank('%s?format=json' % url)
        res = req.get_response(srv)
        filelist = json.loads(res.body)
        for f in filelist:
            req = self.object_request('%s/%s' % (url, f['name']))
            res = req.get_response(srv)
            self.assertEqual(res.status_int, 200)
            obj = objdict.get(f['name'])
            if obj:
                self.assertEqual(res.body, obj)
                del objdict[f['name']]
            file_ts = float(res.headers['x-timestamp'])
            file_ts = datetime.datetime.utcfromtimestamp(file_ts)
            file_ts = file_ts.strftime('%Y-%m-%dT%H:%M:%S.%f')
            cont_ts = f['last_modified']
            self.assertEqual(file_ts, cont_ts)
            self.assertEqual(str(f['bytes']), res.headers['content-length'])
            self.assertEqual(f['hash'], res.headers['etag'])
            if res.app_iter:
                for _ in res.app_iter:
                    pass
        self.assertEqual(len(objdict), 0)

    def add_auth_data(self, req, user):
        req.environ['swift.authorize'] = self.authorize
        # if user == 'anon':
        if user == 'Anonymous':
            req.remote_user = None
        else:
            req.remote_user = user


def do_setup(the_object_server):
    utils.HASH_PATH_SUFFIX = 'endcap'
    global _testdir, _test_servers, _test_sockets, \
        _orig_container_listing_limit, _test_coros, _orig_SysLogHandler, \
        _orig_POLICIES, _test_POLICIES, _pqm
    _orig_POLICIES = storage_policy._POLICIES
    _orig_SysLogHandler = utils.SysLogHandler
    utils.SysLogHandler = mock.MagicMock()
    # Since we're starting up a lot here, we're going to test more than
    # just chunked puts; we're also going to test parts of
    # proxy_server.Application we couldn't get to easily otherwise.
    _testdir = \
        os.path.join(mkdtemp(), 'tmp_test_proxy_server_chunked')
    mkdirs(_testdir)
    rmtree(_testdir)
    mkdirs(os.path.join(_testdir, 'sda1'))
    mkdirs(os.path.join(_testdir, 'sda1', 'tmp'))
    mkdirs(os.path.join(_testdir, 'sdb1'))
    mkdirs(os.path.join(_testdir, 'sdb1', 'tmp'))
    conf = {'devices': _testdir, 'swift_dir': _testdir,
            'mount_check': 'false',
            'allowed_headers': 'content-encoding, x-object-manifest, '
                               'content-disposition, foo',
            'disable_fallocate': 'true',
            'allow_versions': 'True',
            'zerovm_maxoutput': 1024 * 1024 * 10}
    prolis = listen(('localhost', 0))
    acc1lis = listen(('localhost', 0))
    acc2lis = listen(('localhost', 0))
    con1lis = listen(('localhost', 0))
    con2lis = listen(('localhost', 0))
    obj1lis = listen(('localhost', 0))
    obj2lis = listen(('localhost', 0))
    _test_sockets = \
        (prolis, acc1lis, acc2lis, con1lis, con2lis, obj1lis, obj2lis)
    account_ring_path = os.path.join(_testdir, 'account.ring.gz')
    account_devs = [
        {'port': acc1lis.getsockname()[1]},
        {'port': acc2lis.getsockname()[1]},
    ]
    write_fake_ring(account_ring_path, *account_devs)
    container_ring_path = os.path.join(_testdir, 'container.ring.gz')
    container_devs = [
        {'port': con1lis.getsockname()[1]},
        {'port': con2lis.getsockname()[1]},
    ]
    write_fake_ring(container_ring_path, *container_devs)
    storage_policy._POLICIES = StoragePolicyCollection([
        StoragePolicy(0, 'zero', True),
        StoragePolicy(1, 'one', False),
        StoragePolicy(2, 'two', False)])
    obj_rings = {
        0: ('sda1', 'sdb1'),
        1: ('sdc1', 'sdd1'),
        2: ('sde1', 'sdf1'),
    }
    for policy_index, devices in obj_rings.items():
        policy = POLICIES[policy_index]
        dev1, dev2 = devices
        obj_ring_path = os.path.join(_testdir, policy.ring_name + '.ring.gz')
        obj_devs = [
            {'port': obj1lis.getsockname()[1], 'device': dev1},
            {'port': obj2lis.getsockname()[1], 'device': dev2},
        ]
        write_fake_ring(obj_ring_path, *obj_devs)
    prosrv = proxy_server.Application(conf, FakeMemcacheReturnsNone(),
                                      logger=debug_logger('proxy'))
    for policy in POLICIES:
        # make sure all the rings are loaded
        prosrv.get_object_ring(policy.idx)
    # don't loose this one!
    _test_POLICIES = storage_policy._POLICIES
    acc1srv = account_server.AccountController(
        conf, logger=debug_logger('acct1'))
    acc2srv = account_server.AccountController(
        conf, logger=debug_logger('acct2'))
    con1srv = container_server.ContainerController(
        conf, logger=debug_logger('cont1'))
    con2srv = container_server.ContainerController(
        conf, logger=debug_logger('cont2'))
    obj1srv = the_object_server.ObjectController(
        conf, logger=debug_logger('obj1'))
    obj2srv = the_object_server.ObjectController(
        conf, logger=debug_logger('obj2'))
    pqm = proxyquery.ProxyQueryMiddleware(prosrv, conf,
                                          logger=prosrv.logger)
    cmdlwr = chain.ChainMiddleware(pqm, conf, logger=prosrv.logger)
    nl = NullLogger()
    logging_prosv = proxy_logging.ProxyLoggingMiddleware(cmdlwr, conf,
                                                         logger=prosrv.logger)
    prospa = spawn(wsgi.server, prolis, logging_prosv, nl)
    acc1spa = spawn(wsgi.server, acc1lis, acc1srv, nl)
    acc2spa = spawn(wsgi.server, acc2lis, acc2srv, nl)
    cqm1 = objectquery.ObjectQueryMiddleware(con1srv, conf,
                                             logger=con1srv.logger)
    cqm2 = objectquery.ObjectQueryMiddleware(con2srv, conf,
                                             logger=con2srv.logger)
    con1spa = spawn(wsgi.server, con1lis, cqm1, nl)
    con2spa = spawn(wsgi.server, con2lis, cqm2, nl)
    oqm1 = objectquery.ObjectQueryMiddleware(obj1srv, conf,
                                             logger=obj1srv.logger)
    oqm2 = objectquery.ObjectQueryMiddleware(obj2srv, conf,
                                             logger=obj2srv.logger)
    obj1spa = spawn(wsgi.server, obj1lis, oqm1, nl)
    obj2spa = spawn(wsgi.server, obj2lis, oqm2, nl)
    _test_servers = \
        (logging_prosv, acc1srv, acc2srv, cqm1, cqm2, oqm1, oqm2)
    _test_coros = \
        (prospa, acc1spa, acc2spa, con1spa, con2spa, obj1spa, obj2spa)
    _pqm = pqm
    # Create accounts
    ts = normalize_timestamp(time())
    partition, nodes = prosrv.account_ring.get_nodes('a')
    for node in nodes:
        conn = swift.proxy.controllers.obj.http_connect(node['ip'],
                                                        node['port'],
                                                        node['device'],
                                                        partition, 'PUT', '/a',
                                                        {'X-Timestamp': ts,
                                                         'x-trans-id': 'test'})
        resp = conn.getresponse()
        assert(resp.status == 201)
    ts = normalize_timestamp(time())
    partition, nodes = prosrv.account_ring.get_nodes('a1')
    for node in nodes:
        conn = swift.proxy.controllers.obj.http_connect(node['ip'],
                                                        node['port'],
                                                        node['device'],
                                                        partition, 'PUT',
                                                        '/a1',
                                                        {'X-Timestamp': ts,
                                                         'x-trans-id': 'test'})
        resp = conn.getresponse()
        assert(resp.status == 201)
    # Create stats account
    ts = normalize_timestamp(time())
    partition, nodes = prosrv.account_ring.get_nodes('userstats')
    for node in nodes:
        conn = swift.proxy.controllers.obj.http_connect(node['ip'],
                                                        node['port'],
                                                        node['device'],
                                                        partition, 'PUT',
                                                        '/userstats',
                                                        {'X-Timestamp': ts,
                                                         'x-trans-id': 'test'})
        resp = conn.getresponse()
        assert(resp.status == 201)
    # Create containers, 1 per test policy
    sock = connect_tcp(('localhost', prolis.getsockname()[1]))
    fd = sock.makefile()
    fd.write('PUT /v1/a/c HTTP/1.1\r\nHost: localhost\r\n'
             'Connection: close\r\nX-Auth-Token: t\r\n'
             'Content-Length: 0\r\n\r\n')
    fd.flush()
    headers = readuntil2crlfs(fd)
    exp = 'HTTP/1.1 201'
    assert headers[:len(exp)] == exp, "Expected '%s', encountered '%s'" % (
        exp, headers[:len(exp)])

    sock = connect_tcp(('localhost', prolis.getsockname()[1]))
    fd = sock.makefile()
    fd.write(
        'PUT /v1/a/c1 HTTP/1.1\r\nHost: localhost\r\n'
        'Connection: close\r\nX-Auth-Token: t\r\nX-Storage-Policy: one\r\n'
        'Content-Length: 0\r\n\r\n')
    fd.flush()
    headers = readuntil2crlfs(fd)
    exp = 'HTTP/1.1 201'
    assert headers[:len(exp)] == exp, \
        "Expected '%s', encountered '%s'" % (exp, headers[:len(exp)])

    sock = connect_tcp(('localhost', prolis.getsockname()[1]))
    fd = sock.makefile()
    fd.write(
        'PUT /v1/a/c2 HTTP/1.1\r\nHost: localhost\r\n'
        'Connection: close\r\nX-Auth-Token: t\r\nX-Storage-Policy: two\r\n'
        'Content-Length: 0\r\n\r\n')
    fd.flush()
    headers = readuntil2crlfs(fd)
    exp = 'HTTP/1.1 201'
    assert headers[:len(exp)] == exp, \
        "Expected '%s', encountered '%s'" % (exp, headers[:len(exp)])


def setup():
    do_setup(object_server)


def teardown():
    for server in _test_coros:
        server.kill()
    rmtree(os.path.dirname(_testdir))
    utils.SysLogHandler = _orig_SysLogHandler
    storage_policy._POLICIES = _orig_POLICIES


@contextmanager
def save_globals():
    orig_http_connect = getattr(
        swift.proxy.controllers.base, 'http_connect', None)
    orig_query_connect = getattr(proxyquery, 'http_connect', None)
    orig_account_info = getattr(
        proxy_server.ObjectController, 'account_info', None)
    try:
        yield True
    finally:
        proxy_server.http_connect = orig_http_connect
        swift.proxy.controllers.base.http_connect = orig_http_connect
        swift.proxy.controllers.obj.http_connect = orig_http_connect
        swift.proxy.controllers.account.http_connect = orig_http_connect
        swift.proxy.controllers.container.http_connect = orig_http_connect
        proxy_server.ObjectController.account_info = orig_account_info
        proxyquery.http_connect = orig_query_connect


class TestProxyQuery(unittest.TestCase, Utils):

    def setUp(self):
        self.proxy_app = \
            proxy_server.Application(None, FakeMemcache(),
                                     logger=debug_logger('proxy-ut'),
                                     account_ring=FakeRing(),
                                     container_ring=FakeRing())
        self.pqm = proxyquery.ProxyQueryMiddleware(
            self.proxy_app, {},
            logger=self.proxy_app.logger,
            object_ring=FakeRing(),
            container_ring=FakeRing())

        self.zerovm_mock = None
        self.users = {'a': 'user', 'a1': 'user1'}

    def tearDown(self):
        if self.zerovm_mock:
            os.unlink(self.zerovm_mock)

    def test_QUERY_name_service(self):
        peers = 3
        ns_server = proxyquery.NameService(peers)
        pool = GreenPool()
        ns_server.start(pool)
        connection_map = {}
        sleep(0.1)

        def mock_client(ns_port, conf, id):
            bind_data = ''
            connect_data = ''
            bind_map = {}
            connect_list = []
            for h in conf[0]:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(('', 0))
                s.listen(1)
                port = s.getsockname()[1]
                bind_map[h] = {'port': port, 'sock': s}
                bind_data += struct.pack('!IH', h, int(port))
                connection_map['%d->%d' % (h, id)] = int(port)
            for h in conf[1]:
                connect_list.append(h)
                connect_data += struct.pack('!IH', h, 0)
            request = struct.pack('!I', id) + \
                struct.pack('!I', len(conf[0])) + \
                struct.pack('!I', len(conf[1])) + \
                bind_data + connect_data
            ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ns.connect(('localhost', int(ns_port)))
            ns.send(request)
            ns_host = ns.getpeername()[0]
            ns_port = ns.getpeername()[1]
            while 1:
                reply, addr = ns.recvfrom(65535)
                if addr[0] == ns_host and addr[1] == ns_port:
                    offset = 0
                    my_id = struct.unpack_from('!I', reply, offset)[0]
                    self.assertEqual(id, my_id)
                    offset += 4
                    bind_count = struct.unpack_from('!I', reply, offset)[0]
                    offset += 4
                    self.assertEqual(bind_count, len(conf[0]))
                    connect_count = struct.unpack_from('!I', reply, offset)[0]
                    offset += 4
                    self.assertEqual(connect_count, len(conf[1]))
                    offset += len(bind_data)
                    for i in range(connect_count):
                        host, port = struct.unpack_from(
                            '!4sH', reply, offset)[0:2]
                        offset += 6
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect(
                            (socket.inet_ntop(socket.AF_INET, host), port))
                        self.assertEqual(
                            connection_map['%d->%d' % (id, connect_list[i])],
                            port
                        )
                    break
            sleep(0.2)

        dev1 = [[2, 3], [2, 3]]
        dev2 = [[1, 3], [1, 3]]
        dev3 = [[2, 1], [2, 1]]
        th1 = pool.spawn(mock_client, ns_server.port, dev1, 1)
        th2 = pool.spawn(mock_client, ns_server.port, dev2, 2)
        th3 = pool.spawn(mock_client, ns_server.port, dev3, 3)
        th1.wait()
        th2.wait()
        th3.wait()
        ns_server.stop()

    def test_QUERY_sort_store_stdout(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout', 'path': 'swift://a/c/o2'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.check_container_integrity(prosrv,
                                           '/v1/a/c',
                                           {
                                               'o2': self.get_sorted_numbers()
                                           })

    def test_sort_store_stdout_policy(self):
        # store result under different policy
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout', 'path': 'swift://a/c1/o2'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.check_container_integrity(prosrv,
                                           '/v1/a/c1',
                                           {
                                               'o2': self.get_sorted_numbers()
                                           })
            self.assertEqual(res.headers['X-Nexe-Policy'], 'zero')
        # fetch executable from different policy
        self.create_object(prolis, '/v1/a/c1/exe', self._nexescript)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c1/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout', 'path': 'swift://a/c1/o2'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.check_container_integrity(prosrv,
                                           '/v1/a/c1',
                                           {
                                               'o2': self.get_sorted_numbers()
                                           })
            self.assertEqual(res.headers['X-Nexe-Policy'], 'zero')
        # query object from different policy
        self.create_object(prolis, '/v1/a/c1/o', self._randomnumbers)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c1/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c1/o'},
                    {'device': 'stdout', 'path': 'swift://a/c/o3'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.check_container_integrity(prosrv,
                                           '/v1/a/c',
                                           {
                                               'o3': self.get_sorted_numbers()
                                           })
            # is executed under different policy now
            self.assertEqual(res.headers['X-Nexe-Policy'], 'one')

    def test_gzipped_tar(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout', 'path': 'swift://a/c/o2'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_tar_request()
        req.headers['content-type'] = 'application/x-gzip'
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            with self.create_gzip(tar) as gzname:
                req.body_file = open(gzname, 'rb')
                req.content_length = os.path.getsize(gzname)
                res = req.get_response(prosrv)
                self.executed_successfully(res)
                self.check_container_integrity(
                    prosrv,
                    '/v1/a/c',
                    {'o2': self.get_sorted_numbers()}
                )

    def test_QUERY_sort_store_stdout_stderr(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout', 'path': 'swift://a/c/o2'},
                    {'device': 'stderr', 'path': 'swift://a/c/o3'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['x-nexe-status'], 'ok.')
        self.assertEqual(res.headers['x-nexe-system'], 'sort')
        self.assertEqual(res.headers['x-nexe-retcode'], '0')
        self.check_container_integrity(prosrv,
                                       '/v1/a/c',
                                       {
                                           'o2': self.get_sorted_numbers(),
                                           'o3': '\nfinished\n'
                                       })

    def test_QUERY_immediate_stdout(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.content_type, 'text/html')
        self.assertEqual(res.body, self.get_sorted_numbers())
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout',
                        'content_type': 'application/x-pickle'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.content_type, 'application/x-pickle')
        self.assertEqual(res.body, self.get_sorted_numbers())
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_QUERY_store_meta(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return 'Test Test'
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout', 'content_type': 'text/plain',
                        'meta': {'key1': 'test1', 'key2': 'test2'},
                        'path': 'swift://a/c/o3'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['content-type'], 'text/plain')
        self.assertEqual(res.headers['x-object-meta-key1'], 'test1')
        self.assertEqual(res.headers['x-object-meta-key2'], 'test2')
        self.assertEqual(res.body, 'Test Test')
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_QUERY_hello(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return 'hello, world'
            ''')
        self.create_object(prolis, '/v1/a/c/hello.nexe', nexe)
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/c/hello.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_hello_with_policy(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return 'hello, world'
            ''')
        self.create_object(prolis, '/v1/a/c/hello.nexe', nexe)
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/c/hello.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        self.check_container_integrity(prosrv, '/v1/a/c', {})
        self.assertEqual(res.headers['X-Nexe-Policy'], 'zero')
        _orig_policies = _pqm.standalone_policies
        try:
            _pqm.standalone_policies = [1]
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, 'hello, world')
            self.check_container_integrity(prosrv, '/v1/a/c', {})
            self.assertEqual(res.headers['X-Nexe-Policy'], 'one')
        finally:
            _pqm.standalone_policies = _orig_policies

    def test_QUERY_hello_stderr(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return 'hello, world'
            ''')
        self.create_object(prolis, '/v1/a/c/hello.nexe', nexe)
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/c/hello.nexe"},
                "file_list": [
                    {"device": "stderr",
                     "path": "swift://a/c/stderr.log"},
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_QUERY_relative_path(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return 'hello, world'
            ''')
        self.create_object(prolis, '/v1/a/c/hello.nexe', nexe)
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://./c/hello.nexe"},
                "file_list": [
                    {"device": "stderr",
                     "path": "swift://./c/stderr.log"},
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')

    def test_QUERY_cgi_response(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: text/html',
                'X-Object-Meta-Key1: value1',
                'X-Object-Meta-Key2: value2',
                '', ''
                ])
            out = '<html><body>Test this</body></html>'
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdout',
                     'content_type': 'message/http',
                     'path': 'swift://a/c/o3'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.executed_successfully(res)
        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.assertEqual(res.headers['x-object-meta-key1'], 'value1')
        self.assertEqual(res.headers['x-object-meta-key2'], 'value2')
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.assertEqual(res.headers['x-object-meta-key1'], 'value1')
        self.assertEqual(res.headers['x-object-meta-key2'], 'value2')
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_QUERY_cgi_environment(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return pickle.dumps(open(mnfst.nvram['path']).read())
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'application/x-pickle',
                        'path': 'swift://a/c/o3',
                        'meta': {'key1': 'val1', 'key2': 'val2'}
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['x-object-meta-key1'], 'val1')
        self.assertEqual(res.headers['x-object-meta-key2'], 'val2')
        self.assertEqual(res.headers['content-type'], 'application/x-pickle')
        out = pickle.loads(res.body)
        self.assertIn('name=LOCAL_CONTENT_TYPE, value=application/x-pickle',
                      out)
        self.assertIn('name=LOCAL_HTTP_X_OBJECT_META_KEY1, value=val1', out)
        self.assertIn('name=LOCAL_HTTP_X_OBJECT_META_KEY2, value=val2', out)
        self.assertIn('name=LOCAL_DOCUMENT_ROOT, value=/dev/stdout', out)
        self.assertIn('name=LOCAL_PATH_INFO, value=/a/c/o3', out)
        content_length = res.content_length
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'text/plain',
                    },
                    {
                        'device': 'stdin',
                        'path': 'swift://a/c/o3'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        req.query_string = 'param1=v1&param2=v2'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        out = pickle.loads(res.body)
        self.assertIn('name=LOCAL_CONTENT_TYPE, value=application/x-pickle',
                      out)
        self.assertIn('name=LOCAL_HTTP_X_OBJECT_META_KEY1, value=val1', out)
        self.assertIn('name=LOCAL_HTTP_X_OBJECT_META_KEY2, value=val2', out)
        self.assertIn('name=LOCAL_DOCUMENT_ROOT, value=/dev/stdin', out)
        self.assertIn('name=LOCAL_PATH_INFO, value=/a/c/o3', out)
        self.assertIn('name=LOCAL_CONTENT_LENGTH, value=%d' % content_length,
                      out)
        self.assertIn('name=SCRIPT_NAME, value=http', out)
        self.assertIn('name=SCRIPT_FILENAME, value=swift://a/c/exe2', out)
        self.assertIn('name=QUERY_STRING, value=%s' % req.query_string, out)
        self.check_container_integrity(prosrv, '/v1/a/c', {})
        conf = [
            {
                'name': 'http2',
                'exec': {
                    'path': 'swift://a/c/exe2',
                    'name': 'http_script'
                },
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'text/plain',
                    },
                    {
                        'device': 'stdin',
                        'path': 'swift://a/c/o3'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        out = pickle.loads(res.body)
        self.assertIn('name=LOCAL_CONTENT_TYPE, value=application/x-pickle',
                      out)
        self.assertIn('name=LOCAL_HTTP_X_OBJECT_META_KEY1, value=val1', out)
        self.assertIn('name=LOCAL_HTTP_X_OBJECT_META_KEY2, value=val2', out)
        self.assertIn('name=LOCAL_DOCUMENT_ROOT, value=/dev/stdin', out)
        self.assertIn('name=LOCAL_PATH_INFO, value=/a/c/o3', out)
        self.assertIn('name=LOCAL_CONTENT_LENGTH, value=%d' % content_length,
                      out)
        self.assertIn('name=SCRIPT_NAME, value=http_script', out)
        self.assertIn('name=SCRIPT_FILENAME, value=swift://a/c/exe2', out)
        self.check_container_integrity(prosrv, '/v1/a/c', {})
        req = self.zerovm_request()
        req.body = conf
        req.headers['x-auth-token'] = 't'
        req.headers['x-storage-token'] = 't'
        req.headers['cookie'] = 'secret'
        req.headers['x-backend-data'] = 'internal_data'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        out = pickle.loads(res.body)
        self.assertNotIn('name=HTTP_X_AUTH_TOKEN, value=t', out)
        self.assertNotIn('name=HTTP_X_STORAGE_TOKEN, value=t', out)
        self.assertNotIn('name=HTTP_COOKIE, value=secret', out)
        self.assertNotIn('name=HTTP_X_BACKEND_DATA, value=internal_data', out)

    def test_QUERY_GET_response(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            resp = '<html><body>Test this</body></html>'
            return resp
            ''')
        self.create_object(
            prolis, '/v1/a/c/exe2', nexe, content_type='application/x-nexe')
        req = self.object_request('/v1/a/c/exe2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, nexe)

        for ver in ['v1', 'open']:
            url = '/%s/a/c/exe2?' % ver
            req = Request.blank(
                url + urlencode({'content_type': 'text/html'}))
            if ver == 'v1':
                req.headers['x-zerovm-execute'] = 'open/1.0'
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, '<html><body>Test this</body></html>')
            self.assertEqual(res.headers['content-type'], 'text/html')

        self.create_object(
            prolis, '/v1/a/c/my.nexe', nexe, content_type='application/x-nexe')

        for ver in ['v1', 'open']:
            url = '/%s/a/c/my.nexe?' % ver
            req = Request.blank(
                url + urlencode({'content_type': 'text/html'}))
            if ver == 'v1':
                req.headers['x-zerovm-execute'] = 'open/1.0'
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, '<html><body>Test this</body></html>')
            self.assertEqual(res.headers['content-type'], 'text/html')

        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': '{.object_path}'},
                    {'device': 'stdout',
                        'content_type': 'application/x-pickle'}
                ]
            }
        ]
        conf = json.dumps(conf)
        self.create_container(prolis, '/v1/a/%s' %
                              self.pqm.zerovm_registry_path)
        self.create_object(prolis, '/v1/a/%s/%s'
                                   % (self.pqm.zerovm_registry_path,
                                      'application/octet-stream/config'),
                           conf, content_type='application/json')

        for ver in ['v1', 'open']:
            url = '/%s/a/c/o' % ver
            req = Request.blank(url)
            if ver == 'v1':
                req.headers['x-zerovm-execute'] = 'open/1.0'
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.headers['content-type'],
                             'application/x-pickle')
            self.assertEqual(res.body, self.get_sorted_numbers())
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_QUERY_use_image(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return [open(mnfst.image['path']).read(), sorted(id)]
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        image = 'This is image file'
        self.create_object(prolis, '/v1/a/c/img', image)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
                         str(['This is image file',
                              pickle.loads(self.get_sorted_numbers())]))

    def test_QUERY_use_node_attach(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return [open(mnfst.image['path']).read(), sorted(id)]
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        image = 'This is image file'
        self.create_object(prolis, '/v1/a/c/img', image)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ],
                'attach': 'stdin'
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
                         str(['This is image file',
                              pickle.loads(self.get_sorted_numbers())]))
        # Let's try to "attach" to a device that does not point to any object
        # Should succeed also, as only the session location will change
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ],
                'attach': 'image'
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
                         str(['This is image file',
                              pickle.loads(self.get_sorted_numbers())]))
        # Now try proper write-only object
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ],
                'attach': 'stdout'
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
                         str(['This is image file',
                              pickle.loads(self.get_sorted_numbers())]))
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout', 'path': 'swift://a/c/stdout.log'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ],
                'attach': 'stdout'
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        req = self.object_request('/v1/a/c/stdout.log')
        req.headers['x-newest'] = 'true'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
                         str(['This is image file',
                              pickle.loads(self.get_sorted_numbers())]))

    def test_QUERY_use_gzipped_image(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return [open(mnfst.image['path']).read(), sorted(id)]
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        image = 'This is image file'
        image_gz = StringIO('')
        gz = GzipFile(mode='wb', fileobj=image_gz)
        gz.write(image)
        gz.close()
        self.create_object(prolis, '/v1/a/c/img.gz', image_gz.getvalue(),
                           content_type='application/x-gzip')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img.gz'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
                         str(['This is image file',
                              pickle.loads(self.get_sorted_numbers())]))

    def test_QUERY_use_large_image(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return [open(mnfst.image['path']).read(), sorted(id)]
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        image = 'This is image file' * 10000
        self.create_object(prolis, '/v1/a/c/img', image)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
                         str(['This is image file' * 10000,
                              pickle.loads(self.get_sorted_numbers())]))

    def test_QUERY_use_sysimage(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        image = 'This is image file'
        sysimage_path = os.path.join(_testdir, 'sysimage.tar')

        nexe = trim(r'''
            return open(mnfst.nvram['path']).read() + \
                str(mnfst.channels['/dev/sysimage1']['type']) + ' ' + \
                str(mnfst.channels['/dev/sysimage1']['path'])
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        img = open(sysimage_path, 'wb')
        img.write(image)
        img.close()
        with self.add_sysimage_device(sysimage_path):
            conf = [
                {
                    'name': 'sort',
                    'exec': {
                        'path': 'swift://a/c/exe2'
                    },
                    'file_list': [
                        {'device': 'stdin', 'path': 'swift://a/c/o'},
                        {'device': 'stdout'},
                        {'device': 'sysimage1'}
                    ]
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertIn(
                '[fstab]\n'
                'channel=/dev/sysimage1, mountpoint=/, access=ro, '
                'removable=no\n'
                '[args]\n'
                'args = sort\n',
                res.body
            )
            self.assertIn('%d %s' % (3, sysimage_path),
                          res.body)

    def test_sysimage_and_script_device(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        image = 'This is image file'
        sysimage_path = os.path.join(_testdir, 'sysimage.tar')

        nexe = trim(r'''
            return open(mnfst.nvram['path']).read() + \
                str(mnfst.channels['/dev/sysimage1']['type']) + ' ' + \
                str(mnfst.channels['/dev/sysimage1']['path']) + '\n' + \
                str(mnfst.channels['/dev/script']['path']) + '\n' + \
                open(mnfst.channels['/dev/script']['path']).read()
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        self.create_object(prolis, '/v1/a/c/script', 'Test script')
        img = open(sysimage_path, 'wb')
        img.write(image)
        img.close()
        with self.add_sysimage_device(sysimage_path):
            conf = [
                {
                    'name': 'sort',
                    'exec': {
                        'path': 'swift://a/c/exe2'
                    },
                    'file_list': [
                        {'device': 'stdin', 'path': 'swift://a/c/o'},
                        {'device': 'stdout'},
                        {'device': 'sysimage1'},
                        {'device': 'script', 'path': 'swift://a/c/script'}
                    ]
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertIn('[fstab]\n'
                          'channel=/dev/sysimage1, mountpoint=/, '
                          'access=ro, removable=no\n'
                          '[args]\n'
                          'args = sort\n', res.body)
            self.assertIn('%d %s' % (3, sysimage_path),
                          res.body)
            self.assertIn('Test script', res.body)
            self.assert_(re.search('^%s/sd[ab]1/tmp/' % _testdir, res.body,
                                   flags=re.M))

    def test_QUERY_post_script_sysimage(self):
        self.setup_QUERY()
        prosrv = _test_servers[0]
        script = trim(r'''
            #! file://sysimage1:bin/sh
            print 'Test'
            ''')
        nexe = trim(r'''
            import tarfile
            tar = tarfile.open(mnfst.image['path'])
            members = tar.getmembers()
            names = tar.getnames()
            file = tar.extractfile(members[0])
            return names[0] + '\n' + file.read()
            ''')
        shell = StringIO(nexe)
        with self.create_tar({'bin/sh': shell}) as tar:
            with self.add_sysimage_device(tar):
                req = self.zerovm_request()
                req.body = script
                req.headers['content-type'] = 'application/x-shell'
                res = req.get_response(prosrv)
                self.assertEqual(res.status_int, 200)
                self.assertIn('script\n' + script, res.body)
                self.assertEqual(res.headers['x-nexe-retcode'], '0')
                self.assertEqual(res.headers['x-nexe-status'], 'ok.')

    def test_QUERY_post_script(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            import tarfile
            tar = tarfile.open(mnfst.image['path'])
            members = tar.getmembers()
            file = tar.extractfile(members[0])
            return file.read()
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        script = trim(r'''
            #! swift://a/c/exe2
            print 'Test'
            ''')
        req = self.zerovm_request()
        req.body = script
        req.headers['content-type'] = 'application/x-python'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn(script, res.body)
        script = trim(r'''
            #! swift://a/aaa/bbb
            print 'Test'
            ''')
        req.body = script
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 404)
        self.assertIn(' /a/aaa/bbb', res.body)
        script = trim(r'''
            #! aaa/bbb
            print 'Test'
            ''')
        req.body = script
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertIn(' aaa/bbb', res.body)

    def test_deferred(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        orig_timeout = _pqm.immediate_response_timeout
        _pqm.immediate_response_timeout = 0.5
        nexe = trim(r'''
            from time import sleep
            sleep(1)
            return 'slept'
            ''')
        self.create_object(prolis, '/v1/a/c/slow.nexe', nexe)
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': 'swift://a/c/slow.nexe'
                },
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        req.headers['x-zerovm-deferred'] = 'auto'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('swift://a/.zvm/', res.body)
        url = res.body.strip()
        from zerocloud.common import SwiftPath
        path = SwiftPath(url)
        req = self.object_request('/v1/%s/%s/%s' % (path.account,
                                                    path.container,
                                                    path.obj))
        sleep(0.1)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 404)
        sleep(1)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'slept')
        req = self.object_request('/v1/%s/%s/%s.headers' % (path.account,
                                                            path.container,
                                                            path.obj))
        res = req.get_response(prosrv)
        # print res.status
        self.assertEqual(res.status_int, 200)
        raised = 0
        try:
            json.loads(res.body)
        except Exception:
            raised += 1
        self.assertEqual(raised, 0)
        _pqm.immediate_response_timeout = orig_timeout

    def test_deferred_with_obj(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        orig_timeout = _pqm.immediate_response_timeout
        _pqm.immediate_response_timeout = 0.5
        nexe = trim(r'''
            from time import sleep
            sleep(1)
            return 'slept'
            ''')
        self.create_object(prolis, '/v1/a/c/slow.nexe', nexe)
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': 'swift://a/c/slow.nexe'
                },
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        req.path_info = '/v1/a/jobs/my_job'
        req.headers['x-zerovm-deferred'] = 'auto'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual('swift://a/jobs/my_job', res.body)
        url = res.body.strip()
        from zerocloud.common import SwiftPath
        path = SwiftPath(url)
        req = self.object_request('/v1/%s/%s/%s' % (path.account,
                                                    path.container,
                                                    path.obj))
        sleep(0.1)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 404)
        sleep(1)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'slept')
        req = self.object_request('/v1/%s/%s/%s.headers' % (path.account,
                                                            path.container,
                                                            path.obj))
        res = req.get_response(prosrv)
        # print res.status
        self.assertEqual(res.status_int, 200)
        raised = 0
        try:
            json.loads(res.body)
        except Exception:
            raised += 1
        self.assertEqual(raised, 0)
        _pqm.immediate_response_timeout = orig_timeout

    def test_QUERY_use_nvram(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return open(mnfst.nvram['path']).read()
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': 'swift://a/c/exe2'
                },
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('[args]\n'
                      'args = sort\n', res.body)
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': 'swift://a/c/exe2',
                    'args': 'aa bb cc'
                },
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('[args]\n'
                      'args = sort aa bb cc\n', res.body)
        image = 'This is image file'
        self.create_object(prolis, '/v1/a/c/img', image)
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': 'swift://a/c/exe2'
                },
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertIn(
            '[fstab]\n'
            'channel=/dev/image, mountpoint=/, access=ro, removable=no\n'
            '[args]\n'
            'args = sort\n',
            res.body
        )
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': 'swift://a/c/exe2',
                    'args': 'aa bb cc',
                    'env': {
                        'key1': 'val1',
                        'key2': 'val2'
                    }
                },
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertIn('[fstab]\n'
                      'channel=/dev/image, mountpoint=/, access=ro',
                      res.body)
        self.assertIn('[args]\n'
                      'args = sort aa bb cc',
                      res.body)
        self.assertIn('name=key1, value=val1',
                      res.body)
        self.assertIn('name=key2, value=val2',
                      res.body)

        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': 'swift://a/c/exe2'
                },
                'file_list': [
                    {'device': 'input', 'path': 'swift://a/c/o',
                        'mode': 'file'},
                    {'device': 'stdout', 'mode': 'char'},
                    {'device': 'image', 'path': 'swift://a/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertIn('[args]\n'
                      'args = sort\n', res.body)
        self.assertIn('[mapping]', res.body)
        self.assertIn('channel=/dev/input, mode=file', res.body)
        self.assertIn('channel=/dev/stdout, mode=char', res.body)

    def test_QUERY_sort_immediate_stdout_stderr(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ],
                'count': 2
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, str(self.get_sorted_numbers()) * 2)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stderr'}
                ],
                'count': 2
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '\nfinished\n' * 2)

    def test_QUERY_sort_store_stdout_immediate_stderr(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stderr'},
                    {'device': 'stdout', 'path': 'swift://a/c/o2'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '\nfinished\n')
        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers())

    def test_QUERY_config_syntax_2(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'devices': [
                    {'name': 'stdin', 'path': 'swift://a/c/o'},
                    {'name': 'stderr'},
                    {'name': 'stdout', 'path': 'swift://a/c/o2'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '\nfinished\n')
        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers())

    def test_QUERY_network_resolve(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stderr', 'path': 'swift://a/c/o2'}
                ],
                'connect': ['merge']
            },
            {
                'name': 'merge',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stderr', 'path': 'swift://a/c/o3'}
                ],
                'connect': ['sort']
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)

        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('finished', res.body)
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/out/%s' %
                              conf[0]['connect'][0], res.body))

        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('finished', res.body)
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/out/%s' %
                              conf[1]['connect'][0], res.body))

    def test_QUERY_networked_devices(self):
        self.setup_QUERY()
        nexe = trim(r'''
            return 'ok'
            ''')
        prolis = _test_sockets[0]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdout', 'path': 'zvm://merge:/dev/sort'},
                    {'device': 'stderr', 'path': 'swift://a/c/o2'}
                ]
            },
            {
                'name': 'merge',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stderr', 'path': 'swift://a/c/o3'}
                ]
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)

        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('finished', res.body)
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/stdout', res.body))

        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('finished', res.body)

    def test_networked_devices_multistage(self):
        self.setup_QUERY()
        nexe = trim(r'''
            for t in bind_list:
                err.write('%s, %s\n' % (t[1], t[0]))
            return 'ok'
            ''')
        prolis = _test_sockets[0]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'exec': {
                    'args': 'cat /dev/stdin',
                    'path': 'swift://./c/exe2'
                },
                'file_list': [
                    {
                        'device': 'stdin',
                        'path': 'swift://./c/o'
                    },
                    {
                        'device': 'stdout',
                        'path': 'zvm://stage2:/dev/stdin'
                    },
                    {
                        'device': 'stderr',
                        'path': 'swift://a/c/o2'
                    }
                ],
                'name': 'stage1'
            },
            {
                'exec': {
                    'args': 'cat',
                    'path': 'swift://./c/exe2'
                },
                'file_list': [
                    {
                        'device': 'stdout',
                        'path': 'zvm://stage3:/dev/stdin'
                    }
                ],
                'name': 'stage2'
            },
            {
                'exec': {
                    'args': 'cat',
                    'path': 'swift://./c/exe2'
                },
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'text/plain'
                    },
                    {
                        'device': 'stderr',
                        'path': 'swift://a/c/o3'
                    }
                ],
                'name': 'stage3'
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)

        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        # connect stdout to network sink
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/stdout', res.body))
        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        # bind stdin to network source
        self.assert_(re.match('tcp://0:\d+, /dev/stdin', res.body))

    def test_QUERY_network_resolve_multiple(self):
        self.setup_QUERY()
        nexe = trim(r'''
            import json
            con_list.insert(
                0,
                re.sub(r'(?s).*args = ([^\n]+).*', r'\1',
                    open(mnfst.nvram['path']).read())
            )
            return json.dumps(con_list)
            ''')
        prolis = _test_sockets[0]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdout'}
                ],
                'connect': ['merge', 'sort'],
                'count':3,
                'replicate': 2
            },
            {
                'name': 'merge',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdout'}
                ],
                'count': 2,
                'replicate': 2
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)

        results = [json.loads(r) for r in re.findall(
            r'(?s)(\[.*?\](?=\[|$))', res.body)]
        pattern = '/dev/out/([\S]+)\', u?\'tcp://127.0.0.1:\d+'
        for r in results:
            if 'sort-1' in r[0]:
                self.assertEqual(
                    sorted(re.findall(pattern, str(r[1:]))),
                    ['merge-1', 'merge-1', 'merge-2', 'merge-2',
                     'sort-2', 'sort-2', 'sort-3', 'sort-3']
                )
            elif 'sort-2' in r[0]:
                self.assertEqual(
                    sorted(re.findall(pattern, str(r[1:]))),
                    ['merge-1', 'merge-1', 'merge-2', 'merge-2',
                     'sort-1', 'sort-1', 'sort-3', 'sort-3']
                )
            elif 'sort-3' in r[0]:
                self.assertEqual(
                    sorted(re.findall(pattern, str(r[1:]))),
                    ['merge-1', 'merge-1', 'merge-2', 'merge-2',
                     'sort-1', 'sort-1', 'sort-2', 'sort-2']
                )
            elif 'merge-1' in r[0]:
                self.assertEqual(
                    sorted(re.findall(pattern, str(r[1:]))),
                    []
                )
            elif 'merge-2' in r[0]:
                self.assertEqual(
                    sorted(re.findall(pattern, str(r[1:]))),
                    []
                )
            else:
                self.assertTrue(False)
        self.check_container_integrity(prosrv, '/v1/a/c_out1', {})

    def test_QUERY_read_obj_wildcard(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c_in1/in*'},
                    {'device': 'stdout'}
                ]
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(
            0, 10) + self.get_sorted_numbers(10, 20))

    def test_QUERY_read_container_wildcard(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        self.create_object(prolis, '/v1/a/c/exe2', 'return sorted(id)')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c_in*/*'},
                    {'device': 'stdout'}
                ]
            }
        ]
        req = self.zerovm_request()
        jconf = json.dumps(conf)
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, ''.join([
            str(range(0, 10)),
            str(range(10, 20)),
            str([]),
            str(range(20, 30)),
            str(range(30, 40)),
            str([])
        ]))

    def test_QUERY_read_container_and_obj_wildcard(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        self.create_object(prolis, '/v1/a/c/exe2', 'return sorted(id)')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c_in*/in*'},
                    {'device': 'stdout'}
                ]
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, ''.join([
            str(range(0, 10)),
            str(range(10, 20)),
            str(range(20, 30)),
            str(range(30, 40))
        ]))

    def test_QUERY_group_transform(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c_in1/in*'},
                    {'device': 'stdout', 'path': 'swift://a/c_out1/out*'}
                ]
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)

        req = self.object_request('/v1/a/c_out1/output1')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(str(res.body), self.get_sorted_numbers(0, 10))
        req = self.object_request('/v1/a/c_out1/output2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(str(res.body), self.get_sorted_numbers(10, 20))
        self.check_container_integrity(prosrv, '/v1/a/c_out1', {})

    def test_QUERY_write_wildcard(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdout', 'path': 'swift://a/c_out1/wout.*'}],
                'count': 2
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        # each header is duplicated because we have replication level set to 2
        self.assertEqual(
            res.headers['x-nexe-system'], 'sort-1,sort-1,sort-2,sort-2')
        self.assertEqual(res.headers['x-nexe-status'], 'ok.,ok.,ok.,ok.')
        self.assertEqual(res.headers['x-nexe-retcode'], '0,0,0,0')
        self.check_container_integrity(prosrv,
                                       '/v1/a/c_out1',
                                       {
                                           'wout.sort-1': '(l.',
                                           'wout.sort-2': '(l.'
                                       })
        # now we remove auto-replication and should get the same result
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdout', 'path': 'swift://a/c_out1/wout.*'}],
                'count': 2,
                'replicate': 0
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['x-nexe-system'], 'sort-1,sort-2')
        self.assertEqual(res.headers['x-nexe-status'], 'ok.,ok.')
        self.assertEqual(res.headers['x-nexe-retcode'], '0,0')
        self.check_container_integrity(prosrv,
                                       '/v1/a/c_out1',
                                       {
                                           'wout.sort-1': '(l.',
                                           'wout.sort-2': '(l.'
                                       })

    def test_QUERY_group_transform_multiple(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c_in*/in*'},
                    {'device': 'stdout', 'path': 'swift://a/c_out*/out*'}
                ]
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            res.headers['x-nexe-system'], 'sort-1,sort-2,sort-3,sort-4')
        self.assertEqual(res.headers['x-nexe-status'], 'ok.,ok.,ok.,ok.')
        self.assertEqual(res.headers['x-nexe-retcode'], '0,0,0,0')
        self.check_container_integrity(
            prosrv,
            '/v1/a/c_out1',
            {'output1': self.get_sorted_numbers(0, 10),
             'output2': self.get_sorted_numbers(10, 20)}
        )
        self.check_container_integrity(
            prosrv,
            '/v1/a/c_out2',
            {'output1': self.get_sorted_numbers(20, 30),
             'output2': self.get_sorted_numbers(30, 40)}
        )

    def __test_QUERY_calls_authorize(self):
        # there is no pre-authorization right now, maybe we do not need it at
        # all
        called = [False]

        def authorize(req):
            called[0] = True
            return HTTPUnauthorized(request=req)
        with save_globals():
            proxy_server.http_connect =\
                fake_http_connect(200, 200, 201, 201, 201)
            prosrv = _test_servers[0]
            req = self.zerovm_object_request()
            req.environ['swift.authorize'] = authorize
            req.body = '1234'
            req.get_response(prosrv)
        self.assert_(called[0])

    def test_QUERY_request_client_disconnect_attr(self):
        with save_globals():
            proxy_server.http_connect = \
                fake_http_connect(200, 200, 201, 201, 201)
            prosrv = _test_servers[0]
            req = self.zerovm_request()
            req.body = '12345'
            req.content_length = 10
            res = req.get_response(prosrv)
            self.assertEqual(res.status, '499 Client Disconnect')

    def test_QUERY_request_timed_out(self):
        class SlowFile():

            def read(self, amt=None):
                sleep(0.1)
                return '1'

        prosrv = _test_servers[0]
        orig_upload_time = _pqm.max_upload_time
        with save_globals():
            proxy_server.http_connect = \
                fake_http_connect(200, 200, 201, 201, 201)
            _pqm.max_upload_time = 1
            req = self.zerovm_request()
            req.body_file = SlowFile()
            req.content_length = 100
            res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 408)
        _pqm.max_upload_time = orig_upload_time

    def test_QUERY_invalid_etag(self):
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        req.headers['etag'] = '1111'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 422)

    def test_QUERY_invalid_nexe_name(self):
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/error'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout', 'path': 'swift://a/c/out'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(
            res.body, 'Error 404 Not Found while fetching /a/c/error')
        self.assertEqual(res.status_int, 404)

    def test_QUERY_missing_required_fields(self):
        conf = [
            {
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'Must specify node name')
        conf = [
            {
                'name': 'sort',
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'Must specify exec stanza for sort')
        conf = [
            {
                'name': 'sort',
                'exec': {'test': 1},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'Must specify executable path for sort')

    def test_QUERY_invalid_device_config(self):
        prosrv = _test_servers[0]
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'path': 'swift://a/c/o'},
                    {'device': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'Must specify device for file in sort')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdtest'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'Could not resolve channel path "" for '
                                   'device: stdtest')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'file_list': [
                    {'device': 'stdin', 'path': 'swift://*'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'Invalid path swift://* in sort')

    def test_local_device_path_404(self):
        self.setup_QUERY()
        prosrv = _test_servers[0]
        for path in ('c/error', 'c/o/error', 'error'):
            conf = [
                {
                    'name': 'sort',
                    'exec': {'path': 'swift://a/c/exe',
                             'args': ''},
                    'file_list': [
                        {'device': 'stdin',
                         'path': 'swift://a/%s' % path},
                        {'device': 'stdout'}
                    ]
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 404)
            if path == 'error':
                self.assertEqual(res.body, 'Error while fetching '
                                           '/a/%s' % path)
            else:
                self.assertEqual(res.body, 'Error %s while fetching '
                                           '/a/%s' % (res.status, path))
                self.assertEqual(res.headers['x-nexe-system'], 'sort')
                self.assertEqual(res.headers['x-nexe-status'],
                                 'ZeroVM did not run')
                self.assertEqual(res.headers['x-nexe-retcode'], '0')

    def test_remote_device_path_404(self):
        self.setup_QUERY()
        prosrv = _test_servers[0]
        for path in ('c/error', 'c/o/error'):
            conf = [
                {
                    'name': 'sort',
                    'exec': {'path': 'swift://a/c/exe',
                             'args': ''},
                    'file_list': [
                        {'device': 'stdin',
                         'path': 'swift://a/%s' % path},
                        {'device': 'stdout'}
                    ],
                    'attach': 'stdout'
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 404)
            self.assertEqual(res.body, 'Error %s while fetching '
                                       '/a/%s' % (res.status, path))
            self.assertEqual(res.headers['x-nexe-system'], 'sort')
            self.assertEqual(res.headers['x-nexe-status'],
                             'ZeroVM did not run')
            self.assertEqual(res.headers['x-nexe-retcode'], '0')
        for path in ('c/error', 'c/o/error'):
            conf = [
                {
                    'name': 'sort',
                    'exec': {'path': 'swift://a/c/exe',
                             'args': ''},
                    'file_list': [
                        {'device': 'stdin',
                         'path': 'swift://a/%s.in' % path},
                        {'device': 'stdout',
                         'path': 'swift://a/%s.out' % path}
                    ],
                    'attach': 'stdout'
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 404)
            self.assertEqual(res.body, 'Error %s while fetching '
                                       '/a/%s.in' % (res.status, path))
            self.assertEqual(res.headers['x-nexe-system'], 'sort')
            self.assertEqual(res.headers['x-nexe-status'],
                             'ZeroVM did not run')
            self.assertEqual(res.headers['x-nexe-retcode'], '0')
        for path in ('c/error', 'c/o/error'):
            conf = [
                {
                    'name': 'sort',
                    'exec': {'path': 'swift://a/c/exe',
                             'args': ''},
                    'file_list': [
                        {'device': 'stdin',
                         'path': 'swift://a/%s.in' % path},
                        {'device': 'stdout',
                         'path': 'swift://a/%s.out' % path}
                    ],
                    'attach': 'stdin'
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 404)
            self.assertEqual(res.body, 'Error %s while fetching '
                                       '/a/%s.in' % (res.status, path))
            self.assertEqual(res.headers['x-nexe-system'], 'sort')
            self.assertEqual(res.headers['x-nexe-status'],
                             'ZeroVM did not run')
            self.assertEqual(res.headers['x-nexe-retcode'], '0')
        for path in ('c/error', 'c/o/error'):
            conf = [
                {
                    'name': 'sort',
                    'exec': {'path': 'swift://a/c/exe',
                             'args': ''},
                    'file_list': [
                        {'device': 'stdin',
                         'path': 'swift://a/%s' % path},
                        {'device': 'stdout',
                         'path': 'swift://a/%s' % path}
                    ],
                    'attach': 'stdout'
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 400)
            self.assertEqual(res.body, ('Could not resolve channel path '
                                        '"swift://a/%s" for device: stdin'
                                        % path) * 2)
            self.assertEqual(res.headers['x-nexe-system'], 'sort,sort')
            self.assertEqual(res.headers['x-nexe-status'],
                             'ZeroVM did not run,ZeroVM did not run')
            self.assertEqual(res.headers['x-nexe-retcode'], '0,0')

    def test_QUERY_account_server_error(self):
        with save_globals():
            swift.proxy.controllers.account.http_connect = \
                fake_http_connect(500, 500, 500, 500, 500)
            swift.proxy.controllers.base.http_connect = \
                fake_http_connect(500, 500, 500, 500, 500)
            swift.proxy.controllers.container.http_connect = \
                fake_http_connect(500, 500, 500, 500, 500)
            swift.proxy.controllers.obj.http_connect = \
                fake_http_connect(500, 500, 500, 500, 500)
            proxyquery.http_connect = \
                fake_http_connect(500, 500, 500, 500, 500)
            prosrv = _test_servers[0]
            conf = [
                {
                    'name': 'sort',
                    'exec': {'path': 'swift://a/c/exe'},
                    'file_list': [
                        {'device': 'stdin', 'path': 'swift://a/c*'}
                    ]
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 400)
            self.assertEqual(
                res.body, 'Error querying object server for account: a')

    def test_QUERY_config_parser(self):

        pqm = proxyquery.ProxyQueryMiddleware(
            self.proxy_app,
            {'zerovm_sysimage_devices': 'sysimage1 sysimage2'},
            object_ring=FakeRing(), container_ring=FakeRing())
        conf = [
            {
                'name': 'script',
                'exec': {
                    'path': 'file://boot/lua',
                    'args': 'my_script.lua'
                },
                'file_list': [
                    {
                        'device': 'image',
                        'path': 'swift://a/images/lua.img'
                    },
                    {
                        'device': 'stdin',
                        'path': 'swift://a/c/input'
                    },
                    {
                        'device': 'sysimage1'
                    }
                ],
                'connect': ['script'],
                'count':5
            }
        ]
        req = Request.blank('/a', environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/json'})
        parser = None
        try:
            parser = ClusterConfigParser(pqm.zerovm_sysimage_devices,
                                         pqm.zerovm_content_type,
                                         pqm.parser_config,
                                         pqm.list_account,
                                         pqm.list_container)
            parser.parse(conf, False, request=req)
        except ClusterConfigParsingError:
            self.assertTrue(False, msg='ClusterConfigParsingError is raised')
        self.assertEqual(len(parser.nodes), 5)

        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        self.setup_QUERY()
        self.create_container(prolis, '/v1/a/terasort')
        self.create_object(prolis, '/v1/a/terasort/input/1.txt',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/2.txt',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/3.txt',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/4.txt',
                           self.get_random_numbers())
        nexe = trim(r'''
            return open(mnfst.nvram['path']).read()
            ''')
        self.create_object(prolis, '/v1/a/terasort/bin/map', nexe)
        self.create_object(prolis, '/v1/a/terasort/bin/reduce', nexe)
        conf = [
            {
                "name": "map",
                "exec": {
                    "path": "swift://a/terasort/bin/map",
                    "env": {
                        "MAP_NAME": "map",
                        "REDUCE_NAME": "red",
                        "MAP_CHUNK_SIZE": "100485700"
                    }
                },
                "connect": ["red", "map"],
                "file_list": [
                    {
                        "device": "stdin",
                        "path": "swift://a/terasort/input/*.txt"
                    },
                    {
                        "device": "stderr",
                        "path": "swift://a/terasort/log/*.log",
                        "content_type": "text/plain"
                    }
                ]
            },
            {
                "name": "red",
                "exec": {
                    "path": "swift://a/terasort/bin/reduce",
                    "env": {
                        "MAP_NAME": "map",
                        "REDUCE_NAME": "red"
                    }
                },
                "file_list": [
                    {
                        "device": "stdout",
                        "path": "swift://a/terasort/output/*.txt",
                        "content_type": "text/plain"
                    },
                    {
                        "device": "stderr",
                        "path": "swift://a/terasort/log/*.log",
                        "content_type": "text/plain"
                    }
                ],
                "count": 4
            }
        ]
        jconf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        for i in range(1, 5):
            req = self.object_request('/v1/a/terasort/log/%d.log' % i)
            res = req.get_response(prosrv)
            print res.status
            print res.headers
            print res.body
        for i in range(1, 5):
            req = self.object_request('/v1/a/terasort/log/red-%d.log' % i)
            res = req.get_response(prosrv)
            print res.status
            print res.headers
            print res.body
        # controller = _pqm.get_controller('a', None, None)
        # error = controller.parse_cluster_config(req, conf)
        # self.assertIsNone(error)
        # self.assertEqual(len(controller.nodes), 8)
        # for name, node in controller.nodes.iteritems():
        #     self.assertEqual(node.replicate, 1)
        #     self.assertEqual(node.replicas, [])
        # print json.dumps(controller.nodes, sort_keys=True, indent=2,
        # cls=proxyquery.NodeEncoder)

    def test_single_wildcard(self):
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        self.setup_QUERY()
        self.create_container(prolis, '/v1/a/single')
        self.create_object(prolis, '/v1/a/single/input1.txt',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/single/script1.py',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/single/script2.py',
                           self.get_random_numbers())
        nexe = trim(r'''
            err.write('%s:%s\n' % (mnfst.channels['/dev/stdin']['device'],
                                   mnfst.channels['/dev/stdin']['path']))
            err.write('%s:%s\n' % (mnfst.channels['/dev/stdout']['device'],
                                   mnfst.channels['/dev/stdout']['path']))
            err.write('%s:%s\n' % (mnfst.channels['/dev/stderr']['device'],
                                   mnfst.channels['/dev/stderr']['path']))
            err.write('%s:%s\n' % (mnfst.channels['/dev/python']['device'],
                                   mnfst.channels['/dev/python']['path']))
            if mnfst.channels.get('/dev/input'):
                err.write('%s:%s\n' % (mnfst.channels['/dev/input']['device'],
                                       mnfst.channels['/dev/input']['path']))
            return 'ok'
            ''')
        py = StringIO(nexe)
        with self.create_tar({'python': py}) as tar:
            with self.add_sysimage_device(tar, name='python'):
                conf = [
                    {
                        "name": "mapper",
                        "exec": {
                            "path": "file://python:python"
                        },

                        "args": "arg1 arg2",

                        "file_list": [
                            {
                                "device": "stdin",
                                "path": "swift://./single/script1.py"
                            },
                            {
                                "device": "input",
                                "path": "swift://./single/input*.txt"
                            },
                            {
                                "device": "stderr",
                                "path": "swift://./single/output*.err",
                                "content_type": "text/plain"
                            },
                            {
                                "device": "python"
                            }
                        ],
                        "connect": [
                            "reducer"
                        ]
                    },
                    {
                        "name": "reducer",
                        "exec": {
                            "path": "file://python:python"
                        },
                        "file_list": [
                            {
                                "device": "stdin",
                                "path": "swift://./single/script2.py"
                            },
                            {
                                "device": "stdout"
                            },
                            {
                                "device": "python"
                            },
                            {
                                "device": "stderr",
                                "path": "swift://./single/*.err",
                                "content_type": "text/plain"
                            }
                        ]
                    }
                ]
                jconf = json.dumps(conf)
                req = self.zerovm_request()
                req.body = jconf
                res = req.get_response(prosrv)
                self.executed_successfully(res)
                self.assertEqual(res.headers['x-nexe-system'],
                                 'mapper-1,reducer')
                self.assertEqual(res.body, 'ok')
            req = self.object_request('/v1/a/single/output1.err')
            res = req.get_response(prosrv)
            body = res.body.split('\n')
            test_path = os.path.abspath(_testdir)
            dev, path = body[0].split(':')
            self.assertEqual(dev, '/dev/stdin')
            self.assertTrue(path.startswith(test_path))
            dev, path = body[1].split(':')
            self.assertEqual(dev, '/dev/stdout')
            self.assertEqual(path, '/dev/null')
            dev, path = body[2].split(':')
            self.assertEqual(dev, '/dev/stderr')
            self.assertTrue(path.startswith(test_path))
            dev, path = body[3].split(':')
            self.assertEqual(dev, '/dev/python')
            self.assertEqual(path, tar)
            dev, path = body[4].split(':')
            self.assertEqual(dev, '/dev/input')
            self.assertTrue(path.startswith(test_path))
            obj_path = '/%s/' % hash_path('a', 'single', 'input1.txt')
            self.assertTrue(obj_path in path)
            dev, path = body[5].split(', ')
            self.assertEqual(path, '/dev/out/reducer')
            req = self.object_request('/v1/a/single/reducer.err')
            res = req.get_response(prosrv)
            body = res.body.split('\n')
            dev, path = body[0].split(':')
            self.assertEqual(dev, '/dev/stdin')
            self.assertTrue(path.startswith(test_path))
            dev, path = body[1].split(':')
            self.assertEqual(dev, '/dev/stdout')
            self.assertTrue(path.startswith(test_path))
            dev, path = body[2].split(':')
            self.assertEqual(dev, '/dev/stderr')
            self.assertTrue(path.startswith(test_path))
            dev, path = body[3].split(':')
            self.assertEqual(dev, '/dev/python')
            self.assertEqual(path, tar)

    def test_opaque_config(self):

        pqm = proxyquery.ProxyQueryMiddleware(
            self.proxy_app,
            {'zerovm_sysimage_devices': 'sysimage1 sysimage2'},
            object_ring=FakeRing(), container_ring=FakeRing())
        conf = [
            {
                'name': 'script',
                'exec': {
                    'path': 'file://boot/lua',
                    'args': 'my_script.lua'
                },
                'file_list': [
                    {
                        'device': 'image',
                        'path': 'swift://a/images/lua.img'
                    },
                    {
                        'device': 'stdin',
                        'path': 'swift://a/c/input'
                    },
                    {
                        'device': 'sysimage1'
                    }
                ],
                'connect': ['script'],
                'count':5
            }
        ]
        req = Request.blank('/a', environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/json'})
        parser = None
        cluster_config = None
        try:
            parser = ClusterConfigParser(pqm.zerovm_sysimage_devices,
                                         pqm.zerovm_content_type,
                                         pqm.parser_config,
                                         pqm.list_account,
                                         pqm.list_container,
                                         network_type='opaque')
            cluster_config = parser.parse(conf, False, request=req)
        except ClusterConfigParsingError:
            self.assertTrue(False, msg='ClusterConfigParsingError is raised')
        self.assertEqual(len(parser.nodes), 5)
        for n in cluster_config.nodes.itervalues():
            parser.build_connect_string(n, cluster_id='cluster1')
            self.assertEqual(len(n.bind), 4)
            for line in n.bind:
                self.assertNotIn('/dev/in/%s' % n.name, line)
            self.assertEqual(len(n.connect), 4)
            for line in n.connect:
                self.assertNotIn('/dev/in/%s' % n.name, line)
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        self.setup_QUERY()
        self.create_container(prolis, '/v1/a/terasort')
        self.create_object(prolis, '/v1/a/terasort/input/1.txt',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/2.txt',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/3.txt',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/4.txt',
                           self.get_random_numbers())
        mapper_count = 4
        reducer_count = 4
        orig_network_type = _pqm.network_type
        orig_repl = _pqm.ignore_replication
        try:
            _pqm.network_type = 'opaque'
            _pqm.ignore_replication = True
            nexe = trim(r'''
                return open(mnfst.nvram['path']).read()
                ''')
            self.create_object(prolis, '/v1/a/terasort/bin/map', nexe)
            self.create_object(prolis, '/v1/a/terasort/bin/reduce', nexe)
            conf = [
                {
                    "name": "map",
                    "exec": {
                        "path": "swift://a/terasort/bin/map",
                        "env": {
                            "MAP_NAME": "map",
                            "REDUCE_NAME": "red",
                            "MAP_CHUNK_SIZE": "100485700"
                        }
                    },
                    "connect": ["red", "map"],
                    "file_list": [
                        {
                            "device": "stdin",
                            "path": "swift://a/terasort/input/*.txt"
                        },
                        {
                            "device": "stderr",
                            "path": "swift://a/terasort/log/*.log",
                            "content_type": "text/plain"
                        }
                    ]
                },
                {
                    "name": "red",
                    "exec": {
                        "path": "swift://a/terasort/bin/reduce",
                        "env": {
                            "MAP_NAME": "map",
                            "REDUCE_NAME": "red"
                        }
                    },
                    "file_list": [
                        {
                            "device": "stdout",
                            "path": "swift://a/terasort/output/*.txt",
                            "content_type": "text/plain"
                        },
                        {
                            "device": "stderr",
                            "path": "swift://a/terasort/log/*.log",
                            "content_type": "text/plain"
                        }
                    ],
                    "count": reducer_count
                }
            ]
            jconf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = jconf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            map_in = re.compile(
                '/dev/in/map-\d+, opaque:local\|[^-]+-\d+-\d+')
            map_out = re.compile(
                '/dev/out/map-\d+, opaque:local\|>[^-]+-\d+-\d+')
            red_in = re.compile(
                '/dev/in/red-\d+, opaque:local\|[^-]+-\d+-\d+')
            red_out = re.compile(
                '/dev/out/red-\d+, opaque:local\|>[^-]+-\d+-\d+')
            for i in range(1, mapper_count + 1):
                req = self.object_request('/v1/a/terasort/log/%d.log' % i)
                res = req.get_response(prosrv)
                self.assertEqual(res.status_int, 200)
                con_list = map_in.findall(res.body)
                self.assertEqual(len(con_list), mapper_count - 1)
                for line in con_list:
                    self.assertNotIn('/dev/in/map-%d' % i, line)

                con_list = map_out.findall(res.body)
                self.assertEqual(len(con_list), mapper_count - 1)
                for line in con_list:
                    self.assertNotIn('/dev/out/map-%d' % i, line)

                con_list = red_in.findall(res.body)
                self.assertEqual(len(con_list), 0)

                con_list = red_out.findall(res.body)
                self.assertEqual(len(con_list), reducer_count)
                for line in con_list:
                    self.assertNotIn('/dev/out/map-%d' % i, line)
            for i in range(1, reducer_count + 1):
                req = self.object_request('/v1/a/terasort/log/red-%d.log' % i)
                res = req.get_response(prosrv)
                self.assertEqual(res.status_int, 200)
                con_list = map_in.findall(res.body)
                self.assertEqual(len(con_list), mapper_count)

                con_list = map_out.findall(res.body)
                self.assertEqual(len(con_list), 0)

                con_list = red_in.findall(res.body)
                self.assertEqual(len(con_list), 0)

                con_list = red_out.findall(res.body)
                self.assertEqual(len(con_list), 0)
        finally:
            _pqm.network_type = orig_network_type
            _pqm.ignore_replication = orig_repl

    def test_container_query(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            import json
            import sqlite3
            db_path = mnfst.channels['/dev/input']['path']
            con = sqlite3.connect(db_path)
            cursor = con.cursor()
            cursor.execute("SELECT name FROM object order by 1;")
            l = []
            for r in cursor.fetchall():
                l.append(str(r[0]))
            return json.dumps(l)
            ''')
        self.create_object(prolis, '/v1/a/c/list_container.nexe', nexe)
        self.create_container(prolis, '/v1/a/test_cont1')
        self.create_object(prolis, '/v1/a/test_cont1/o1',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/test_cont1/o2',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/test_cont1/o/o3',
                           self.get_random_numbers())
        conf = [
            {
                'name': 'list',
                'exec': {
                    'path': 'swift://a/c/list_container.nexe'
                },
                'file_list': [
                    {
                        'device': 'input',
                        'path': 'swift://a/test_cont1'
                    },
                    {
                        'device': 'stdout'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.executed_successfully(res)
        obj_list = json.loads(res.body)
        self.assertEqual(obj_list, ['o/o3', 'o1', 'o2'])
        self.create_container(prolis, '/v1/a/test_cont2')
        self.create_object(prolis, '/v1/a/test_cont2/oo2',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/test_cont2/o/o2',
                           self.get_random_numbers())
        self.create_object(prolis, '/v1/a/test_cont2/o/o/o2',
                           self.get_random_numbers())
        conf = [
            {
                'name': 'list',
                'exec': {
                    'path': 'swift://a/c/list_container.nexe'
                },
                'file_list': [
                    {
                        'device': 'input',
                        'path': 'swift://a/test_cont*'
                    },
                    {
                        'device': 'stdout',
                        'path': 'swift://a/c/list_output*',
                        'content_type': 'application/json'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.executed_successfully(res)
        req = self.object_request('/v1/a/c/list_output1')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.content_type, 'application/json')
        self.assertEqual(json.loads(res.body),
                         ['o/o3', 'o1', 'o2'])
        req = self.object_request('/v1/a/c/list_output2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.content_type, 'application/json')
        self.assertEqual(json.loads(res.body),
                         ['o/o/o2', 'o/o2', 'oo2'])

    def test_parse_daemon_config(self):
        conf = [
            {
                'name': 'daemon1',
                'exec': {
                    'path': 'file://sysimage1:daemon1'
                },
                'file_list': [
                    {
                        'device': 'stdin',
                        'path': 'swift://a/c/o'
                    },
                    {
                        'device': 'stdout',
                        'path': 'swift://a/c/o'
                    },
                    {
                        'device': 'sysimage1'
                    }
                ]
            }
        ]
        fd = open('%s/config.json' % _testdir, 'w')
        json.dump(conf, fd)
        fd.close()
        conf = [
            {
                'name': 'daemon2',
                'exec': {
                    'path': 'file://sysimage1:daemon2'
                },
                'file_list': [
                    {
                        'device': 'input',
                        'path': 'swift://a/c/o'
                    },
                    {
                        'device': 'output',
                        'path': 'swift://a/c/o'
                    },
                    {
                        'device': 'sysimage1'
                    }
                ]
            }
        ]
        fd = open('%s/config2.json' % _testdir, 'w')
        json.dump(conf, fd)
        fd.close()
        pqm = proxyquery.ProxyQueryMiddleware(
            self.proxy_app,
            {'zerovm_sysimage_devices': 'sysimage1 sysimage2'},
            object_ring=FakeRing(), container_ring=FakeRing())
        daemons = pqm.parse_daemon_config(['daemon1',
                                           '%s/config.json' % _testdir,
                                           'daemon2',
                                           '%s/config2.json' % _testdir])
        for val in daemons:
            self.assertIn(val[0], ('daemon1', 'daemon2'))
            config = val[1]
            self.assertEqual(config.exe.image, 'sysimage1')
            self.assertIn(config.exe.path, ('daemon1', 'daemon2'))

    def test_cors(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        if hasattr(_pqm.app, 'strict_cors_mode'):
            self.assertTrue(_pqm.app.strict_cors_mode)
        nexe = trim(r'''
            return 'hello, world'
            ''')
        self.create_object(prolis, '/v1/a/c/hello.nexe', nexe)
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/c/hello.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        req.headers['origin'] = 'http://example.com'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        # Uncomment it when tested on Swift > 1.13.1
        # the bug with strict_cors_mode is fixed in current trunk
        # try:
        #     _pqm.app.strict_cors_mode = False
        #     req = self.zerovm_request()
        #     req.body = conf
        #     req.headers['origin'] = 'http://example.com'
        #     res = req.get_response(prosrv)
        #     self.assertEqual(res.status_int, 200)
        #     self.assertEqual(res.body, 'hello, world')
        #     self.assertIn('Access-Control-Allow-Origin', res.headers)
        #     self.assertEqual(res.headers['Access-Control-Allow-Origin'],
        #                      'http://example.com')
        #     self.assertIn('Access-Control-Expose-Headers', res.headers)
        #     self.check_container_integrity(prosrv, '/v1/a/c', {})
        # finally:
        #     _pqm.app.strict_cors_mode = True

    def test_min_size(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            return ''
            ''')
        self.create_object(prolis, '/v1/a/c/hello.nexe', nexe)
        conf = [
            {
                'name': 'hello',
                'exec': {'path': 'swift://a/c/hello.nexe'},
                'file_list': [
                    {'device': 'stderr',
                     'path': 'swift://a/c/stderr.log',
                     'min_size': 0},
                    {'device': 'stdout',
                     'path': 'swift://a/c/stdout.log',
                     'min_size': 0}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '')
        req = self.object_request('/v1/a/c/stderr.log')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '\nfinished\n')
        req = self.object_request('/v1/a/c/stdout.log')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '')
        self.check_container_integrity(prosrv, '/v1/a/c', {})
        conf = [
            {
                'name': 'hello',
                'exec': {'path': 'swift://a/c/hello.nexe'},
                'file_list': [
                    {'device': 'stderr',
                     'path': 'swift://a/c/stderr_m.log',
                     'min_size': 1},
                    {'device': 'stdout',
                     'path': 'swift://a/c/stdout_m.log',
                     'min_size': 1}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '')
        req = self.object_request('/v1/a/c/stderr_m.log')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '\nfinished\n')
        req = self.object_request('/v1/a/c/stdout_m.log')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 404)
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_policy_config(self):
        conf = {'devices': _testdir, 'swift_dir': _testdir,
                'mount_check': 'false',
                'allowed_headers': 'content-encoding, x-object-manifest, '
                                   'content-disposition, foo',
                'allow_versions': 'True',
                'standalone_policies': 'one two three'}
        pqm = proxyquery.ProxyQueryMiddleware(None, conf,
                                              logger=debug_logger('pqm'))
        self.assertTrue(1 in pqm.standalone_policies)
        self.assertTrue(2 in pqm.standalone_policies)
        self.assertTrue(3 not in pqm.standalone_policies)
        self.assertEqual(pqm.logger.lines_dict['warning'][0],
                         'Could not load storage policy: three')

    def test_sort_from_request(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/c/exe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout', 'path': 'swift://a/c/o2'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, '')
            self.create_object(prolis, '/v1/a/c/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = self.zerovm_request()
            req.headers['x-zerovm-source'] = 'swift://a/c/myapp'
            req.headers['content-type'] = 'application/x-pickle'
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.check_container_integrity(prosrv,
                                           '/v1/a/c',
                                           {
                                               'o2': self.get_sorted_numbers(),
                                               'myapp': open(tar, 'rb').read()
                                           })
        self.create_object(prolis, '/v1/a/c/sort.json',
                           conf,
                           content_type='application/json')
        req = self.zerovm_request()
        req.headers['x-zerovm-source'] = 'swift://a/c/sort.json'
        req.headers['content-type'] = 'application/x-pickle'
        random_data = self.get_random_numbers()
        data = StringIO(random_data)
        req.body_file = data
        req.content_length = len(random_data)
        res = req.get_response(prosrv)
        self.executed_successfully(res)
        self.check_container_integrity(prosrv,
                                       '/v1/a/c',
                                       {
                                           'o2': self.get_sorted_numbers(),
                                           'sort.json': conf
                                       })

    def test_invalid_methods(self):
        prosrv = _test_servers[0]
        for method in ['GET', 'HEAD', 'DELETE', 'PUT']:
            req = self.zerovm_request()
            req.body = ''
            req.method = method
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 501)
        for method in ['POST', 'HEAD', 'DELETE', 'PUT']:
            req = self.zerovm_request()
            req.body = ''
            req.method = method
            req.headers['x-zerovm-execute'] = 'open/1.0'
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 412)
        for method in ['POST', 'HEAD', 'DELETE', 'PUT']:
            req = self.zerovm_request()
            req.body = ''
            req.method = method
            req.headers['x-zerovm-execute'] = 'open/1.0'
            req.path_info = '/v1/a/c/o'
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 501)

    def test_job_chain(self):
        self.setup_QUERY()
        self.actions = []
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            import json
            conf = [
                {
                    'name': 'http',
                    'exec': {'path': 'swift://a/c/exe2'},
                    'file_list': [
                        {
                            'device': 'stdout',
                            'content_type': 'message/http'
                        }
                    ]
                }
            ]
            out = json.dumps(conf)
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: application/json',
                'X-Zerovm-Execute: 1.0',
                '', ''
                ])
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/chainer', nexe)
        nexe = trim(r'''
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: text/html',
                'X-Object-Meta-Key1: value1',
                'X-Object-Meta-Key2: value2',
                '', ''
                ])
            out = '<html><body>Test this</body></html>'
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/chainer'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a'])
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.assertEqual(res.headers['x-object-meta-key1'], 'value1')
        self.assertEqual(res.headers['x-object-meta-key2'], 'value2')
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        self.check_container_integrity(prosrv, '/v1/a/c', {})
        self.assertEqual(
            ['Allowed Owner to POST swift://a with 1.0',
             'Allowed Owner to GET swift://a/c/chainer with 1.0',
             'Allowed Owner to POST swift://a with 1.0',
             'Allowed Owner to GET swift://a/c/exe2 with 1.0'],
            self.actions)

    def test_job_chain_timeout(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            import json
            conf = [
                {
                    'name': 'http',
                    'exec': {'path': 'swift://a/c/chainer'},
                    'file_list': [
                        {
                            'device': 'stdout',
                            'content_type': 'message/http'
                        }
                    ]
                }
            ]
            out = json.dumps(conf)
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: application/json',
                'X-Zerovm-Execute: 1.0',
                '', ''
                ])
            sleep(0.3)
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/chainer', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/chainer'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        _orig_chain_timeout = prosrv.app.chain_timeout
        try:
            prosrv.app.chain_timeout = 1
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.headers['content-type'], 'application/json')
            self.assertEqual(res.body, conf)
            self.assertTrue(res.headers['x-chain-total-time'] >
                            prosrv.app.chain_timeout)
            self.check_container_integrity(prosrv, '/v1/a/c', {})
        finally:
            prosrv.app.chain_timeout = _orig_chain_timeout

    def test_job_chain_with_payload(self):
        self.setup_QUERY()
        data = pickle.dumps('Quick brown fox', protocol=0)
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            import json
            import urlparse
            qs = zvm_environ['QUERY_STRING']
            params = dict(urlparse.parse_qsl(qs, True))
            conf = [
                {
                    'name': 'store',
                    'exec': {'path': 'swift://a/c/store'},
                    'file_list': [
                        {
                            'device': 'stdout',
                            'path': 'swift:/%s' % params['path'],
                            'content_type': params['content_type']
                        },
                        {
                            'device': 'stdin'
                        }
                    ]
                }
            ]
            out = json.dumps(conf, indent=2)
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: application/json',
                'X-Zerovm-Execute: 1.0',
                '', ''
                ])
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/receive', nexe)
        nexe = trim(r'''
            return id
            ''')
        self.create_object(prolis, '/v1/a/c/store', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/receive'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        self.create_object(prolis, '/v1/a/c/receiver.json', conf,
                           content_type='application/json')
        req = self.zerovm_request()
        req.query_string = 'path=/a/c/my_object&content_type=text/plain'
        req.body = data
        req.headers['x-zerovm-source'] = 'swift://a/c/receiver.json'
        res = req.get_response(prosrv)
        self.executed_successfully(res)
        req = self.object_request('/v1/a/c/my_object')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'Quick brown fox')
        self.assertEqual(res.content_type, 'text/plain')

    def test_restful_job_chain_with_payload(self):
        self.setup_QUERY()
        data = pickle.dumps('Quick brown fox', protocol=0)
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            import json
            import urlparse
            qs = zvm_environ['QUERY_STRING']
            params = dict(urlparse.parse_qsl(qs, True))
            path_info = zvm_environ['PATH_INFO']
            conf = [
                {
                    'name': 'store',
                    'exec': {'path': 'swift://a/c/store'},
                    'file_list': [
                        {
                            'device': 'stdout',
                            'path': 'swift:/%s' % path_info,
                            'content_type': params['content_type']
                        },
                        {
                            'device': 'stdin'
                        }
                    ]
                }
            ]
            out = json.dumps(conf, indent=2)
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: application/json',
                'X-Zerovm-Execute: 1.0',
                '', ''
                ])
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/receive', nexe)
        nexe = trim(r'''
            return id
            ''')
        self.create_object(prolis, '/v1/a/c/store', nexe)
        req = Request.blank('/v1/a/c',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={
                                'X-Container-Meta-Rest-Endpoint':
                                'swift://a/c/myapp'})
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 204)
        req = Request.blank('/v1/a/c',
                            environ={'REQUEST_METHOD': 'HEAD'})
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 204)
        self.assertEqual(res.headers['X-Container-Meta-Rest-Endpoint'],
                         'swift://a/c/myapp')
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/receive'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        cache = FakeMemcache()
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(prolis, '/v1/a/c/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')

            def create_req(cache):
                req = Request.blank(
                    '/api/a/c/my_object',
                    environ={'REQUEST_METHOD': 'PUT'},
                    headers={
                        'Content-Type': 'application/x-pickle'})
                req.query_string = 'content_type=text/plain'
                req.body = data
                req.environ['swift.cache'] = cache
                return req
            req = create_req(cache)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.assertEqual(cache.call, {'set': 1, 'get': 1})
            req = create_req(cache)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.assertEqual(cache.call, {'set': 1, 'get': 2})
            req = self.object_request('/v1/a/c/my_object')
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, 'Quick brown fox')
            self.assertEqual(res.content_type, 'text/plain')

    def test_return_bad_retcode(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            global error_code
            error_code = 1
            return 'hello, world'
            ''')
        self.create_object(prolis, '/v1/a/c/rc.nexe', nexe)
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/c/rc.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 500)
        self.assertEqual(res.body, 'hello, world')
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_setting_nexe_headers(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: text/html',
                'X-Nexe-Status: stat',
                'X-Nexe-Retcode: 42',
                '', ''
                ])
            out = '<html><body>Test this</body></html>'
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http'
                    }
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        # we should get actual x-nexe- headers
        # and not the ones user application sets in its output
        self.assertEqual(res.headers['x-nexe-status'], 'ok.')
        self.assertEqual(res.headers['x-nexe-retcode'], '0')
        self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_zapp_post(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'zapp-post',
                'exec': {'path': 'swift://a/c/exe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(prolis, '/v1/a/c/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = Request.blank('/open/a/c/myapp',
                                environ={'REQUEST_METHOD': 'POST'},
                                headers={
                                    'Content-Type': 'application/x-pickle'})
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            self.assertEqual(res.body, self.get_sorted_numbers())
            self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_zapp_post_error(self):

        def post_request():
            return Request.blank('/open/a/c/myapp1',
                                 environ={'REQUEST_METHOD': 'POST'},
                                 headers={
                                     'Content-Type': 'application/x-pickle'})

        self.setup_QUERY()
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        req = post_request()
        random_data = self.get_random_numbers()
        data = StringIO(random_data)
        req.body_file = data
        req.content_length = len(random_data)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 404)
        self.create_object(prolis, '/v1/a/c/myapp1', '')
        req = post_request()
        req.body_file = data
        req.content_length = len(random_data)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 501)
        self.create_object(prolis, '/v1/a/c/myapp1', 'a')
        req = post_request()
        req.body_file = data
        req.content_length = len(random_data)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 501)
        self.create_object(prolis, '/v1/a/c/myapp1', 'a',
                           content_type='application/x-tar')
        req = post_request()
        req.body_file = data
        req.content_length = len(random_data)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 501)
        self.create_object(prolis, '/v1/a/c/myapp1', 'bad gzip',
                           content_type='application/x-gzip')
        req = post_request()
        req.body_file = data
        req.content_length = len(random_data)
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 422)

    def test_zapp_put(self):
        self.setup_QUERY()
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        nexe = trim(r'''
            import json
            out = {
                'data': sorted(id),
                'env': zvm_environ
            }
            out = json.dumps(out)
            fp = open(mnfst.channels['/dev/output']['path'], 'wb')
            fp.write(out)
            fp.close()
            resp = '\n'.join([
                'Status: 201 Created',
                'Content-Type: text/html',
                '', ''
                ])
            return resp
            ''')
        self.create_object(prolis, '/v1/a/c/put.zapp', nexe)
        conf = [
            {
                'name': 'zapp-put',
                'exec': {'path': 'swift://a/c/put.zapp'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout',
                     'content_type': 'message/cgi'},
                    {'name': 'output',
                     'content_type': 'application/json',
                     'path': 'swift://./c/obj.json'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(prolis, '/v1/a/c/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = Request.blank('/open/a/c/myapp',
                                environ={'REQUEST_METHOD': 'PUT'},
                                headers={
                                    'Content-Type': 'application/x-pickle'})
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 201)
            for status in res.headers['x-nexe-status'].split(','):
                self.assertEqual(status, 'ok.')
            self.assertNotIn('x-nexe-error', res.headers)
            req = self.object_request('/v1/a/c/obj.json')
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            body = json.loads(res.body)
            self.assertEqual(pickle.dumps(body['data']),
                             self.get_sorted_numbers())
            self.assertEqual(body['env']['REQUEST_METHOD'], 'PUT')
            self.assertEqual(body['env']['REQUEST_URI'], '/open/a/c/myapp')
            self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_zapp_get(self):
        self.setup_QUERY()
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        nexe = trim(r'''
            import json
            import urlparse
            qs = zvm_environ['QUERY_STRING']
            params = dict(urlparse.parse_qsl(qs, True))
            start = int(params['start'])
            end = int(params['end'])
            out = {
                'data': sorted(id)[start:end],
                'env': zvm_environ
            }
            out = json.dumps(out)
            resp = '\n'.join([
                'Status: 200 OK',
                'Content-Type: application/json',
                '', ''
                ])
            return resp + out
            ''')
        self.create_object(prolis, '/v1/a/c/get.zapp', nexe)
        conf = [
            {
                'name': 'zapp-get',
                'exec': {'path': 'swift://a/c/get.zapp'},
                'devices': [
                    {'name': 'stdin',
                     'path': 'swift://./c_in1/input1'},
                    {'name': 'stdout',
                     'content_type': 'message/cgi'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(prolis, '/v1/a/c/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = Request.blank('/open/a/c/myapp',
                                environ={'REQUEST_METHOD': 'GET'},
                                headers={
                                    'Content-Type': 'application/x-pickle'})
            start = 1
            end = 5
            req.query_string = 'start=%d&end=%d' % (start, end)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            body = json.loads(res.body)
            self.assertEqual(pickle.dumps(body['data']),
                             self.get_sorted_numbers(start, end))
            self.assertEqual(body['env']['REQUEST_METHOD'], 'GET')
            self.assertEqual(body['env']['REQUEST_URI'],
                             '/open/a/c/myapp?start=%d&end=%d' % (start, end))
            self.assertEqual(body['env']['SCRIPT_NAME'], 'zapp-get')
            self.check_container_integrity(prosrv, '/v1/a/c', {})

    def test_zapp_head(self):
        self.setup_QUERY()
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        nexe = trim(r'''
            import json
            import urlparse
            qs = zvm_environ['QUERY_STRING']
            params = dict(urlparse.parse_qsl(qs, True))
            start = int(params['start'])
            end = int(params['end'])
            out = {
                'data': sorted(id)[start:end]
            }
            out = json.dumps(out)
            resp = '\n'.join([
                'Status: 200 OK',
                'Content-Type: application/json',
                'Content-Length: %d' % len(out),
                'X-Seq-Start: %d' % start,
                'X-Seq-End: %d' % end,
                '', ''
                ])
            return resp
            ''')
        self.create_object(prolis, '/v1/a/c/get.zapp', nexe)
        conf = [
            {
                'name': 'zapp-get',
                'exec': {'path': 'swift://a/c/get.zapp'},
                'devices': [
                    {'name': 'stdin',
                     'path': 'swift://./c_in1/input1'},
                    {'name': 'stdout',
                     'content_type': 'message/cgi'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(prolis, '/v1/a/c/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = Request.blank('/open/a/c/myapp',
                                environ={'REQUEST_METHOD': 'HEAD'},
                                headers={
                                    'Content-Type': 'application/x-pickle'})
            start = 1
            end = 5
            req.query_string = 'start=%d&end=%d' % (start, end)
            res = req.get_response(prosrv)
            self.executed_successfully(res)
            data = self.get_random_numbers()
            out = {
                'data': sorted(pickle.loads(data))[start:end]
            }
            out = json.dumps(out)
            self.assertEqual(res.content_length, len(out))
            self.assertEqual(res.headers['x-seq-start'], str(start))
            self.assertEqual(res.headers['x-seq-end'], str(end))
            self.check_container_integrity(prosrv, '/v1/a/c', {})


class TestAuthBase(unittest.TestCase, Utils):
    """Base class for tests for authorization, involving the
    ``X-Container-Meta-Zerovm-Suid`` container header.
    """

    def setUp(self):
        self.setup_QUERY()
        self.prolis = _test_sockets[0]
        nexe = trim(r'''
            return 'hello, world'
            ''')
        self.create_object(self.prolis, '/v1/a/auth/hello.nexe', nexe)
        self.actions = []
        self.zerovm_mock = None
        self.users = {'a': 'user', 'a1': 'user1'}

        self.proxy_server = _test_servers[0]
        self.remove_acls('/v1/a/auth')

    def tearDown(self):
        if self.zerovm_mock:
            os.unlink(self.zerovm_mock)

    def remove_acls(self, url):
        req = Request.blank(url,
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'X-Remove-Container-Read': 't',
                                     'X-Remove-Container-Write': 't'})
        req.environ['swift_owner'] = True
        res = req.get_response(_test_servers[0])
        self.assertEqual(res.status_int, 204)

    def set_acls(self, url, read=None, write=None):
        headers = {}
        if read:
            headers['X-Container-Read'] = read
        if write:
            headers['X-Container-Write'] = write
        req = Request.blank(url,
                            environ={'REQUEST_METHOD': 'POST'},
                            headers=headers)
        req.environ['swift_owner'] = True
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 204)

    def set_suid(self, container, suid):
        headers = {
            'X-Container-Meta-Zerovm-Suid': suid
        }
        req = Request.blank(container,
                            environ={'REQUEST_METHOD': 'POST'},
                            headers=headers)
        req.environ['swift_owner'] = True
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 204)

    def set_endpoint(self, container, endpoint, suid=None):
        # Typically, `Zerovm-Suid` must be set in conjunction with
        # `Rest-Endpoint`. So we can set both at the same time.
        headers = {
            'X-Container-Meta-Rest-Endpoint': endpoint,
        }
        if suid is not None:
            headers['X-Container-Meta-Zerovm-Suid'] = suid

        req = Request.blank(container,
                            environ={'REQUEST_METHOD': 'POST'},
                            headers=headers)
        req.environ['swift_owner'] = True
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 204)

    def remove_suid(self, url):
        headers = {
            'X-Remove-Container-Meta-Rest-Endpoint': 't',
            'X-Remove-Container-Meta-Zerovm-Suid': 't'
        }
        req = Request.blank(url,
                            environ={'REQUEST_METHOD': 'POST'},
                            headers=headers)
        req.environ['swift_owner'] = True
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 204)


class TestAuthPostJson(TestAuthBase):

    def test_post_owner(self):
        # test owner posts json
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a'])
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        self.check_container_integrity(self.proxy_server, '/v1/a/auth', {})
        self.assertEqual(
            ['Allowed Owner to POST swift://a with 1.0',
             'Allowed Owner to GET swift://a/auth/hello.nexe with 1.0'],
            self.actions)

    def test_post_other(self):
        # test other user posts json
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a1'])
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 403)
        self.assertTrue(res.body is not None)
        self.assertEqual(len(self.actions), 1)
        self.assertEqual(['Denied user1 to POST swift://a with 1.0'],
                         self.actions)

    def test_post_owner_read_other_with_perm(self):
        # test owner post json that reads object in another account,
        # and read permission is set
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        self.set_acls('/v1/a/auth', read='user1')
        req = self.zerovm_request(user=self.users['a1'])
        req.path_info = '/v1/a1'
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        self.assertEqual(
            ['Allowed Owner to POST swift://a1 with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0'],
            self.actions)

    def test_post_owner_read_other_no_perm(self):
        # test owner post json that reads object in another account,
        # and read permission is NOT set
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a1'])
        req.path_info = '/v1/a1'
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 403)
        self.assertTrue(res.body is not None)
        self.assertEqual(
            ['Allowed Owner to POST swift://a1 with 1.0',
             'Denied user1 to GET swift://a/auth/hello.nexe with 1.0'],
            self.actions)

    def test_post_owner_read_write_other_with_perm(self):
        # test owner post json that reads object in another account,
        # and read permission is set, it also writes to another object, and
        # write permission is set
        self.set_acls('/v1/a/auth', read='user1', write='user1')
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"},
                    {"device": "stderr",
                     "path": "swift://a/auth/hello.log"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a1'])
        req.path_info = '/v1/a1'
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        self.assertEqual(
            ['Allowed Owner to POST swift://a1 with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Allowed user1 to PUT swift://a/auth/hello.log with 1.0'],
            self.actions)

    def test_post_owner_read_write_other_no_perm(self):
        # test owner post json that reads object in another account,
        # and read permission is set, it also writes to another object, and
        # write permission is NOT set
        self.set_acls('/v1/a/auth', read='user1')
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"},
                    {"device": "stderr",
                     "path": "swift://a/auth/hello.log"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a1'])
        req.path_info = '/v1/a1'
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 403)
        self.assertTrue(res.body is not None)
        self.assertEqual(
            ['Allowed Owner to POST swift://a1 with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Denied user1 to PUT swift://a/auth/hello.log with 1.0'],
            self.actions)

    def test_post_owner_read_local_read_write_remote(self):
        # test owner post json that reads object locally, another object
        # remotely and writes yet another object
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"},
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {"device": "stderr",
                     "path": "swift://a/auth/hello.log"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a'])
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        self.assertEqual(
            ['Allowed Owner to POST swift://a with 1.0',
             'Allowed Owner to POST swift://a/c/o with 1.0',
             'Allowed Owner to GET swift://a/auth/hello.nexe with 1.0',
             'Allowed Owner to PUT swift://a/auth/hello.log with 1.0'],
            self.actions)

    def test_post_owner_read_local_read_write_remote_other(self):
        # test owner post json that reads object from other account locally,
        # reads another object from other account remotely and writes yet
        # another object from other account, and NO permissions are set
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"},
                    {'device': 'stdin', 'path': 'swift://a/c/o'},
                    {"device": "stderr",
                     "path": "swift://a/auth/hello.log"}
                ]
            }
        ]
        conf = json.dumps(conf)
        self.set_acls('/v1/a/auth', read='user1', write='user1')
        req = self.zerovm_request(user=self.users['a1'])
        req.path_info = '/v1/a1'
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 403)
        self.assertTrue(res.body is not None)
        self.assertEqual(
            ['Allowed Owner to POST swift://a1 with 1.0',
             'Denied user1 to POST swift://a/c/o with 1.0'],
            self.actions)

    def test_post_owner_read_local_read_write_remote_other_with_perm(self):
        # test owner post json that reads object from other account locally,
        # reads another object from other account remotely and writes yet
        # another object from other account, and permissions are set for
        # both read and write
        self.set_acls('/v1/a/auth', read='user1', write='user1')
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"},
                    {'device': 'stdin',
                     'path': 'swift://a/auth/hello.nexe'},
                    {"device": "stderr",
                     "path": "swift://a/auth/hello.log"}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a1'])
        req.path_info = '/v1/a1'
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 500)
        self.assertTrue(res.body is not None)
        self.assertEqual(
            ['Allowed Owner to POST swift://a1 with 1.0',
             'Allowed user1 to POST swift://a/auth/hello.nexe with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Allowed user1 to PUT swift://a/auth/hello.log with 1.0'],
            self.actions)

    def test_post_owner_read_same_object_twice_with_perm(self):
        # test owner post json that writes object to other account locally,
        # reads another object from other account remotely and reads the
        # same object from other account remotely on other channel, although
        # the permissions are good the call will fail because it's not
        # a valid call (same object referenced twice in remote context)
        self.set_acls('/v1/a/auth', read='user1', write='user1')
        conf = [
            {
                "name": "hello",
                "exec": {"path": "swift://a/auth/hello.nexe"},
                "file_list": [
                    {"device": "stdout"},
                    {'device': 'stdin',
                     'path': 'swift://a/auth/hello.nexe'},
                    {"device": "stderr",
                     "path": "swift://a/auth/hello.log"}
                ],
                "attach": "stderr"
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request(user=self.users['a1'])
        req.path_info = '/v1/a1'
        req.body = conf
        res = req.get_response(self.proxy_server)
        self.assertEqual(res.status_int, 400)
        self.assertTrue(res.body is not None)
        self.assertEqual(
            ['Allowed Owner to POST swift://a1 with 1.0',
             'Allowed user1 to POST swift://a/auth/hello.log with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0'],
            self.actions)


class TestAuthXSource(TestAuthBase):

    def test_x_source_with_setuid(self):
        # test an app called by other user from x-zerovm-source with set-uid
        # permission set
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid='user1')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'stderr', 'path': 'swift://a/auth/hello.log'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = self.zerovm_request(user=self.users['a1'])
            req.headers['x-zerovm-source'] = 'swift://a/auth/myapp'
            req.headers['content-type'] = 'application/x-pickle'
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(self.proxy_server)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, 'hello, world')
        self.assertEqual(
            ['Denied user1 to GET swift://a/auth/myapp with v1',
             'Allowed user1 to GET swift://a/auth/myapp with v1',
             'Denied user1 to POST swift://a with 1.0',
             'Allowed user1 to POST swift://a with 1.0',
             'Denied user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Denied user1 to PUT swift://a/auth/hello.log with 1.0',
             'Allowed user1 to PUT swift://a/auth/hello.log with 1.0'],
            self.actions)

    def test_x_source_with_read_setuid_and_no_write_setuid(self):
        # test an app called by other user from x-zerovm-source with set-uid
        # permission set and NO set-uid permission set on writeable channel
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid='user1')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'stderr', 'path': 'swift://a/auth1/hello.log'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = self.zerovm_request(user=self.users['a1'])
            req.headers['x-zerovm-source'] = 'swift://a/auth/myapp'
            req.headers['content-type'] = 'application/x-pickle'
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(self.proxy_server)
            self.assertEqual(res.status_int, 403)
            self.assertTrue(res.body is not None)
        self.assertEqual(
            ['Denied user1 to GET swift://a/auth/myapp with v1',
             'Allowed user1 to GET swift://a/auth/myapp with v1',
             'Denied user1 to POST swift://a with 1.0',
             'Allowed user1 to POST swift://a with 1.0',
             'Denied user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Denied user1 to PUT swift://a/auth1/hello.log with 1.0'],
            self.actions)

    def test_x_source_with_read_setuid_and_write_setuid(self):
        # test an app called by other user from x-zerovm-source with set-uid
        # permission set and set-uid permission set on writeable channel
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid='user1')
        self.set_endpoint('/v1/a/auth1', 'swift://a/auth/myapp', suid='user1')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'stderr', 'path': 'swift://a/auth1/hello.log'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = self.zerovm_request(user=self.users['a1'])
            req.headers['x-zerovm-source'] = 'swift://a/auth/myapp'
            req.headers['content-type'] = 'application/x-pickle'
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(self.proxy_server)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, 'hello, world')
        self.assertEqual(
            ['Denied user1 to GET swift://a/auth/myapp with v1',
             'Allowed user1 to GET swift://a/auth/myapp with v1',
             'Denied user1 to POST swift://a with 1.0',
             'Allowed user1 to POST swift://a with 1.0',
             'Denied user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Allowed user1 to GET swift://a/auth/hello.nexe with 1.0',
             'Denied user1 to PUT swift://a/auth1/hello.log with 1.0',
             'Allowed user1 to PUT swift://a/auth1/hello.log with 1.0'],
            self.actions)

    def test_x_source_with_setuid_for_other_object(self):
        # test an app called by other user from x-zerovm-source with set-uid
        # permission set for different x-zerovm-source header
        self.remove_suid('/v1/a/auth1')
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp1', suid='user1')
        conf = [
            {
                'name': 'sort',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'stderr', 'path': 'swift://a/auth/hello.log'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = self.zerovm_request(user=self.users['a1'])
            req.headers['x-zerovm-source'] = 'swift://a/auth/myapp'
            req.headers['content-type'] = 'application/x-pickle'
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(self.proxy_server)
            self.assertEqual(res.status_int, 403)
            self.assertTrue(res.body is not None)
        self.assertEqual(
            ['Denied user1 to GET swift://a/auth/myapp with v1'],
            self.actions)


class TestAuthOpen(TestAuthBase):
    """Authorization tests using the open/1.0 execution method.
    """

    def test_open_owner(self):
        # test an open call to app by owner
        self.remove_suid('/v1/a/auth')
        self.remove_suid('/v1/a/auth1')
        conf = [
            {
                'name': 'zapp-post',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'}
                ]
            }
        ]
        conf = json.dumps(conf)
        sysmap = StringIO(conf)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/c/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')
            req = Request.blank('/open/a/c/myapp',
                                environ={'REQUEST_METHOD': 'POST'},
                                headers={
                                    'Content-Type': 'application/x-pickle'})
            self.add_auth_data(req, 'user')
            random_data = self.get_random_numbers()
            data = StringIO(random_data)
            req.body_file = data
            req.content_length = len(random_data)
            res = req.get_response(self.proxy_server)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, 'hello, world')
            self.assertEqual(
                ['Allowed Owner to GET swift://a/c/myapp with open/1.0',
                 'Allowed Owner to GET swift://a/c/myapp with v1',
                 'Allowed Owner to POST swift://a/c/myapp with open/1.0',
                 'Allowed Owner to GET swift://a/auth/hello.nexe with '
                 'open/1.0'],
                self.actions)


class TestAuthApi(TestAuthBase):
    """Authorization tests using the api/1.0 execution method.
    """

    def setUp(self):
        # This will create for us the 'hello.nexe' executable at
        # swift://a/auth/hello.nexe
        super(TestAuthApi, self).setUp()
        self.sysmap = StringIO(json.dumps([
            {
                'name': 'zapp',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'}
                ]
            }
        ]))
        with self.create_tar({CLUSTER_CONFIG_FILENAME: self.sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')

        # Set up the client request
        random_data = self.get_random_numbers()
        data = StringIO(random_data)
        # NOTE(larsbutler): The method doesn't really matter.
        method = 'DELETE'
        self.req = Request.blank(
            '/api/a/auth',
            environ={'REQUEST_METHOD': method},
            headers={'Content-Type': 'application/x-pickle'}
        )
        self.req.body_file = data
        self.req.content_length = len(random_data)

        self.create_container(self.prolis, '/v1/a/test')
        self.create_container(self.prolis, '/v1/a/test2')
        self.request_user = None

    def _get_response(self):
        # Helper to actually execute the client request, and return the http
        # response.
        self.assertIsNotNone(self.request_user)
        self.add_auth_data(self.req, self.request_user)
        return self.req.get_response(self.proxy_server)

    def tearDown(self):
        super(TestAuthApi, self).tearDown()
        self.remove_acls('/v1/a/auth')
        self.remove_acls('/v1/a/test')
        self.remove_acls('/v1/a/test2')
        self.remove_suid('/v1/a/auth')
        self.remove_suid('/v1/a/test')
        self.remove_suid('/v1/a/test2')

    def assertActionsEqual(self, expected, actual):
        expected = [x % dict(ru=self.request_user) for x in expected]
        self.assertEqual(expected, actual)


class ApiAuthTestsMixin:
    """Template mixin containing api/1.0 auth test procedures.

    Subclasses should inherit from TestAuthApi and this, then set
    `self.request_user` and `self.suid` in `setUp()`.
    """

    def test_execute(self):
        # Test an api call to `auth` container by a user other than the owner.
        # Setuid permissions are used to grant this user access.
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp',
                          suid=self.suid)

        res = self._get_response()
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0'
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_no_perm(self):
        # Test an api call to `auth` container by a user other than the owner.
        # Setuid permissions are not set for this user, so execution is denied.
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid='')

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_read_other_object(self):
        # Test an api call to the `auth` container by a user other than the
        # owner. The application executed reads from an object in a separate
        # container.
        # Setuid permissions are set on both containers to allow execution.
        self.sysmap = StringIO(json.dumps([
            {
                'name': 'zapp',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'input', 'path': 'swift://a/test/foo.txt'},
                ]
            }
        ]))
        with self.create_tar({CLUSTER_CONFIG_FILENAME: self.sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')

        self.create_object(self.prolis, '/v1/a/test/foo.txt', 'foobar')

        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp',
                          suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp',
                          suid=self.suid)

        res = self._get_response()
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to POST swift://a/test/foo.txt with api/1.0',
            'Allowed %(ru)s to POST swift://a/test/foo.txt with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0'
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_read_other_object_no_perm(self):
        # Test an api call to the `auth` container by a user other than the
        # owner. The application executed reads from an object in a separate
        # container.
        # Setuid permissions are set to allow execution on the app, but the
        # container with the object to be read does not allow suid to the
        # requestor.
        self.sysmap = StringIO(json.dumps([
            {
                'name': 'zapp',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'input', 'path': 'swift://a/test/foo.txt'},
                ]
            }
        ]))
        with self.create_tar({CLUSTER_CONFIG_FILENAME: self.sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')

        self.create_object(self.prolis, '/v1/a/test/foo.txt', 'foobar')

        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp',
                          suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp')

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to POST swift://a/test/foo.txt with api/1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_write_other_object(self):
        self.sysmap = StringIO(json.dumps([
            {
                'name': 'zapp',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'output', 'path': 'swift://a/test/bar.txt'},
                ]
            }
        ]))
        with self.create_tar({CLUSTER_CONFIG_FILENAME: self.sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')

        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp',
                          suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp',
                          suid=self.suid)

        res = self._get_response()
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0',
            'Denied %(ru)s to PUT swift://a/test/bar.txt with api/1.0',
            'Allowed %(ru)s to PUT swift://a/test/bar.txt with api/1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_write_other_object_no_perm(self):
        self.sysmap = StringIO(json.dumps([
            {
                'name': 'zapp',
                'exec': {'path': 'swift://a/auth/hello.nexe'},
                'devices': [
                    {'name': 'stdin'},
                    {'name': 'stdout'},
                    {'name': 'output', 'path': 'swift://a/test/bar.txt'},
                ]
            }
        ]))
        with self.create_tar({CLUSTER_CONFIG_FILENAME: self.sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')

        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp',
                          suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp')

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/hello.nexe '
            'with api/1.0',
            'Denied %(ru)s to PUT swift://a/test/bar.txt with api/1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)


class TestAuthApiCallByOwner(TestAuthApi):

    def setUp(self):
        super(TestAuthApiCallByOwner, self).setUp()
        self.request_user = 'user'

    def test_api_call_by_owner(self):
        # Test an api call to `auth` container by the user who owns it.
        # No setuid permission is required for this to be allowed.
        # An authenticated user can do anything with their own containers,
        # applications, and objects.
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid='')

        res = self._get_response()

        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, 'hello, world')

        expected_actions = [
            'Allowed Owner to GET swift://a/auth/myapp with api/1.0',
            'Allowed Owner to GET swift://a/auth/myapp with v1',
            # TODO(larsbutler): Why is this always a POST, despite the request
            # method above?
            'Allowed Owner to POST swift://a/auth with api/1.0',
            'Allowed Owner to GET swift://a/auth/hello.nexe '
            'with api/1.0'
        ]
        self.assertEqual(expected_actions, self.actions)


class ApiAuthChainTestsMixin:
    """Template mixin containing api/1.0 auth test procedures, which include
    job chaining.

    Subclasses should inherit from TestAuthApi and this, then set
    `self.request_user` and `self.suid` in `setUp()`.
    """

    def _setup_chain_test(self, extra_devices=None):
        self.create_container(self.prolis, '/v1/a/auth')
        self.create_container(self.prolis, '/v1/a/test')
        self.create_container(self.prolis, '/v1/a/test2')

        if extra_devices is None:
            extra_devices = []

        nexe2_conf = [
            {
                'name': 'http',
                'exec': {'path': 'swift://a/test/nexe2'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http',
                    },
                ]
            }
        ]
        for ed in extra_devices:
            nexe2_conf[0]['file_list'].append(ed)

        chainer_nexe = trim(r'''
            import json
            conf = %(nexe2_conf)s
            out = json.dumps(conf)
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: application/json',
                'X-Zerovm-Execute: 1.0',
                '', ''
                ])
            return resp + out
            ''' % dict(nexe2_conf=json.dumps(nexe2_conf)))
        self.create_object(self.prolis, '/v1/a/auth/chainer', chainer_nexe)
        nexe2 = trim(r'''
            resp = '\n'.join([
                'HTTP/1.1 200 OK',
                'Content-Type: text/html',
                'X-Object-Meta-Key1: value1',
                'X-Object-Meta-Key2: value2',
                '', ''
                ])
            out = '<html><body>Test this</body></html>'
            return resp + out
            ''')
        self.create_object(self.prolis, '/v1/a/test/nexe2', nexe2)
        self.sysmap = StringIO(json.dumps([
            {
                'name': 'http',
                'exec': {'path': 'swift://a/auth/chainer'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'message/http'
                    }
                ]
            }
        ]))
        with self.create_tar({CLUSTER_CONFIG_FILENAME: self.sysmap}) as tar:
            self.create_object(self.prolis, '/v1/a/auth/myapp',
                               open(tar, 'rb').read(),
                               content_type='application/x-tar')

        # Set up the client request
        random_data = self.get_random_numbers()
        data = StringIO(random_data)
        # NOTE(larsbutler): The method doesn't really matter.
        method = 'DELETE'
        self.req = Request.blank(
            '/api/a/auth',
            environ={'REQUEST_METHOD': method},
            headers={'Content-Type': 'application/x-pickle'}
        )
        self.req.body_file = data
        self.req.content_length = len(random_data)

    def test_execute(self):
        self._setup_chain_test()
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)

        res = self._get_response()
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Allowed %(ru)s to GET swift://a/test/nexe2 with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_no_perm(self):
        self._setup_chain_test()
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        # don't grant suid on `test` container, where `nexe2` resides
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp')

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to GET swift://a/test/nexe2 with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_read_other_object(self):
        # the chain-called `nexe2` reads from an object in a third container
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test2', 'swift://a/auth/myapp',
                          suid=self.suid)
        self.create_object(self.prolis, '/v1/a/test2/baz.txt', 'baz')

        self._setup_chain_test(extra_devices=[
            {'name': 'input', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to POST swift://a/test2/baz.txt with 1.0',
            'Allowed %(ru)s to POST swift://a/test2/baz.txt with 1.0',
            'Denied %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Allowed %(ru)s to GET swift://a/test/nexe2 with 1.0'
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_read_other_object_no_perm_1(self):
        # neither endpoint nor suid is set on the test file read by the
        # chain-called `nexe2`
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)
        self.create_object(self.prolis, '/v1/a/test2/baz.txt', 'baz')

        self._setup_chain_test(extra_devices=[
            {'name': 'input', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to POST swift://a/test2/baz.txt with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_read_other_object_no_perm_2(self):
        # suid is set on the test file read by the chain-called nexe2,
        # but no endpoint is set
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)
        self.set_suid('/v1/a/test2', self.suid)
        self.create_object(self.prolis, '/v1/a/test2/baz.txt', 'baz')

        self._setup_chain_test(extra_devices=[
            {'name': 'input', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to POST swift://a/test2/baz.txt with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_read_other_object_no_perm_3(self):
        # endpoint is set on the test file read by the chain-called nexe2,
        # but no suid is set
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test2', 'swift://a/auth/myapp', suid='')
        self.create_object(self.prolis, '/v1/a/test2/baz.txt', 'baz')

        self._setup_chain_test(extra_devices=[
            {'name': 'input', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to POST swift://a/test2/baz.txt with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_write_other_object(self):
        # the chain-called `nexe2` writes to an object in a third container
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test2', 'swift://a/auth/myapp',
                          suid=self.suid)

        self._setup_chain_test(extra_devices=[
            {'name': 'output', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Allowed %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Denied %(ru)s to PUT swift://a/test2/baz.txt with 1.0',
            'Allowed %(ru)s to PUT swift://a/test2/baz.txt with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_write_other_object_no_perm_1(self):
        # neither endpoint nor suid is set on the test file read by the
        # chain-called `nexe2`
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)

        self._setup_chain_test(extra_devices=[
            {'name': 'output', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Allowed %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Denied %(ru)s to PUT swift://a/test2/baz.txt with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_write_other_object_no_perm_2(self):
        # suid is set on the test file read by the chain-called nexe2,
        # but no endpoint is set
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)
        self.set_suid('/v1/a/test2', self.suid)

        self._setup_chain_test(extra_devices=[
            {'name': 'output', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Allowed %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Denied %(ru)s to PUT swift://a/test2/baz.txt with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)

    def test_execute_write_other_object_no_perm_3(self):
        # endpoint is set on the test file read by the chain-called nexe2,
        # but no suid is set
        self.set_endpoint('/v1/a/auth', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test', 'swift://a/auth/myapp', suid=self.suid)
        self.set_endpoint('/v1/a/test2', 'swift://a/auth/myapp', suid='')

        self._setup_chain_test(extra_devices=[
            {'name': 'output', 'path': 'swift://a/test2/baz.txt'},
        ])

        res = self._get_response()
        self.assertEqual(res.status_int, 403)
        expected_actions = [
            'Denied %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/myapp with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/myapp with v1',
            'Allowed %(ru)s to GET swift://a/auth/myapp with v1',
            'Denied %(ru)s to POST swift://a/auth with api/1.0',
            'Allowed %(ru)s to POST swift://a/auth with api/1.0',
            'Denied %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Allowed %(ru)s to GET swift://a/auth/chainer with api/1.0',
            'Denied %(ru)s to POST swift://a with 1.0',
            'Allowed %(ru)s to POST swift://a with 1.0',
            'Denied %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Allowed %(ru)s to GET swift://a/test/nexe2 with 1.0',
            'Denied %(ru)s to PUT swift://a/test2/baz.txt with 1.0',
        ]
        self.assertActionsEqual(expected_actions, self.actions)


class TestAuthApiCallByOther(TestAuthApi, ApiAuthTestsMixin):
    """Run tests using the `user1` as the request user. `user` owns the
    resources in these tests, and grants/denies access to `user1` by
    setting/not setting Rest-Endpoint and Zerovm-Suid headers on containers.
    """

    def setUp(self):
        super(TestAuthApiCallByOther, self).setUp()
        self.request_user = 'user1'
        self.suid = 'user1'


class TestAuthApiCallByAnonymous(TestAuthApi, ApiAuthTestsMixin):
    """Run tests using an anonymous user as the request user. `user` owns the
    resources in these tests, and grants/denies access to anonymous user by
    setting/not setting Rest-Endpoint and Zerovm-Suid headers on containers.
    """

    def setUp(self):
        super(TestAuthApiCallByAnonymous, self).setUp()
        self.create_container(self.prolis, '/v1/a/test')
        self.request_user = 'Anonymous'
        self.suid = '.r:*'


class TestAuthApiChainCallByOther(TestAuthApi, ApiAuthChainTestsMixin):

    def setUp(self):
        super(TestAuthApiChainCallByOther, self).setUp()
        self.request_user = 'user1'
        self.suid = 'user1'


class TestAuthApiChainCallByAnonymous(TestAuthApi, ApiAuthChainTestsMixin):

    def setUp(self):
        super(TestAuthApiChainCallByAnonymous, self).setUp()
        self.request_user = 'Anonymous'
        self.suid = '.r:*'
