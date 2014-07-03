from __future__ import with_statement
from StringIO import StringIO
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
from swift.common.swob import Request, HTTPUnauthorized
from hashlib import md5
from tempfile import mkstemp, mkdtemp
from shutil import rmtree

from nose import SkipTest
from eventlet import sleep, spawn, wsgi, listen, GreenPool
from gzip import GzipFile
from contextlib import contextmanager

from swift.proxy import server as proxy_server
from swift.account import server as account_server
from swift.container import server as container_server
from swift.obj import server as object_server
from swift.common.utils import mkdirs, normalize_timestamp, NullLogger
from swift.common import utils

from zerocloud import proxyquery, objectquery
from test.unit import connect_tcp, readuntil2crlfs, fake_http_connect, trim, \
    debug_logger, FakeMemcache, write_fake_ring, FakeRing
from zerocloud.common import CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME
from zerocloud.configparser import ClusterConfigParser, \
    ClusterConfigParsingError

try:
    import simplejson as json
except ImportError:
    import json

ZEROVM_DEFAULT_MOCK = 'test/unit/zerovm_mock.py'

logging.getLogger().addHandler(logging.StreamHandler(sys.stdout))

STATIC_TIME = time()
_test_coros = _test_servers = _test_sockets = _orig_container_listing_limit = \
    _testdir = _orig_SysLogHandler = _orig_POLICIES = _test_POLICIES = None


class FakeMemcacheReturnsNone(FakeMemcache):

    def get(self, key):
        # Returns None as the timestamp of the container; assumes we're only
        # using the FakeMemcache for container existence checks.
        return None


def do_setup(the_object_server):
    utils.HASH_PATH_SUFFIX = 'endcap'
    global _testdir, _test_servers, _test_sockets, \
        _orig_container_listing_limit, _test_coros, _orig_SysLogHandler, \
        _orig_POLICIES, _test_POLICIES
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
    obj_ring_path = os.path.join(_testdir, 'object.ring.gz')
    obj_devs = [
        {'port': obj1lis.getsockname()[1]},
        {'port': obj2lis.getsockname()[1]},
    ]
    write_fake_ring(obj_ring_path, *obj_devs)
    prosrv = proxy_server.Application(conf, FakeMemcacheReturnsNone(),
                                      logger=debug_logger('proxy'))
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
    nl = NullLogger()
    logging_prosv = proxy_logging.ProxyLoggingMiddleware(pqm, conf,
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
        (pqm, acc1srv, acc2srv, cqm1, cqm2, oqm1, oqm2)
    _test_coros = \
        (prospa, acc1spa, acc2spa, con1spa, con2spa, obj1spa, obj2spa)
    # Create account
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
    # Create containers
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


def setup():
    do_setup(object_server)


def teardown():
    for server in _test_coros:
        server.kill()
    rmtree(os.path.dirname(_testdir))
    utils.SysLogHandler = _orig_SysLogHandler


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


class TestProxyQuery(unittest.TestCase):

    def setUp(self):
        self.proxy_app = \
            proxy_server.Application(None, FakeMemcache(),
                                     logger=debug_logger('proxy-ut'),
                                     account_ring=FakeRing(),
                                     container_ring=FakeRing(),
                                     object_ring=FakeRing())

        self.zerovm_mock = None

    def tearDown(self):
        if self.zerovm_mock:
            os.unlink(self.zerovm_mock)

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

    def zerovm_request(self):
        req = Request.blank('/v1/a',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/json',
                                     'x-zerovm-execute': '1.0'})
        return req

    def zerovm_tar_request(self):
        req = Request.blank('/v1/a',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/x-gtar',
                                     'x-zerovm-execute': '1.0'})
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
        prosrv = _test_servers[0]
        _con1srv = _test_servers[3]
        _con2srv = _test_servers[4]
        _obj1srv = _test_servers[5]
        _obj2srv = _test_servers[6]
        zerovm_sysimage_devices = prosrv.zerovm_sysimage_devices
        zerovm_sysimage_devices1 = _obj1srv.parser.sysimage_devices
        zerovm_sysimage_devices2 = _obj2srv.parser.sysimage_devices
        zerovm_sysimage_devices3 = _con1srv.parser.sysimage_devices
        zerovm_sysimage_devices4 = _con2srv.parser.sysimage_devices
        prosrv.zerovm_sysimage_devices = {name: None}
        _con1srv.parser.sysimage_devices = {name: sysimage_path}
        _con2srv.parser.sysimage_devices = {name: sysimage_path}
        _obj1srv.parser.sysimage_devices = {name: sysimage_path}
        _obj2srv.parser.sysimage_devices = {name: sysimage_path}
        try:
            yield True
        finally:
            prosrv.zerovm_sysimage_devices = zerovm_sysimage_devices
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
        self.assertEqual(len(objdict), 0)

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
                req.content_length = os.path.getsize(tar)
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
        self.assertNotIn('x-object-meta-key1', res.headers)
        self.assertNotIn('x-object-meta-key2', res.headers)
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
        self.assertIn('name=CONTENT_TYPE, value=application/x-pickle', out)
        self.assertIn('name=HTTP_X_OBJECT_META_KEY1, value=val1', out)
        self.assertIn('name=HTTP_X_OBJECT_META_KEY2, value=val2', out)
        self.assertIn('name=DOCUMENT_ROOT, value=/dev/stdout', out)
        self.assertIn('name=PATH_INFO, value=/a/c/o3', out)
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
        self.assertIn('name=CONTENT_TYPE, value=application/x-pickle', out)
        self.assertIn('name=HTTP_X_OBJECT_META_KEY1, value=val1', out)
        self.assertIn('name=HTTP_X_OBJECT_META_KEY2, value=val2', out)
        self.assertIn('name=DOCUMENT_ROOT, value=/dev/stdin', out)
        self.assertIn('name=PATH_INFO, value=/a/c/o3', out)
        self.assertIn('name=CONTENT_LENGTH, value=%d' % content_length, out)
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
        self.assertIn('name=CONTENT_TYPE, value=application/x-pickle', out)
        self.assertIn('name=HTTP_X_OBJECT_META_KEY1, value=val1', out)
        self.assertIn('name=HTTP_X_OBJECT_META_KEY2, value=val2', out)
        self.assertIn('name=DOCUMENT_ROOT, value=/dev/stdin', out)
        self.assertIn('name=PATH_INFO, value=/a/c/o3', out)
        self.assertIn('name=CONTENT_LENGTH, value=%d' % content_length, out)
        self.assertIn('name=SCRIPT_NAME, value=http_script', out)
        self.assertIn('name=SCRIPT_FILENAME, value=swift://a/c/exe2', out)
        self.check_container_integrity(prosrv, '/v1/a/c', {})

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
        req = Request.blank(
            '/open/a/c/exe2?' + urlencode({'content_type': 'text/html'}))
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.create_object(
            prolis, '/v1/a/c/my.nexe', nexe, content_type='application/x-nexe')
        req = Request.blank(
            '/open/a/c/my.nexe?' + urlencode({'content_type': 'text/html'}))
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
        self.create_container(prolis, '/v1/a/%s' % prosrv.zerovm_registry_path)
        self.create_object(prolis, '/v1/a/%s/%s'
                                   % (prosrv.zerovm_registry_path,
                                      'application/octet-stream/config'),
                           conf, content_type='application/json')
        req = Request.blank('/open/a/c/o')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['content-type'], 'application/x-pickle')
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
        orig_timeout = prosrv.immediate_response_timeout
        prosrv.immediate_response_timeout = 0.5
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
        prosrv.immediate_response_timeout = orig_timeout

    def test_deferred_with_obj(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        orig_timeout = prosrv.immediate_response_timeout
        prosrv.immediate_response_timeout = 0.5
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
        prosrv.immediate_response_timeout = orig_timeout

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
        pattern = '/dev/out/([^\s]+)\', \'tcp://127.0.0.1:\d+'
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

    def test_QUERY_calls_authorize(self):
        # there is no pre-authorization right now, maybe we do not need it at
        # all
        raise SkipTest
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
        orig_upload_time = prosrv.max_upload_time
        with save_globals():
            proxy_server.http_connect = \
                fake_http_connect(200, 200, 201, 201, 201)
            prosrv.max_upload_time = 1
            req = self.zerovm_request()
            req.body_file = SlowFile()
            req.content_length = 100
            res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 408)
        prosrv.max_upload_time = orig_upload_time

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
        self.assertEqual(res.body, 'Unknown device stdtest in sort')
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
            self.assertEqual(res.body, ('Could not resolve channel path: '
                                        'swift://a/%s' % path) * 2)
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
        # controller = prosrv.get_controller('a', None, None)
        # error = controller.parse_cluster_config(req, conf)
        # self.assertIsNone(error)
        # self.assertEqual(len(controller.nodes), 8)
        # for name, node in controller.nodes.iteritems():
        #     self.assertEqual(node.replicate, 1)
        #     self.assertEqual(node.replicas, [])
        # print json.dumps(controller.nodes, sort_keys=True, indent=2,
        # cls=proxyquery.NodeEncoder)

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
        try:
            parser = ClusterConfigParser(pqm.zerovm_sysimage_devices,
                                         pqm.zerovm_content_type,
                                         pqm.parser_config,
                                         pqm.list_account,
                                         pqm.list_container,
                                         network_type='opaque')
            parser.parse(conf, False, request=req)
        except ClusterConfigParsingError:
            self.assertTrue(False, msg='ClusterConfigParsingError is raised')
        self.assertEqual(len(parser.nodes), 5)
        for n in parser.node_list:
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
        orig_network_type = prosrv.network_type
        orig_repl = prosrv.ignore_replication
        try:
            prosrv.network_type = 'opaque'
            prosrv.ignore_replication = True
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
            prosrv.network_type = orig_network_type
            prosrv.ignore_replication = orig_repl

    def test_container_query(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = trim(r'''
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
        if hasattr(prosrv.app, 'strict_cors_mode'):
            self.assertTrue(prosrv.app.strict_cors_mode)
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
        #     prosrv.app.strict_cors_mode = False
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
        #     prosrv.app.strict_cors_mode = True
