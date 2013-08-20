from __future__ import with_statement
from StringIO import StringIO
import re
import struct
from eventlet.green import socket
import tarfile
import datetime
import random
from urllib import urlencode
import swift

import unittest
import os
import cPickle as pickle
from time import time, sleep
from swift.common.swob import Request, HTTPNotFound, HTTPUnauthorized
from hashlib import md5
from tempfile import mkstemp, mkdtemp
from shutil import rmtree

from nose import SkipTest
from httplib import HTTPException
from eventlet import sleep, spawn, Timeout, util, wsgi, listen, GreenPool
from gzip import GzipFile
from contextlib import contextmanager

from swift.proxy import server as proxy_server
from swift.account import server as account_server
from swift.container import server as container_server
from swift.obj import server as object_server
from swift.common.utils import mkdirs, normalize_timestamp, NullLogger
from swift.common.wsgi import monkey_patch_mimetools
from swift.common import ring

from zerocloud import proxyquery, objectquery
from test.unit import connect_tcp, readuntil2crlfs, FakeLogger, fake_http_connect
from zerocloud.common import CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME

try:
    import simplejson as json
except ImportError:
    import json

ZEROVM_DEFAULT_MOCK = 'test/unit/zerovm_mock.py'

class FakeRing(object):

    def __init__(self, replicas=3):
        # 9 total nodes (6 more past the initial 3) is the cap, no matter if
        # this is set higher, or R^2 for R replicas
        self.replicas = replicas
        self.max_more_nodes = 0
        self.devs = {}

    def set_replicas(self, replicas):
        self.replicas = replicas
        self.devs = {}

    @property
    def replica_count(self):
        return self.replicas

    def get_part(self, account, container=None, obj=None):
        return 1

    def get_nodes(self, account, container=None, obj=None):
        devs = []
        for x in xrange(self.replicas):
            devs.append(self.devs.get(x))
            if devs[x] is None:
                self.devs[x] = devs[x] = \
                    {'ip': '10.0.0.%s' % x,
                     'port': 1000 + x,
                     'device': 'sd' + (chr(ord('a') + x)),
                     'id': x}
        return 1, devs

    def get_part_nodes(self, part):
        return self.get_nodes('blah')[1]

    def get_more_nodes(self, nodes):
        # replicas^2 is the true cap
        for x in xrange(self.replicas, min(self.replicas + self.max_more_nodes,
                                           self.replicas * self.replicas)):
            yield {'ip': '10.0.0.%s' % x, 'port': 1000 + x, 'device': 'sda'}


class FakeMemcache(object):

    def __init__(self):
        self.store = {}

    def get(self, key):
        return self.store.get(key)

    def keys(self):
        return self.store.keys()

    def set(self, key, value, time=0):
        self.store[key] = value
        return True

    def incr(self, key, time=0):
        self.store[key] = self.store.setdefault(key, 0) + 1
        return self.store[key]

    @contextmanager
    def soft_lock(self, key, timeout=0, retries=5):
        yield True

    def delete(self, key):
        try:
            del self.store[key]
        except Exception:
            pass
        return True


class FakeMemcacheReturnsNone(FakeMemcache):

    def get(self, key):
        # Returns None as the timestamp of the container; assumes we're only
        # using the FakeMemcache for container existence checks.
        return None


def setup():
    global _testdir, _test_servers, _test_sockets,\
    _orig_container_listing_limit, _test_coros
    #monkey_patch_mimetools()
    # Since we're starting up a lot here, we're going to test more than
    # just chunked puts; we're also going to test parts of
    # proxy_server.Application we couldn't get to easily otherwise.
    _testdir = os.path.join(mkdtemp(), 'tmp_test_proxy_server_chunked')
    mkdirs(_testdir)
    rmtree(_testdir)
    mkdirs(os.path.join(_testdir, 'sda1'))
    mkdirs(os.path.join(_testdir, 'sda1', 'tmp'))
    mkdirs(os.path.join(_testdir, 'sdb1'))
    mkdirs(os.path.join(_testdir, 'sdb1', 'tmp'))
    _orig_container_listing_limit = \
        swift.proxy.controllers.obj.CONTAINER_LISTING_LIMIT
    prolis = listen(('localhost', 0))
    acc1lis = listen(('localhost', 0))
    acc2lis = listen(('localhost', 0))
    con1lis = listen(('localhost', 0))
    con2lis = listen(('localhost', 0))
    obj1lis = listen(('localhost', 0))
    obj2lis = listen(('localhost', 0))
    conf = {'devices': _testdir, 'swift_dir': _testdir,
            'mount_check': 'false', 'allowed_headers':
        'content-encoding, x-object-manifest, content-disposition, foo',
            'disable_fallocate': 'true',
            'zerovm_proxy': 'http://127.0.0.1:%d/v1/' % prolis.getsockname()[1],
            'zerovm_maxoutput': 1024 * 1024 * 10 }
    _test_sockets = \
        (prolis, acc1lis, acc2lis, con1lis, con2lis, obj1lis, obj2lis)
    pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                              [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                                'port': acc1lis.getsockname()[1]},
                               {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                                'port': acc2lis.getsockname()[1]}], 30),
                GzipFile(os.path.join(_testdir, 'account.ring.gz'), 'wb'))
    pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                              [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                                'port': con1lis.getsockname()[1]},
                               {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                                'port': con2lis.getsockname()[1]}], 30),
                GzipFile(os.path.join(_testdir, 'container.ring.gz'), 'wb'))
    pickle.dump(ring.RingData([[0, 1, 0, 1], [1, 0, 1, 0]],
                              [{'id': 0, 'zone': 0, 'device': 'sda1', 'ip': '127.0.0.1',
                                'port': obj1lis.getsockname()[1]},
                               {'id': 1, 'zone': 1, 'device': 'sdb1', 'ip': '127.0.0.1',
                                'port': obj2lis.getsockname()[1]}], 30),
                GzipFile(os.path.join(_testdir, 'object.ring.gz'), 'wb'))
    prosrv = proxyquery.filter_factory(conf)(
        proxy_server.Application(conf, memcache=FakeMemcacheReturnsNone())
    )
    acc1srv = account_server.AccountController(conf)
    acc2srv = account_server.AccountController(conf)
    con1srv = container_server.ContainerController(conf)
    con2srv = container_server.ContainerController(conf)
    obj1srv = objectquery.filter_factory(conf)(object_server.ObjectController(conf))
    obj2srv = objectquery.filter_factory(conf)(object_server.ObjectController(conf))
    _test_servers =\
    (prosrv, acc1srv, acc2srv, con1srv, con2srv, obj1srv, obj2srv)
    nl = NullLogger()
    prospa = spawn(wsgi.server, prolis, prosrv, nl)
    acc1spa = spawn(wsgi.server, acc1lis, acc1srv, nl)
    acc2spa = spawn(wsgi.server, acc2lis, acc2srv, nl)
    con1spa = spawn(wsgi.server, con1lis, con1srv, nl)
    con2spa = spawn(wsgi.server, con2lis, con2srv, nl)
    obj1spa = spawn(wsgi.server, obj1lis, obj1srv, nl)
    obj2spa = spawn(wsgi.server, obj2lis, obj2srv, nl)
    _test_coros =\
    (prospa, acc1spa, acc2spa, con1spa, con2spa, obj1spa, obj2spa)
    # Create account
    ts = normalize_timestamp(time())
    partition, nodes = prosrv.app.account_ring.get_nodes('a')
    for node in nodes:
        conn = swift.proxy.controllers.base.http_connect(node['ip'], node['port'],
            node['device'], partition, 'PUT', '/a',
                {'X-Timestamp': ts, 'x-trans-id': 'test'})
        resp = conn.getresponse()
        assert(resp.status == 201)
    ts = normalize_timestamp(time())
    partition, nodes = prosrv.app.account_ring.get_nodes('userstats')
    for node in nodes:
        conn = swift.proxy.controllers.base.http_connect(node['ip'], node['port'],
            node['device'], partition, 'PUT', '/userstats',
            {'X-Timestamp': ts, 'x-trans-id': 'test1'})
        resp = conn.getresponse()
        assert(resp.status == 201)
    # Create container
    sock = connect_tcp(('localhost', prolis.getsockname()[1]))
    fd = sock.makefile()
    fd.write('PUT /v1/a/c HTTP/1.1\r\nHost: localhost\r\n'
             'Connection: close\r\nX-Auth-Token: t\r\n'
             'Content-Length: 0\r\n\r\n')
    fd.flush()
    headers = readuntil2crlfs(fd)
    exp = 'HTTP/1.1 201'
    assert(headers[:len(exp)] == exp)

def teardown():
    for server in _test_coros:
        server.kill()
    swift.proxy.controllers.obj.CONTAINER_LISTING_LIMIT = \
        _orig_container_listing_limit
    rmtree(os.path.dirname(_testdir))

@contextmanager
def save_globals():
    orig_http_connect = getattr(swift.proxy.controllers.base, 'http_connect', None)
    orig_query_connect = getattr(proxyquery, 'http_connect', None)
    orig_account_info = getattr(proxy_server.ObjectController, 'account_info', None)
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
        obj_ring=FakeRing()
        obj_ring.partition_count = 1
        self.proxy_app = proxy_server.Application(None, FakeMemcache(),
            account_ring=FakeRing(), container_ring=FakeRing(),
            object_ring=obj_ring)
#        self.conf = {'devices': _testdir, 'swift_dir': _testdir,
#                'mount_check': 'false', 'allowed_headers':
#                'content-encoding, x-object-manifest, content-disposition, foo'}
        #monkey_patch_mimetools()
        self.zerovm_mock = None

    def tearDown(self):
        if self.zerovm_mock:
            os.unlink(self.zerovm_mock)
        proxy_server.CONTAINER_LISTING_LIMIT = _orig_container_listing_limit

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

    def create_object(self, prolis, url, obj, content_type='application/octet-stream'):
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
        numlist = [i for i in range(min_num,max_num)]
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
            #_obj1srv.zerovm_nexe_xparams = ['ok.', '0']
            _obj2srv.zerovm_exename = ['python', zerovm_mock]
            #_obj2srv.zerovm_nexe_xparams = ['ok.', '0']

        self._randomnumbers = self.get_random_numbers()
        self._nexescript = ('return pickle.dumps(sorted(id))')
        self._nexescript_etag = md5()
        self._nexescript_etag.update(self._nexescript)
        self._nexescript_etag = self._nexescript_etag.hexdigest()
        set_zerovm_mock()

        (prolis, acc1lis, acc2lis, con1lis, con2lis, obj1lis, obj2lis) = _test_sockets
        self.create_container(prolis, '/v1/a/c')
        self.create_container(prolis, '/v1/a/c_in1')
        self.create_container(prolis, '/v1/a/c_in2')
        self.create_container(prolis, '/v1/a/c_out1')
        self.create_container(prolis, '/v1/a/c_out2')
        self.create_object(prolis, '/v1/a/c/o', self._randomnumbers)
        self.create_object(prolis, '/v1/a/c/exe', self._nexescript)

        self.create_object(prolis, '/v1/a/c_in1/input1', self.get_random_numbers(0,10))
        self.create_object(prolis, '/v1/a/c_in1/input2', self.get_random_numbers(10,20))
        self.create_object(prolis, '/v1/a/c_in1/junk', 'junk')
        self.create_object(prolis, '/v1/a/c_in2/input1', self.get_random_numbers(20,30))
        self.create_object(prolis, '/v1/a/c_in2/input2', self.get_random_numbers(30,40))
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
            headers={'Content-Type': 'application/octet-stream'})
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
    def add_sysimage_device(self, sysimage_path):
        prosrv = _test_servers[0]
        _obj1srv = _test_servers[5]
        _obj2srv = _test_servers[6]
        zerovm_sysimage_devices = prosrv.app.zerovm_sysimage_devices
        zerovm_sysimage_devices1 = _obj1srv.zerovm_sysimage_devices
        zerovm_sysimage_devices2 = _obj2srv.zerovm_sysimage_devices
        prosrv.app.zerovm_sysimage_devices = ['sysimage']
        _obj1srv.zerovm_sysimage_devices = {'sysimage': sysimage_path}
        _obj2srv.zerovm_sysimage_devices = {'sysimage': sysimage_path}
        try:
            yield True
        finally:
            prosrv.app.zerovm_sysimage_devices = zerovm_sysimage_devices
            _obj1srv.zerovm_sysimage_devices = zerovm_sysimage_devices1
            _obj2srv.zerovm_sysimage_devices = zerovm_sysimage_devices2
            try:
                os.unlink(sysimage_path)
            except IOError:
                pass

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
            ns.sendto(request, ('localhost', int(ns_port)))
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
                        host, port = struct.unpack_from('!4sH', reply, offset)[0:2]
                        offset += 6
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect((socket.inet_ntop(socket.AF_INET, host), port))
                        self.assertEqual(connection_map['%d->%d' % (id, connect_list[i])], port)
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                    {'device':'stdin','path':'/c/o'},
                    {'device':'stdout','path':'/c/o2'}
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
            self.assertEqual(res.status_int, 200)
            req = self.object_request('/v1/a/c/o2')
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body, self.get_sorted_numbers())

    def test_QUERY_sort_store_stdout_stderr(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout','path':'/c/o2'},
                        {'device':'stderr','path':'/c/o3'}
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
        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers())

        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '\nfinished\n')

    def test_QUERY_immediate_stdout(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                    {'device':'stdin','path':'/c/o'},
                    {'device':'stdout', 'content_type': 'application/x-pickle'}
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

    def test_QUERY_store_meta(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
return 'Test Test'
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': '/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout', 'content_type': 'text/plain',
                        'meta': {'key1': 'test1', 'key2': 'test2'},
                        'path': '/c/o3'
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

    def test_QUERY_hello(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
return 'hello, world'
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/hello.nexe', nexe)
        conf = [
            {
                "name": "hello",
                "exec": {"path": "/c/hello.nexe"},
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

    def test_QUERY_cgi_response(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
resp = '\n'.join([
    'HTTP/1.1 200 OK',
    'Content-Type: text/html',
    'X-Object-Meta-Key1: value1',
    'X-Object-Meta-Key2: value2',
    '', ''
    ])
out = '<html><body>Test this</body></html>'
return resp + out
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': '/c/exe2'},
                'file_list': [
                    {'device': 'stdout',
                     'content_type': 'message/http',
                     'path': '/c/o3'}
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
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.assertEqual(res.headers['x-object-meta-key1'], 'value1')
        self.assertEqual(res.headers['x-object-meta-key2'], 'value2')
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        conf = [
            {
                'name': 'http',
                'exec': {'path': '/c/exe2'},
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

    def test_QUERY_cgi_environment(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
return pickle.dumps(open(mnfst.nvram['path']).read())
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'http',
                'exec': {'path': '/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'application/x-pickle',
                        'path': '/c/o3',
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
                'exec': {'path': '/c/exe2'},
                'file_list': [
                    {
                        'device': 'stdout',
                        'content_type': 'text/plain',
                    },
                    {
                        'device': 'stdin',
                        'path': '/c/o3'
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

    def test_QUERY_GET_response(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
resp = '<html><body>Test this</body></html>'
return resp
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe, content_type='application/x-nexe')
        req = self.object_request('/v1/a/c/exe2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, nexe)
        req = Request.blank('/open/a/c/exe2?' + urlencode({'content_type':'text/html'}))
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.create_object(prolis, '/v1/a/c/my.nexe', nexe, content_type='application/x-nexe')
        req = Request.blank('/open/a/c/my.nexe?' + urlencode({'content_type':'text/html'}))
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        self.assertEqual(res.headers['content-type'], 'text/html')
        conf = [
            {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                    {'device':'stdin','path':'{.object_path}'},
                    {'device':'stdout', 'content_type': 'application/x-pickle'}
                ]
            }
        ]
        conf = json.dumps(conf)
        self.create_container(prolis, '/v1/a/%s' % prosrv.app.zerovm_registry_path)
        self.create_object(prolis, '/v1/a/%s/%s'
                                   % (prosrv.app.zerovm_registry_path,
                                      'application/octet-stream/config'),
            conf, content_type='application/json')
        req = Request.blank('/open/a/c/o')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['content-type'], 'application/x-pickle')
        self.assertEqual(res.body, self.get_sorted_numbers())

    def test_QUERY_use_image(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
return [open(mnfst.image['path']).read(), sorted(id)]
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        image = 'This is image file'
        self.create_object(prolis, '/v1/a/c/img', image)
        conf = [
            {
                'name':'sort',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                    {'device':'stdin','path':'/c/o'},
                    {'device':'stdout'},
                    {'device':'image','path':'/c/img'}
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

    def test_QUERY_use_sysimage(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        image = 'This is image file'
        sysimage_path = os.path.join(_testdir, 'sysimage.tar')

        nexe =\
r'''
return open(mnfst.nvram['path']).read() + \
    str(mnfst.channels['/dev/sysimage']['type']) + ' ' + \
    str(mnfst.channels['/dev/sysimage']['path'])
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        img = open(sysimage_path, 'wb')
        img.write(image)
        img.close()
        with self.add_sysimage_device(sysimage_path):
            conf = [
                {
                    'name': 'sort',
                    'exec': {
                        'path': '/c/exe2'
                    },
                    'file_list': [
                        {'device': 'stdin', 'path': '/c/o'},
                        {'device': 'stdout'},
                        {'device': 'sysimage'}
                    ]
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertIn('[fstab]\n'
                          'channel=/dev/sysimage, mountpoint=/, access=ro\n'
                          '[args]\n'
                          'args = sort\n', res.body)
            self.assertIn('%d %s' % (3, sysimage_path),
                          res.body)

    def test_QUERY_post_script_sysimage(self):
        self.setup_QUERY()
        prosrv = _test_servers[0]
        script = \
r'''
#! sysimage bin/sh
print 'Test'
'''[1:-1]
        nexe = \
r'''
import tarfile
tar = tarfile.open(mnfst.image['path'])
members = tar.getmembers()
names = tar.getnames()
file = tar.extractfile(members[0])
return names[0] + '\n' + file.read()
'''[1:-1]
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
        nexe = \
r'''
import tarfile
tar = tarfile.open(mnfst.image['path'])
members = tar.getmembers()
file = tar.extractfile(members[0])
return file.read()
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        script = \
r'''
#! /c/exe2
print 'Test'
'''[1:-1]
        req = self.zerovm_request()
        req.body = script
        req.headers['content-type'] = 'application/x-python'
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn(script, res.body)
        script = \
r'''
#! /aaa/bbb
print 'Test'
'''[1:-1]
        req.body = script
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 404)
        self.assertIn(' /a/aaa/bbb', res.body)
        script = \
r'''
#! aaa/bbb
print 'Test'
'''[1:-1]
        req.body = script
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertIn(' aaa/bbb', res.body)

    def test_QUERY_use_nvram(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
return open(mnfst.nvram['path']).read()
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': '/c/exe2'
                },
                'file_list': [
                    {'device': 'stdin', 'path': '/c/o'},
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
                    'path': '/c/exe2',
                    'args': 'aa bb cc'
                },
                'file_list': [
                    {'device': 'stdin', 'path': '/c/o'},
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
                    'path': '/c/exe2'
                },
                'file_list': [
                    {'device': 'stdin', 'path': '/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': '/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertIn('[fstab]\n'
                      'channel=/dev/image, mountpoint=/, access=ro\n'
                      '[args]\n'
                      'args = sort\n', res.body)
        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': '/c/exe2',
                    'args': 'aa bb cc',
                    'env': {
                        'key1': 'val1',
                        'key2': 'val2'
                    }
                },
                'file_list': [
                    {'device': 'stdin', 'path': '/c/o'},
                    {'device': 'stdout'},
                    {'device': 'image', 'path': '/c/img'}
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
        self.assertIn('name=key2, value=val2\n'
                      'name=key1, value=val1',
                      res.body)

        conf = [
            {
                'name': 'sort',
                'exec': {
                    'path': '/c/exe2'
                },
                'file_list': [
                    {'device': 'input', 'path': '/c/o', 'mode': 'file'},
                    {'device': 'stdout', 'mode': 'char'},
                    {'device': 'image', 'path': '/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertIn('[args]\n'
                      'args = sort\n', res.body)
        self.assertIn('[mapping]\n'
                      'channel=/dev/input, mode=file\n'
                      'channel=/dev/stdout, mode=char\n',
                      res.body)

    def test_QUERY_sort_immediate_stdout_stderr(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                    {'device':'stdin','path':'/c/o'},
                    {'device':'stderr'}
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stderr'},
                        {'device':'stdout','path':'/c/o2'}
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
                'exec': {'path': '/c/exe'},
                'file_list': [
                    {'device': 'stderr', 'path': '/c/o2'}
                ],
                'connect': ['merge']
            },
            {
                'name': 'merge',
                'exec': {'path': '/c/exe'},
                'file_list': [
                    {'device': 'stderr', 'path': '/c/o3'}
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
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/out/%s' % conf[0]['connect'][0], res.body))

        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('finished', res.body)
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/out/%s' % conf[1]['connect'][0], res.body))

    def test_QUERY_networked_devices(self):
        self.setup_QUERY()
        nexe =\
r'''
return 'ok'
'''[1:-1]
        prolis = _test_sockets[0]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name': 'sort',
                'exec': {'path': '/c/exe2'},
                'file_list':[
                    {'device': 'stdout', 'path': 'merge:/dev/sort'},
                    {'device': 'stderr', 'path': '/c/o2'}
                ],
                'connect': ['merge']
            },
            {
                'name': 'merge',
                'exec': {'path': '/c/exe2'},
                'file_list': [
                    {'device': 'stderr', 'path': '/c/o3'}
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
        #self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/out/%s' % conf[1]['connect'][0], res.body))

    def test_QUERY_network_resolve_multiple(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': '/c/exe'},
                'file_list': [
                    {'device': 'stderr', 'path': '/c_out1/*.stderr'}
                ],
                'connect': ['merge', 'sort'],
                'count':3
            },
            {
                'name': 'merge',
                'exec': {'path': '/c/exe'},
                'file_list': [
                    {'device': 'stderr', 'path': '/c_out1/*.stderr'}
                ],
                'count': 2
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)

        req = self.object_request('/v1/a/c_out1/sort-1.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            ['merge-1', 'merge-1', 'merge-2', 'merge-2', 'sort-2', 'sort-2', 'sort-3', 'sort-3']
        )
        req = self.object_request('/v1/a/c_out1/sort-2.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            ['merge-1', 'merge-1', 'merge-2', 'merge-2', 'sort-1', 'sort-1', 'sort-3', 'sort-3']
        )
        req = self.object_request('/v1/a/c_out1/sort-3.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            ['merge-1', 'merge-1', 'merge-2', 'merge-2', 'sort-1', 'sort-1', 'sort-2', 'sort-2']
        )
        req = self.object_request('/v1/a/c_out1/merge-1.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            []
        )
        req = self.object_request('/v1/a/c_out1/merge-2.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            []
        )


    def test_QUERY_read_obj_wildcard(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c_in1/in*'},
                        {'device':'stdout'}
                ]
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(0, 10) + self.get_sorted_numbers(10, 20))

    def test_QUERY_read_container_wildcard(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        self.create_object(prolis, '/v1/a/c/exe2', 'return sorted(id)')
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                        {'device':'stdin','path':'/c_in*'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                        {'device':'stdin','path':'/c_in*/in*'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c_in1/in*'},
                        {'device':'stdout','path':'/c_out1/out*'}
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

    def test_QUERY_write_wildcard(self):
        self.setup_QUERY()
        conf = [
            {
                'name': 'sort',
                'exec': {'path': '/c/exe'},
                'file_list': [
                    {'device': 'stdout', 'path': '/c_out1/out.*'}],
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
        self.assertEqual(res.headers['x-nexe-system'], 'sort-1,sort-1,sort-2,sort-2')
        self.assertEqual(res.headers['x-nexe-status'], 'ok.,ok.,ok.,ok.')
        self.assertEqual(res.headers['x-nexe-retcode'], '0,0,0,0')
        req = self.object_request('/v1/a/c_out1/out.sort-1')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '(l.')
        req = self.object_request('/v1/a/c_out1/out.sort-2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '(l.')

    def test_QUERY_group_transform_multiple(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c_in*/in*'},
                        {'device':'stdout','path':'/c_out*/out*'}
                ]
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers['x-nexe-system'], 'sort-1,sort-2,sort-3,sort-4')
        self.assertEqual(res.headers['x-nexe-status'], 'ok.,ok.,ok.,ok.')
        self.assertEqual(res.headers['x-nexe-retcode'], '0,0,0,0')
        req = self.object_request('/v1/a/c_out1/output1')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(0, 10))
        req = self.object_request('/v1/a/c_out1/output2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(10, 20))
        req = self.object_request('/v1/a/c_out2/output1')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(20, 30))
        req = self.object_request('/v1/a/c_out2/output2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(30, 40))

    def test_QUERY_calls_authorize(self):
        raise SkipTest # there is no pre-authorization right now, maybe we do not need it at all
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
            res = req.get_response(prosrv)
        self.assert_(called[0])

    def test_QUERY_request_client_disconnect_attr(self):
        with save_globals():
            proxy_server.http_connect =\
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

        with save_globals():
            proxy_server.http_connect =\
            fake_http_connect(200, 200, 201, 201, 201)
            prosrv = _test_servers[0]
            prosrv.app.max_upload_time = 1
            req = self.zerovm_request()
            req.body_file = SlowFile()
            res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 408)

    def test_QUERY_invalid_etag(self):
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'path':'/c/error'},
                'file_list':[
                    {'device':'stdin','path':'/c/o'},
                    {'device':'stdout', 'path':'/c/out'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.body, 'Error 404 Not Found while fetching /a/c/error')
        self.assertEqual(res.status_int, 404)

    def test_QUERY_missing_required_fields(self):
        conf = [
                {
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'}
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
                'name':'sort',
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'test':1},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'path':'/c/o'},
                        {'device':'stdout'}
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdtest'}
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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin', 'path':'*'},
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'Invalid path * in sort')

    def test_QUERY_account_server_error(self):
        with save_globals():
            swift.proxy.controllers.account.http_connect =\
            fake_http_connect(500, 500, 500, 500, 500)
            swift.proxy.controllers.base.http_connect =\
            fake_http_connect(500, 500, 500, 500, 500)
            swift.proxy.controllers.container.http_connect =\
            fake_http_connect(500, 500, 500, 500, 500)
            swift.proxy.controllers.obj.http_connect =\
            fake_http_connect(500, 500, 500, 500, 500)
            proxyquery.http_connect = \
            fake_http_connect(500, 500, 500, 500, 500)
            prosrv = _test_servers[0]
            conf = [
                    {
                    'name':'sort',
                    'exec':{'path':'/c/exe'},
                    'file_list':[
                            {'device':'stdin', 'path':'/c*'}
                    ]
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 400)
            self.assertEqual(res.body, 'Error querying object server for account a')

    def test_QUERY_config_parser(self):

        fake_controller = proxyquery.ProxyQueryMiddleware(
            self.proxy_app, {'zerovm_sysimage_devices': 'sysimage1 sysimage2'}).get_controller('a', None, None)
        conf = [
            {
                'name': 'script',
                'exec': {
                    'path': 'boot/lua',
                    'args': 'my_script.lua'
                },
                'file_list': [
                    {
                        'device': 'image',
                        'path': '/images/lua.img'
                    },
                    {
                        'device': 'stdin',
                        'path': '/c/input'
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
        error = fake_controller.parse_cluster_config(req, conf)
        self.assertIsNone(error)
        self.assertEqual(len(fake_controller.nodes), 5)

        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        self.setup_QUERY()
        self.create_container(prolis, '/v1/a/terasort')
        self.create_object(prolis, '/v1/a/terasort/input/1.txt', self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/2.txt', self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/3.txt', self.get_random_numbers())
        self.create_object(prolis, '/v1/a/terasort/input/4.txt', self.get_random_numbers())
        nexe =\
r'''
return open(mnfst.nvram['path']).read()
'''[1:-1]
        self.create_object(prolis, '/v1/a/terasort/bin/map', nexe)
        self.create_object(prolis, '/v1/a/terasort/bin/reduce', nexe)
        conf = [
            {
                "name": "map",
                "exec": {
                    "path": "/terasort/bin/map",
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
                        "path": "/terasort/input/*.txt"
                    },
                    {
                        "device": "stderr",
                        "path": "/terasort/log/*.log",
                        "content_type": "text/plain"
                    }
                ]
            },
            {
                "name": "red",
                "exec": {
                    "path": "/terasort/bin/reduce",
                    "env": {
                        "MAP_NAME": "map",
                        "REDUCE_NAME": "red"
                    }
                },
                "connect": ["map"],
                "file_list": [
                    {
                        "device": "stdout",
                        "path": "/terasort/output/*.txt",
                        "content_type": "text/plain"
                    },
                    {
                        "device": "stderr",
                        "path": "/terasort/log/*.log",
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
        #print json.dumps(controller.nodes, sort_keys=True, indent=2, cls=proxyquery.NodeEncoder)
