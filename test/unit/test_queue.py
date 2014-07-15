from eventlet import sleep, spawn, wsgi, listen, GreenPool
import mock
from eventlet.green import os
from tempfile import mkdtemp
from shutil import rmtree
from time import time
import unittest
import swift
try:
    import simplejson as json
except ImportError:
    import json
from swift.proxy import server as proxy_server
from swift.account import server as account_server
from swift.common.middleware import proxy_logging
from swift.common.http import is_success
from swift.common.swob import Request
from swift.container import server as container_server
from swift.obj import server as object_server
from swift.common.utils import mkdirs, normalize_timestamp, NullLogger
from swift.common import utils
from swift.common import storage_policy
from swift.common.storage_policy import StoragePolicy, \
    StoragePolicyCollection, POLICIES
from test.unit import connect_tcp, readuntil2crlfs, fake_http_connect, trim, \
    debug_logger, FakeMemcache, write_fake_ring, FakeRing
from zerocloud import queue


class FakeMemcacheReturnsNone(FakeMemcache):

    def get(self, key):
        # Returns None as the timestamp of the container; assumes we're only
        # using the FakeMemcache for container existence checks.
        return None


def setup():
    do_setup(object_server)


def teardown():
    for server in _test_coros:
        server.kill()
    rmtree(os.path.dirname(_testdir))
    utils.SysLogHandler = _orig_SysLogHandler
    storage_policy._POLICIES = _orig_POLICIES


def do_setup(the_object_server):
    utils.HASH_PATH_SUFFIX = 'endcap'
    global _testdir, _test_servers, _test_sockets, \
        _orig_container_listing_limit, _test_coros, _orig_SysLogHandler, \
        _orig_POLICIES, _test_POLICIES
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
    queuesrv = queue.QueueMiddleware(prosrv, conf,
                                     logger=prosrv.logger)
    nl = NullLogger()
    logging_prosv = proxy_logging.ProxyLoggingMiddleware(queuesrv, conf,
                                                         logger=prosrv.logger)
    prospa = spawn(wsgi.server, prolis, logging_prosv, nl)
    acc1spa = spawn(wsgi.server, acc1lis, acc1srv, nl)
    acc2spa = spawn(wsgi.server, acc2lis, acc2srv, nl)
    con1spa = spawn(wsgi.server, con1lis, con1srv, nl)
    con2spa = spawn(wsgi.server, con2lis, con2srv, nl)
    obj1spa = spawn(wsgi.server, obj1lis, obj1srv, nl)
    obj2spa = spawn(wsgi.server, obj2lis, obj2srv, nl)
    _test_servers = \
        (queuesrv, acc1srv, acc2srv, con1srv, con2srv, obj1srv, obj2srv)
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


class TestQueue(unittest.TestCase):

    def setUp(self):
        self.proxy_app = \
            proxy_server.Application(None, FakeMemcache(),
                                     logger=debug_logger('proxy-ut'),
                                     account_ring=FakeRing(),
                                     container_ring=FakeRing())

    def create_queue(self, name):
        req = Request.blank('/queue/a/%s' % name,
                            environ={'REQUEST_METHOD': 'PUT'})
        prosrv = _test_servers[0]
        resp = req.get_response(prosrv)
        return resp

    def delete_queue(self, name):
        req = Request.blank('/queue/a/%s' % name,
                            environ={'REQUEST_METHOD': 'DELETE'})
        prosrv = _test_servers[0]
        resp = req.get_response(prosrv)
        return resp

    def clear_queue(self, name):
        prefix = _test_servers[0].queue_prefix
        req = Request.blank('/v1/a/%s%s?format=json' % (prefix, name))
        prosrv = _test_servers[0]
        resp = req.get_response(prosrv)
        for item in json.loads(resp.body):
            obj_name = item['name']
            req = Request.blank('/v1/a/%s%s/%s' % (prefix, name, obj_name),
                                environ={'REQUEST_METHOD': 'GET'})
            resp = req.get_response(prosrv)
            print [resp.status, resp.headers]
            req = Request.blank('/v1/a/%s%s/%s' % (prefix, name, obj_name),
                                environ={'REQUEST_METHOD': 'DELETE'})
            resp = req.get_response(prosrv)
            self.assertTrue(is_success(resp.status_int))
        req = Request.blank('/v1/a/%s%s?format=json' % (prefix, name))
        resp = req.get_response(prosrv)
        self.assertEqual(len(json.loads(resp.body)), 0)

    def put_message(self, queue_name, data, client_id='client-1', ttl=None):
        req = Request.blank('/queue/a/%s/message' % queue_name,
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/json',
                                     'Client-Id': client_id})
        req.body = data
        if ttl:
            req.query_string = 'ttl=%d' % ttl
        prosrv = _test_servers[0]
        resp = req.get_response(prosrv)
        return resp

    def list_messages(self, queue_name, echo=False, limit=1000,
                      client_id='client-1'):
        req = Request.blank('/queue/a/%s/message' % queue_name,
                            environ={'REQUEST_METHOD': 'GET'},
                            headers={'Content-Type': 'application/json',
                                     'Client-Id': client_id})
        if limit:
            req.query_string = 'limit=%d' % limit
        if echo:
            req.query_string += '&echo=true'
        prosrv = _test_servers[0]
        resp = req.get_response(prosrv)
        return resp

    def test_create_queue(self):
        resp = self.create_queue('test')
        self.assertTrue(is_success(resp.status_int))
        resp = self.create_queue('test')
        self.assertTrue(is_success(resp.status_int))
        resp = self.create_queue('test1')
        self.assertTrue(is_success(resp.status_int))

    def test_list_queues(self):
        subreq = swift.common.wsgi.make_subrequest
        calls = [0]

        def mock_subreq(*args, **kwargs):
            calls[0] += 1
            return subreq(*args, **kwargs)

        self.create_queue('test')
        with mock.patch('zerocloud.queue.make_subrequest', mock_subreq):
            req = Request.blank('/queue/a')
            prosrv = _test_servers[0]
            resp = req.get_response(prosrv)
            self.assertTrue(is_success(resp.status_int))
            data = json.loads(resp.body)
            self.assertTrue('test' in data.keys())
            self.assertEqual(calls[0], 1)

    def test_delete_queue(self):
        self.create_queue('test1')
        resp = self.delete_queue('test1')
        self.assertTrue(is_success(resp.status_int))

    def test_put_message(self):
        self.create_queue('test')
        data = {'aaa': '111', 'bbb': '222'}
        data = json.dumps(data)
        resp = self.put_message('test', data)
        resp_data = json.loads(resp.body)
        self.assertEqual(json.dumps(resp_data['data']), data)
        self.assertEqual(resp_data['client_id'], 'client-1')
        tail = '/client-1/client-1'
        self.assertEqual(resp_data['claim_id'][-len(tail):], tail)
        data = {'aaa': '111', 'bbb': '222'}
        data = json.dumps(data)
        resp = self.put_message('test', data)
        resp_data = json.loads(resp.body)
        self.assertEqual(json.dumps(resp_data['data']), data)
        self.assertEqual(resp_data['client_id'], 'client-1')
        tail = '/client-1/client-1'
        self.assertEqual(resp_data['claim_id'][-len(tail):], tail)

    def test_list_all_messages(self):
        self.create_queue('test')
        data = {'aaa': '111', 'bbb': '222'}
        data = json.dumps(data)
        resp = self.put_message('test', data)
        self.assertTrue(is_success(resp.status_int))
        resp_data = [json.loads(resp.body)]
        resp = self.list_messages('test', echo=True)
        list_data = json.loads(resp.body)
        self.assertEqual(resp_data[0], list_data[0])
        resp_data.append(json.loads(self.put_message('test', data).body))
        resp_data.append(json.loads(self.put_message('test', data).body))
        resp_data.append(json.loads(self.put_message('test', data).body))
        resp = self.list_messages('test', echo=True)
        list_data = json.loads(resp.body)
        self.assertEqual(resp_data[0], list_data[0])
        self.assertEqual(resp_data, list_data)
        self.clear_queue('test')
        resp = self.delete_queue('test')
        self.assertTrue(is_success(resp.status_int))

    def test_put_message_ttl(self):
        self.create_queue('test')
        data = {'aaa': '111', 'bbb': '222'}
        data = json.dumps(data)
        resp = self.put_message('test', data, ttl=1)
        resp_data = json.loads(resp.body)
        self.assertEqual(json.dumps(resp_data['data']), data)
        self.assertEqual(resp_data['client_id'], 'client-1')
        tail = '/client-1/client-1'
        self.assertEqual(resp_data['claim_id'][-len(tail):], tail)
        resp = self.list_messages('test', echo=True)
        list_data = json.loads(resp.body)
        # something strange here, works well on real Swift
        self.clear_queue('test')