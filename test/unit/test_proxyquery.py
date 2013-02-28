from StringIO import StringIO
import re
import struct
from eventlet.green import socket
import tarfile
import datetime
from swiftclient.client import quote
import random
import swift

from zerocloud.proxyquery import ZvmNode, ZvmChannel, NodeEncoder, CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME

try:
    import simplejson as json
except ImportError:
    import json
import unittest
import os
import cPickle as pickle
from time import time, sleep
from swift.common.swob import Request, HTTPNotFound, HTTPUnauthorized
from hashlib import md5
from test.unit import connect_tcp, readuntil2crlfs
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
from test.unit.proxy.test_server import fake_http_connect, save_globals, \
    FakeRing, FakeMemcache, FakeMemcacheReturnsNone
from swift.common.middleware import proxyquery, objectquery

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
    _test_sockets =\
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
    orig_account_info = getattr(proxy_server.Controller, 'account_info', None)
    try:
        yield True
    finally:
        proxy_server.http_connect = orig_http_connect
        swift.proxy.controllers.base.http_connect = orig_http_connect
        swift.proxy.controllers.obj.http_connect = orig_http_connect
        swift.proxy.controllers.account.http_connect = orig_http_connect
        swift.proxy.controllers.container.http_connect = orig_http_connect
        proxy_server.Controller.account_info = orig_account_info
        proxyquery.http_connect = orig_query_connect

def fake_http_connect(*code_iter, **kwargs):

    class FakeConn(object):

        def __init__(self, status, etag=None, body='', timestamp='1'):
            self.status = status
            self.reason = 'Fake'
            self.host = '1.2.3.4'
            self.port = '1234'
            self.sent = 0
            self.received = 0
            self.etag = etag
            self.body = body
            self.timestamp = timestamp

        def getresponse(self):
            if kwargs.get('raise_exc'):
                raise Exception('test')
            if kwargs.get('raise_timeout_exc'):
                raise Timeout()
            return self

        def getexpect(self):
            if self.status == -2:
                raise HTTPException()
            if self.status == -3:
                return FakeConn(507)
            return FakeConn(100)

        def getheaders(self):
            headers = {'content-length': len(self.body),
                       'content-type': 'x-application/test',
                       'x-timestamp': self.timestamp,
                       'last-modified': self.timestamp,
                       'x-object-meta-test': 'testing',
                       'etag':
                           self.etag or '"68b329da9893e34099c7d8ad5cb9c940"',
                       'x-works': 'yes',
                       'x-account-container-count': 12345}
            if not self.timestamp:
                del headers['x-timestamp']
            try:
                if container_ts_iter.next() is False:
                    headers['x-container-timestamp'] = '1'
            except StopIteration:
                pass
            if 'slow' in kwargs:
                headers['content-length'] = '4'
            if 'headers' in kwargs:
                headers.update(kwargs['headers'])
            return headers.items()

        def read(self, amt=None):
            if 'slow' in kwargs:
                if self.sent < 4:
                    self.sent += 1
                    sleep(0.1)
                    return ' '
            rv = self.body[:amt]
            self.body = self.body[amt:]
            return rv

        def send(self, amt=None):
            if 'slow' in kwargs:
                if self.received < 4:
                    self.received += 1
                    sleep(0.1)

        def getheader(self, name, default=None):
            return dict(self.getheaders()).get(name.lower(), default)

    timestamps_iter = iter(kwargs.get('timestamps') or ['1'] * len(code_iter))
    etag_iter = iter(kwargs.get('etags') or [None] * len(code_iter))
    x = kwargs.get('missing_container', [False] * len(code_iter))
    if not isinstance(x, (tuple, list)):
        x = [x] * len(code_iter)
    container_ts_iter = iter(x)
    code_iter = iter(code_iter)

    def connect(*args, **ckwargs):
        if 'give_content_type' in kwargs:
            if len(args) >= 7 and 'Content-Type' in args[6]:
                kwargs['give_content_type'](args[6]['Content-Type'])
            else:
                kwargs['give_content_type']('')
        if 'give_connect' in kwargs:
            kwargs['give_connect'](*args, **ckwargs)
        status = code_iter.next()
        etag = etag_iter.next()
        timestamp = timestamps_iter.next()
        if status <= 0:
            raise HTTPException()
        return FakeConn(status, etag, body=kwargs.get('body', ''),
            timestamp=timestamp)

    return connect

class TestProxyQuery(unittest.TestCase):

    def setUp(self):
        self.proxy_app = proxy_server.Application(None, FakeMemcache(),
            account_ring=FakeRing(), container_ring=FakeRing(),
            object_ring=FakeRing())
#        self.conf = {'devices': _testdir, 'swift_dir': _testdir,
#                'mount_check': 'false', 'allowed_headers':
#                'content-encoding, x-object-manifest, content-disposition, foo'}
        #monkey_patch_mimetools()

    def tearDown(self):
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

    def create_object(self, prolis, url, obj):
        sock = connect_tcp(('localhost', prolis.getsockname()[1]))
        fd = sock.makefile()
        fd.write('PUT %s HTTP/1.1\r\n'
                 'Host: localhost\r\n'
                 'Connection: close\r\n'
                 'X-Storage-Token: t\r\n'
                 'Content-Length: %s\r\n'
                 'Content-Type: application/octet-stream\r\n'
                 '\r\n%s' % (url, str(len(obj)),  obj))
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
            def_mock = \
r'''
import socket
import struct
from sys import argv, exit
import re
import logging
import cPickle as pickle
from time import sleep
from argparse import ArgumentParser

def errdump(zvm_errcode, nexe_validity, nexe_errcode, nexe_etag, nexe_accounting, status_line):
    print '%d\n%d\n%s\n%s\n%s' % (nexe_validity, nexe_errcode, nexe_etag,
                                  ' '.join([str(val) for val in nexe_accounting]), status_line)
    exit(zvm_errcode)

def eval_as_function(code, local_vars={}, global_vars=None):
    if not global_vars:
        global_vars = globals()
    retval = None
    context = {}
    code = re.sub(r"(?m)^", "    ", code)
    code = "def anon(" + ','.join(local_vars.keys()) + "):\n" + code
    exec code in global_vars, context
    retval = context['anon'](*(local_vars.values()))
    return retval

parser = ArgumentParser()
parser.add_argument('-M', dest='manifest')
parser.add_argument('-s', action='store_true', dest='skip')
parser.add_argument('-z', action='store_true', dest='validate')
args = parser.parse_args()

valid = 1
if args.skip:
    valid = 0
accounting = [0,0,0,0,0,0,0,0,0,0,0]
manifest = args.manifest
if not manifest:
    errdump(1,valid, 0,'',accounting,'Manifest file required')
try:
    inputmnfst = file(manifest, 'r').read().splitlines()
except IOError:
    errdump(1,valid, 0,'',accounting,'Cannot open manifest file: %s' % manifest)
dl = re.compile("\s*=\s*")
mnfst_dict = dict()
for line in inputmnfst:
    (attr, val) = re.split(dl, line, 1)
    if attr and attr in mnfst_dict:
        mnfst_dict[attr] += ',' + val
    else:
        mnfst_dict[attr] = val

class Mnfst:
    pass

mnfst = Mnfst()
index = 0
status = 'nexe did not run'
retcode = 0

def retrieve_mnfst_field(n, eq=None, min=None, max=None, isint=False, optional=False):
    if n not in mnfst_dict:
        if optional:
            return
        errdump(1,valid,0,'',accounting,'Manifest key missing "%s"' % n)
    v = mnfst_dict[n]
    if isint:
        v = int(v)
        if min and v < min:
            errdump(1,valid,0,'',accounting,'%s = %d is less than expected: %d' % (n,v,min))
        if max and v > max:
            errdump(1,valid,0,'',accounting,'%s = %d is more than expected: %d' % (n,v,max))
    if eq and v != eq:
        errdump(1,valid,0,'',accounting,'%s = %s and expected %s' % (n,v,eq))
    setattr(mnfst, n.strip(), v)


retrieve_mnfst_field('Version', '09082012')
retrieve_mnfst_field('Nexe')
exe = file(mnfst.Nexe, 'r').read()
if 'INVALID' == exe:
    valid = 2
    retcode = 0
if args.validate:
    errdump(0, valid, retcode, '', accounting, status)
    exit(0)
retrieve_mnfst_field('NexeMax', isint=True)
retrieve_mnfst_field('SyscallsMax', min=1, isint=True, optional=True)
retrieve_mnfst_field('NexeEtag', optional=True)
retrieve_mnfst_field('Timeout', min=1, isint=True)
retrieve_mnfst_field('MemMax', min=32*1048576, max=4096*1048576, isint=True)
retrieve_mnfst_field('Environment', optional=True)
retrieve_mnfst_field('CommandLine', optional=True)
retrieve_mnfst_field('Channel')
retrieve_mnfst_field('NodeName', optional=True)
retrieve_mnfst_field('NameServer', optional=True)
if not getattr(mnfst, 'NexeEtag', None):
    mnfst.NexeEtag = 'DISABLED'

channel_list = re.split('\s*,\s*',mnfst.Channel)
if len(channel_list) % 7 != 0:
    errdump(1,valid,0,mnfst.NexeEtag,accounting,'wrong channel config: %s' % mnfst.Channel)
dev_list = channel_list[1::7]
bind_data = ''
bind_count = 0
connect_data = ''
connect_count = 0
con_list = []
bind_map = {}
alias = int(re.split('\s*,\s*', mnfst.NodeName)[1])
for i in xrange(0,len(dev_list)):
    device = dev_list[i]
    fname = channel_list[i*7]
    if device == '/dev/stdin' or device == '/dev/input':
        mnfst.input = fname
    elif device == '/dev/stdout' or device == '/dev/output':
        mnfst.output = fname
    elif device == '/dev/stderr':
        mnfst.err = fname
    elif '/dev/in/' in device or '/dev/out/' in device:
        node_name = device.split('/')[3]
        proto, host, port = fname.split(':')
        host = int(host)
        if '/dev/in/' in device:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
            bind_map[host] = {'name':device,'port':port,'proto':proto, 'sock':s}
            bind_data += struct.pack('!IIH', host, 0, int(port))
            bind_count += 1
        else:
            connect_data += struct.pack('!IIH', host, 0, 0)
            connect_count += 1
            con_list.append(device)
request = struct.pack('!I', alias) +\
          struct.pack('!I', bind_count) + bind_data + struct.pack('!I', connect_count) + connect_data
ns_proto, ns_host, ns_port = mnfst.NameServer.split(':')
ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
ns.connect((ns_host, int(ns_port)))
ns.sendto(request, (ns_host, int(ns_port)))
ns_host = ns.getpeername()[0]
ns_port = ns.getpeername()[1]
while 1:
    reply, addr = ns.recvfrom(65535)
    if addr[0] == ns_host and addr[1] == ns_port:
        offset = 0
        count = struct.unpack_from('!I', reply, offset)[0]
        offset += 4
        for i in range(count):
            host, port = struct.unpack_from('!4sH', reply, offset+4)[0:2]
            offset += 10
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((socket.inet_ntop(socket.AF_INET, host), port))
            con_list[i] = [con_list[i], 'tcp://%s:%d'
                % (socket.inet_ntop(socket.AF_INET, host), port)]
        break
if bind_map:
    sleep(0.5)
if valid < 2:
    try:
        inf = file(mnfst.input, 'r')
        ouf = file(mnfst.output, 'w')
        err = file(mnfst.err, 'w')
        ins = inf.read()
        accounting[4] += 1
        accounting[5] += len(ins)
        id = pickle.loads(ins)
    except EOFError:
        id = []
    except Exception:
        errdump(1,valid,0,mnfst.NexeEtag,accounting,'Std files I/O error')

    od = ''
    try:
        od = str(eval_as_function(exe))
    except Exception, e:
        err.write(e.message+'\n')
        accounting[6] += 1
        accounting[7] += len(e.message+'\n')

    ouf.write(od)
    accounting[6] += 1
    accounting[7] += len(od)
    for t in con_list:
        err.write('%s, %s\n' % (t[1], t[0]))
        accounting[6] += 1
        accounting[7] += len('%s, %s\n' % (t[1], t[0]))
    inf.close()
    ouf.close()
    err.write('\nfinished\n')
    accounting[6] += 1
    accounting[7] += len('\nfinished\n')
    err.close()
status = 'ok.'
errdump(0, valid, retcode, mnfst.NexeEtag, accounting, status)
'''
            (_prosrv, _acc1srv, _acc2srv, _con1srv,
             _con2srv, _obj1srv, _obj2srv) = _test_servers
            fd, zerovm_mock = mkstemp()
            if mock:
                os.write(fd, mock)
            else:
                os.write(fd, def_mock)
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
    def create_tar(self, dict):
        tarfd, tarname = mkstemp()
        os.close(tarfd)
        tar = tarfile.open(name=tarname, mode='w')
        sysmap = None
        for name, file in dict.iteritems():
            if name in [CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME]:
                info = tarfile.TarInfo(name)
                file.seek(0, 2)
                size = file.tell()
                info.size = size
                file.seek(0, 0)
                tar.addfile(info, file)
                sysmap = name
                break
        if sysmap:
            del dict[sysmap]
        for name, file in dict.iteritems():
            info = tarfile.TarInfo(name)
            file.seek(0, 2)
            size = file.tell()
            info.size = size
            file.seek(0, 0)
            tar.addfile(info, file)
        tar.close()
        try:
            yield tarname
        finally:
            try:
                os.unlink(tarname)
            except OSError:
                pass

    def test_QUERY_name_service(self):
        ns_server = proxyquery.NameService()
        pool = GreenPool()
        peers = 3
        ns_port = ns_server.start(pool, peers)
        map = {}
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
                bind_map[h] = {'port':port,'sock':s}
                bind_data += struct.pack('!IH', h, int(port))
                map['%d->%d' % (h, id)] = int(port)
            for h in conf[1]:
                connect_list.append(h)
                connect_data += struct.pack('!IH', h, 0)
            request = struct.pack('!I', id) +\
                      struct.pack('!I', len(conf[0])) + bind_data +\
                      struct.pack('!I', len(conf[1])) + connect_data
            ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            ns.connect(('localhost', int(ns_port)))
            ns.sendto(request, ('localhost', int(ns_port)))
            ns_host = ns.getpeername()[0]
            ns_port = ns.getpeername()[1]
            while 1:
                reply, addr = ns.recvfrom(65535)
                if addr[0] == ns_host and addr[1] == ns_port:
                    offset = 0
                    count = struct.unpack_from('!I', reply, offset)[0]
                    offset += 4
                    for i in range(count):
                        host, port = struct.unpack_from('!4sH', reply, offset)[0:3]
                        offset += 6
                        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        s.connect((socket.inet_ntop(socket.AF_INET, host), port))
                        self.assertEqual(map['%d->%d' %(id,connect_list[i])], port)
                    break
            sleep(0.2)
        dev1 = [[2, 3],[2, 3]]
        dev2 = [[1, 3],[1, 3]]
        dev3 = [[2, 1],[2, 1]]
        th1 = pool.spawn(mock_client, ns_port, dev1, 1)
        th2 = pool.spawn(mock_client, ns_port, dev2, 2)
        th3 = pool.spawn(mock_client, ns_port, dev3, 3)
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
        self.assertEqual(res.headers,{
            'x-nexe-retcode': '0',
            'content-length': '0',
            'x-nexe-cdr-line': '0 0 0 0 0 0 0 0 0 0 0 0',
            'x-nexe-validation': '1',
            'x-nexe-system': 'sort',
            'x-nexe-etag': 'DISABLED',
            'x-nexe-status': 'ok.'
        })
        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers())

        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, '\nfinished\n')

    def test_QUERY_sort_store_stdout_stderr_realzvm(self):
        self.setup_QUERY()
        (_prosrv, _acc1srv, _acc2srv, _con1srv,
         _con2srv, _obj1srv, _obj2srv) = _test_servers
        _obj1srv.zerovm_exename = ['zerovm']
        _obj2srv.zerovm_exename = ['zerovm']
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        fd = open('sort_uint_proper_with_args.nexe')
        exe = fd.read()
        fd.close()
        self.create_object(prolis, '/v1/a/c/sort.exe', exe)
        randomnum = self.get_random_numbers(0, 1024 * 1024 / 4, proto='binary')
        self.create_object(prolis, '/v1/a/c/binary.data', randomnum)
        conf = [
                {
                'name':'sort',
                'exec':{
                    'path':'/c/sort.exe',
                    'args':'%d' % (1024 * 1024)
                    },
                'file_list':[
                        {'device':'stdin','path':'/c/binary.data'},
                        {'device':'stdout','path':'/c/binary.out'},
                        {'device':'stderr','path':'/c/sort.log'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers, {
            'x-nexe-retcode': '0',
            'content-length': '0',
            'x-nexe-cdr-line': '0 0 0 0 0 0 0 0 0 0 0 0',
            'x-nexe-validation': '1',
            'x-nexe-system': 'sort',
            'x-nexe-etag': 'disabled',
            'x-nexe-status': 'ok'
        })

        req = self.object_request('/v1/a/c/binary.out')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(0, 1024 * 1024 / 4, proto='binary'))

        req = self.object_request('/v1/a/c/sort.log')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assert_('done\n' in res.body)

    def test_QUERY_sort_transform_realzvm(self):
        self.setup_QUERY()
        (_prosrv, _acc1srv, _acc2srv, _con1srv,
         _con2srv, _obj1srv, _obj2srv) = _test_servers
        _obj1srv.zerovm_exename = ['zerovm']
        _obj2srv.zerovm_exename = ['zerovm']
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        fd = open('sort_uint_proper_with_args.nexe')
        exe = fd.read()
        fd.close()
        self.create_object(prolis, '/v1/a/c/sort.exe', exe)
        size = 1024 * 1024 / 4
        randomnum = self.get_random_numbers(0, size, proto='binary')
        self.create_object(prolis, '/v1/a/c/binary.data', randomnum)
        randomnum = self.get_random_numbers(size, size * 2, proto='binary')
        self.create_object(prolis, '/v1/a/c/binary1.data', randomnum)
        randomnum = self.get_random_numbers(size * 2, size * 3, proto='binary')
        self.create_object(prolis, '/v1/a/c/binary2.data', randomnum)
        conf = [
            {
                'name':'sort',
                'exec':{
                    'path':'/c/sort.exe',
                    'args':'%d' % (1024 * 1024)
                },
                'file_list':[
                    {'device':'stdin','path':'/c/binary*.data'},
                    {'device':'stdout','path':'/c/binary*.out'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.headers,{
            'x-nexe-retcode': '0,'
                              '0,'
                              '0',
            'content-length': '0',
            'x-nexe-cdr-line': '0 0 0 0 0 0 0 0 0 0 0 0,'
                               '0 0 0 0 0 0 0 0 0 0 0 0,'
                               '0 0 0 0 0 0 0 0 0 0 0 0',
            'x-nexe-validation': '1,'
                                 '1,'
                                 '1',
            'x-nexe-system': 'sort-1,'
                             'sort-2,'
                             'sort-3',
            'x-nexe-etag': 'disabled,'
                           'disabled,'
                           'disabled',
            'x-nexe-status': 'ok,'
                             'ok,'
                             'ok'
        })

        req = self.object_request('/v1/a/c/binary.out')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(0, size, proto='binary'))

        req = self.object_request('/v1/a/c/binary1.out')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(size, size * 2, proto='binary'))

        req = self.object_request('/v1/a/c/binary2.out')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers(size * 2, size * 3, proto='binary'))

    def test_QUERY_mapred_realzvm(self):

        def upload_file(listener, name, url):
            fd = open(name)
            content = fd.read()
            fd.close()
            self.create_object(listener, url, content)

        self.setup_QUERY()
        (_prosrv, _acc1srv, _acc2srv, _con1srv,
         _con2srv, _obj1srv, _obj2srv) = _test_servers
        _obj1srv.zerovm_exename = ['zerovm']
        _obj2srv.zerovm_exename = ['zerovm']
        _obj1srv.zerovm_timeout = 60
        _obj2srv.zerovm_timeout = 60
        _obj1srv.zerovm_maxnexemem = 128 * 1048576
        _obj2srv.zerovm_maxnexemem = 128 * 1048576
        _prosrv.app.node_timeout = 60
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        fd = open('mapred/map.nexe')
        map_nexe = fd.read()
        fd.close()
        fd = open('mapred/reduce.nexe')
        red_nexe = fd.read()
        fd.close()
        #upload_file(prolis, 'mapred/map.nexe', '/v1/a/c/map.nexe')
        #upload_file(prolis, 'mapred/reduce.nexe', '/v1/a/c/reduce.nexe')
        upload_file(prolis, 'mapred/1input.txt', '/v1/a/c/1input.txt')
        upload_file(prolis, 'mapred/2input.txt', '/v1/a/c/2input.txt')
        upload_file(prolis, 'mapred/3input.txt', '/v1/a/c/3input.txt')
        upload_file(prolis, 'mapred/4input.txt', '/v1/a/c/4input.txt')
        conf = [
            {
                'name':'map',
                'exec':{
                    'path':'boot/map.nexe',
                    'env':{ 'MAP_NAME':'map', 'REDUCE_NAME':'red'}
                },
                'file_list':[
                    {'device':'stdin','path':'/c/*input.txt'}
                ],
                'connect': [ 'map', 'red' ]
            },
            {
                'name':'red',
                'exec':{
                    'path':'boot/reduce.nexe',
                    'env':{ 'MAP_NAME':'map', 'REDUCE_NAME':'red'}
                },
                'file_list':[
                    {'device':'stdout','path':'/c/*output.txt'}
                ],
                'connect': [ 'map' ],
                'count': 5
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        map_nexe = StringIO(map_nexe)
        red_nexe = StringIO(red_nexe)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap,
                              'boot/map.nexe': map_nexe,
                              'boot/reduce.nexe': red_nexe}) \
        as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
#        req = self.zerovm_request()
#        req.body = conf
#        res = req.get_response(prosrv)
            print res.headers
            print res.body

    def test_QUERY_dist_sort_realzvm(self):

        def upload_file(listener, name, url):
            fd = open(name)
            content = fd.read()
            fd.close()
            self.create_object(listener, url, content)

        def load_file(name):
            fd = open(name)
            content = fd.read()
            fd.close()
            return StringIO(content)

        self.setup_QUERY()
        (_prosrv, _acc1srv, _acc2srv, _con1srv,
         _con2srv, _obj1srv, _obj2srv) = _test_servers
        _obj1srv.zerovm_exename = ['zerovm']
        _obj2srv.zerovm_exename = ['zerovm']
        _obj1srv.zerovm_timeout = 60
        _obj2srv.zerovm_timeout = 60
        _obj1srv.zerovm_maxnexemem = 128 * 1048576
        _obj2srv.zerovm_maxnexemem = 128 * 1048576
        _prosrv.app.node_timeout = 60
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        fd = open('generator.uint32_t.nexe')
        gen_nexe = fd.read()
        fd.close()
        self.create_container(prolis, '/v1/a/disort')
        #upload_file(prolis, 'mapred/map.nexe', '/v1/a/c/map.nexe')
        #upload_file(prolis, 'mapred/reduce.nexe', '/v1/a/c/reduce.nexe')
        conf = [
            {
                "name":"gen",
                "exec":{
                    "path":"generator.uint32_t.nexe",
                    "args":"5000000"
                },
                "file_list":[
                    { "device":"stdout", "path":"/disort/unsorted*.data" }
                ],
                "count": 5
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        gen_nexe = StringIO(gen_nexe)
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap,
                              'generator.uint32_t.nexe': gen_nexe}) \
        as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
            #        req = self.zerovm_request()
            #        req.body = conf
            #        res = req.get_response(prosrv)
            print res.headers
            print res.body

        req = self.object_request('/v1/a/disort/unsortedgen-1.data')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(len(res.body), res.content_length)
        conf = [
            {
                "name": "man",
                "exec": {
                    "path": "nodeman.nexe",
                    "args":"5000000",
                    "env": {"SOURCE_NAME": "src", "DEST_NAME": "dst", "MAN_NAME": "man"}
                },
                "file_list": [
                    {"device": "stderr"}
                ],
                "connect": ["src"]
            },
            {
                "name": "src",
                "exec": {
                    "path": "nodesrc.nexe",
                    "args":"5000000",
                    "env": {"SOURCE_NAME": "src", "DEST_NAME": "dst", "MAN_NAME": "man"}
                },
                "file_list": [
                    {"device": "stdin", "path": "/disort/unsorted*.data"}
                ],
                "connect": ["man", "dst"]
            },
            {
                "name": "dst",
                "exec": {
                    "path": "nodedst.nexe",
                    "args":"5000000",
                    "env": {"SOURCE_NAME": "src", "DEST_NAME": "dst", "MAN_NAME": "man"}
                },
                "file_list": [
                    {"device": "stdout", "path": "/disort/sorted*.data"}
                ],
                "connect": ["man"],
                "count": 5
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_tar_request()
        sysmap = StringIO(conf)
        man_nexe = load_file('nodeman.nexe')
        src_nexe = load_file('nodesrc.nexe')
        dst_nexe = load_file('nodedst.nexe')
        with self.create_tar({CLUSTER_CONFIG_FILENAME: sysmap,
                              'nodeman.nexe': man_nexe,
                              'nodesrc.nexe': src_nexe,
                              'nodedst.nexe': dst_nexe})\
        as tar:
            req.body_file = open(tar, 'rb')
            req.content_length = os.path.getsize(tar)
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            print res.headers
            #self.assertIn('crc OK', res.body)

        req = Request.blank('/v1/userstats/a/%s' % datetime.datetime.utcnow().strftime('%Y/%m/%d.log'),
            environ={'REQUEST_METHOD': 'GET'})
        res = req.get_response(prosrv)
        print res.body

    def test_QUERY_generator_zerovm(self):
        raise SkipTest
        self.setup_QUERY()
        (_prosrv, _acc1srv, _acc2srv, _con1srv,
         _con2srv, _obj1srv, _obj2srv) = _test_servers
        prosrv = _test_servers[0]
        prolis = _test_sockets[0]
        self.create_container(prolis, '/v1/a/exe')
        self.create_container(prolis, '/v1/a/unsorted')
        self.create_container(prolis, '/v1/a/sorted')

        @contextmanager
        def save_args():
            obj1_exe = _obj1srv.zerovm_exename
            obj2_exe = _obj2srv.zerovm_exename
            obj1_timeout = _obj1srv.zerovm_timeout
            obj2_timeout = _obj2srv.zerovm_timeout
            proxy_timeout = prosrv.app.node_timeout
            try:
                yield True
            finally:
                _obj1srv.zerovm_exename = obj1_exe
                _obj2srv.zerovm_exename = obj2_exe
                _obj1srv.zerovm_timeout = obj1_timeout
                _obj2srv.zerovm_timeout = obj2_timeout
                prosrv.app.node_timeout = proxy_timeout

        with save_args():
            _obj1srv.zerovm_exename = ['./zerovm']
            _obj2srv.zerovm_exename = ['./zerovm']
            _obj1srv.zerovm_timeout = 30
            _obj2srv.zerovm_timeout = 30
            prosrv.app.node_timeout = 30

            fd = open('generator.uint32_t.nexe')
            exe = fd.read()
            fd.close()
            self.create_object(prolis, '/v1/a/exe/generator.uint32_t.nexe', exe)
            conf = [
                    {
                    "name": "generator",
                    "exec": {"path": "/exe/generator.uint32_t.nexe"},
                    "file_list": [
                            {
                            "device": "stdout",
                            "path": "/unsorted/*.data"
                        },
                            {
                            "device": "stderr"
                        }
                    ],
                    "args": "500000",
                    "count":2
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            print res

            fd = open('nodeman.nexe')
            exe = fd.read()
            fd.close()
            self.create_object(prolis, '/v1/a/exe/nodeman.nexe', exe)
            fd = open('nodesrc.nexe')
            exe = fd.read()
            fd.close()
            self.create_object(prolis, '/v1/a/exe/nodesrc.nexe', exe)
            fd = open('nodedst.nexe')
            exe = fd.read()
            fd.close()
            self.create_object(prolis, '/v1/a/exe/nodedst.nexe', exe)
            conf = [
                    {
                    "name":"src",
                    "exec":{
                        "path":"/exe/nodesrc.nexe"
                    },
                    "connect":[ "dst", "man" ],
                    "file_list":[
                            {
                            "device":"stdin",
                            "path":"/unsorted/generator*.data"
                        }
                    ],
                    "env":{
                        "SOURCE_NAME":"src",
                        "MAN_NAME":"man",
                        "DEST_NAME":"dst"
                    }
                },
                    {
                    "name":"dst",
                    "exec":{
                        "path":"/exe/nodedst.nexe"
                    },
                    "connect":[ "man" ],
                    "file_list":[
                            {
                            "device":"stdout",
                            "path":"/sorted/*.data"
                        }
                    ],
                    "env":{
                        "SOURCE_NAME":"src",
                        "MAN_NAME":"man",
                        "DEST_NAME":"dst"
                    },
                    "count":2
                },
                    {
                    "name":"man",
                    "exec":{
                        "path":"/exe/nodeman.nexe"
                    },
                    "connect":[ "src" ],
                    "file_list":[
                            {
                            "device":"stdout"
                        },
                            {
                            "device":"stderr"
                        }
                    ],
                    "env":{
                        "SOURCE_NAME":"src",
                        "MAN_NAME":"man",
                        "DEST_NAME":"dst"
                    }
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            print res

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
                    {'device':'stdout', 'content-type': 'application/x-pickle'}
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

    def test_QUERY_immediate_response(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe = \
r'''
content = '<html><body>Test this</body></html>\r\n'
return ('Status: 200 OK\r\n'
       'Content-Type: text/html\r\n'
       'Content-Length: %d'
       '\r\n' % len(content)
       + content)
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name':'http',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                    {'device':'stdout', 'content-type': 'message/http'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        print res.headers
        print res.body

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
                'name':'http',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                    {'device':'stdout', 'content-type': 'text/plain',
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

    def test_QUERY_sort_immediate_stdout_stderr(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'},
                        {'device':'stderr'}
                ]
            }
        ]
        conf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        resp = [
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers()+'\nfinished\n',
                'name': 'sort',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(res.body, json.dumps(resp))

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
        resp = [
                {
                'status': '200 OK',
                'body': '\nfinished\n',
                'name': 'sort',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(res.body, json.dumps(resp))
        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body, self.get_sorted_numbers())

    def test_QUERY_network_resolve(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stderr','path':'/c/o2'}
                ],
                'connect':['merge']
            },
                {
                'name':'merge',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stderr','path':'/c/o3'}
                ],
                'connect':['sort']
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        resp = [
                {
                'status': '201 Created',
                'body': '',
                'name': 'merge',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(res.body, json.dumps(resp))

        req = self.object_request('/v1/a/c/o2')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('finished', res.body)
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/out/%s' % conf[0]['connect'][0],res.body))

        req = self.object_request('/v1/a/c/o3')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertIn('finished', res.body)
        self.assert_(re.match('tcp://127.0.0.1:\d+, /dev/out/%s' % conf[1]['connect'][0],res.body))

    def test_QUERY_network_resolve_multiple(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stderr', 'path':'/c_out1/*.stderr'}
                ],
                'connect':['merge','sort'],
                'count':3
            },
                {
                'name':'merge',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stderr', 'path':'/c_out1/*.stderr'}
                ],
                'count':2
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        resp = [
                {
                'status': '201 Created',
                'body': '',
                'name': 'merge-1',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'merge-2',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-1',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-2',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-3',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(res.body, json.dumps(resp))

        req = self.object_request('/v1/a/c_out1/sort-1.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            ['merge-1', 'merge-2', 'sort-2', 'sort-3']
        )
        req = self.object_request('/v1/a/c_out1/sort-2.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            ['merge-1', 'merge-2', 'sort-1', 'sort-3']
        )
        req = self.object_request('/v1/a/c_out1/sort-3.stderr')
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        self.assertEqual(
            sorted(re.findall('tcp://127.0.0.1:\d+, /dev/out/([^\s]+)', res.body)),
            ['merge-1', 'merge-2', 'sort-1', 'sort-2']
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
        result = [
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(0, 10),
                'name': 'sort-1',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(10, 20),
                'name': 'sort-2',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(json.dumps(result), res.body)

    def test_QUERY_read_container_wildcard(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdin','path':'/c_in*'},
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
        result = [
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(0, 10),
                'name': 'sort-1',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(10, 20),
                'name': 'sort-2',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': '(l.',
                'name': 'sort-3',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(20, 30),
                'name': 'sort-4',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(30, 40),
                'name': 'sort-5',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': '(l.',
                'name': 'sort-6',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
        ]
        self.assertEqual(json.dumps(result), res.body)

    def test_QUERY_read_container_and_obj_wildcard(self):
        self.setup_QUERY()
        conf = [
                {
                'name':'sort',
                'exec':{'path':'/c/exe'},
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
        result = [
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(0, 10),
                'name': 'sort-1',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(10, 20),
                'name': 'sort-2',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(20, 30),
                'name': 'sort-3',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '200 OK',
                'body': self.get_sorted_numbers(30, 40),
                'name': 'sort-4',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(json.dumps(result), res.body)

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
                'name':'sort',
                'exec':{'path':'/c/exe'},
                'file_list':[
                        {'device':'stdout','path':'/c_out1/out.*'},
                ],
                'count':2
            }
        ]
        jconf = json.dumps(conf)
        prosrv = _test_servers[0]
        req = self.zerovm_request()
        req.body = jconf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 200)
        resp = [
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-1',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-2',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(json.dumps(resp), res.body)
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
        resp = [
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-1',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-2',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-3',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            },
                {
                'status': '201 Created',
                'body': '',
                'name': 'sort-4',
                'nexe_etag': '07405c77e6bdc4533612831e02bed9fb',
                'nexe_status': 'ok.',
                'nexe_retcode': 0
            }
        ]
        self.assertEqual(json.dumps(resp), res.body)
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
        called = [False]
        def authorize(req):
            called[0] = True
            return HTTPUnauthorized(request=req)
        with save_globals():
            proxy_server.http_connect =\
            fake_http_connect(200, 200, 201, 201, 201)
            prosrv = _test_servers[0]
            req = self.zerovm_request()
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
            print req.__dict__
            res = req.get_response(prosrv)
            print req.__dict__
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
        #req.headers['etag'] = '1111'
        res = req.get_response(prosrv)
        print res.body
        #self.assertEqual(res.status_int, 422)

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
                        {'device':'stdin', 'path':'/c/in'},
                        {'device':'image', 'path':'/c/img'}
                ]
            }
        ]
        conf = json.dumps(conf)
        req = self.zerovm_request()
        req.body = conf
        res = req.get_response(prosrv)
        self.assertEqual(res.status_int, 400)
        self.assertEqual(res.body, 'More than one readable file in sort')
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

    def test_QUERY_chunked(self):

        class ChunkedFile():

            def __init__(self, str):
                self.str = str
                self.bytes = len(str)
                self.read_bytes = 0

            @property
            def bytes_left(self):
                return self.bytes - self.read_bytes

            def read(self, amt=None):
                if self.read_bytes >= self.bytes:
                    raise StopIteration()
                if not amt:
                    amt = self.bytes_left
                data = self.str[self.read_bytes:self.read_bytes + min(amt, self.bytes_left)]
                #data = '9' * min(amt, self.bytes_left)
                self.read_bytes += len(data)
                return data

        with save_globals():
            proxy_server.http_connect = \
            fake_http_connect(200, 200, 201, 201, 201, body='1234567890')
            proxyquery.http_connect = \
            fake_http_connect(200, 200, 201, 201, 201, body='1234567890')
            controller = proxyquery.ProxyQueryMiddleware(self.proxy_app,{}).get_controller('account')
            req = Request.blank('/a', environ={'REQUEST_METHOD': 'POST'},
                headers={'Transfer-Encoding': 'chunked',
                         'Content-Type': 'application/json'})
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
            req.body_file = ChunkedFile(conf)
            self.proxy_app.memcache.store = {}
            self.proxy_app.update_request(req)
            res = controller.zerovm_query(req)
            self.assertEqual(res.status_int, 200)

    def test_QUERY_config_parser(self):

        fake_controller = proxyquery.ProxyQueryMiddleware(
            self.proxy_app,{}).get_controller('a')
        conf = [
            {
                'name':'script',
                'exec':{'path':'boot/lua','args':'my_script.lua'},
                'file_list':[
                    {'device':'image', 'path':'/images/lua.img'}
                ],
                'connect':['script'],
                'count':5
            }
        ]
        conf = json.dumps(conf)
        req = Request.blank('/a', environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/json'})
        error = fake_controller.parse_cluster_config(req, conf)
        if error:
            print [error.status,error.body]
        else:
            print json.dumps(fake_controller.nodes,
                cls=NodeEncoder, indent='  ')


    '''
    def test_QUERY_connect_exceptions(self):

    def mock_http_connect(*code_iter, **kwargs):

    class FakeConn(object):

        def __init__(self, status):
            self.status = status
            self.reason = 'Fake'

        def getresponse(self):
            return self

        def read(self, amt=None):
            return ''

        def getheader(self, name):
            return ''

        def getexpect(self):
            if self.status == -2:
                raise HTTPException()
            if self.status == -3:
                return FakeConn(507)
            return FakeConn(100)

    code_iter = iter(code_iter)

    def connect(*args, **ckwargs):
        status = code_iter.next()
        if status == -1:
            raise HTTPException()
        return FakeConn(status)

    return connect

    with save_globals():
    controller = proxy_server.ObjectController(self.app, 'account',
        'container', 'object')

    def test_status_map(statuses, expected):
        proxy_server.http_connect = mock_http_connect(*statuses)
        self.app.memcache.store = {}
        req = Request.blank('/a/c/o.jpg', {})
        req.content_length = 0
        self.app.update_request(req)
        res = controller.QUERY(req)
        expected = str(expected)
        self.assertEqual(res.status[:len(expected)], expected)
    test_status_map((200, 200, 201, 201, -1), 201)
    test_status_map((200, 200, 201, 201, -2), 201)  # expect timeout
    test_status_map((200, 200, 201, 201, -3), 201)  # error limited
    test_status_map((200, 200, 201, -1, -1), 503)
    test_status_map((200, 200, 503, 503, -1), 503)
    def test_QUERY_send_exceptions(self):

    def mock_http_connect(*code_iter, **kwargs):

    class FakeConn(object):

        def __init__(self, status):
            self.status = status
            self.reason = 'Fake'
            self.host = '1.2.3.4'
            self.port = 1024
            self.etag = md5()

        def getresponse(self):
            self.etag = self.etag.hexdigest()
            self.headers = {
                'etag': self.etag,
            }
            return self

        def read(self, amt=None):
            return ''

        def send(self, amt=None):
            if self.status == -1:
                raise HTTPException()
            else:
                self.etag.update(amt)

        def getheader(self, name):
            return self.headers.get(name, '')

        def getexpect(self):
            return FakeConn(100)
    code_iter = iter(code_iter)

    def connect(*args, **ckwargs):
        return FakeConn(code_iter.next())
    return connect
    with save_globals():
    controller = proxy_server.ObjectController(self.app, 'account',
        'container', 'object')

    def test_status_map(statuses, expected):
        self.app.memcache.store = {}
        proxy_server.http_connect = mock_http_connect(*statuses)
        req = Request.blank('/a/c/o.jpg',
            environ={'REQUEST_METHOD': 'QUERY'}, body='some data')
        self.app.update_request(req)
        res = controller.QUERY(req)
        expected = str(expected)
        self.assertEqual(res.status[:len(expected)], expected)
    test_status_map((200, 200, 201, -1, 201), 201)
    test_status_map((200, 200, 201, -1, -1), 503)
    test_status_map((200, 200, 503, 503, -1), 503)
    def test_QUERY_max_size(self):
    with save_globals():
    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    controller = proxy_server.ObjectController(self.app, 'account',
        'container', 'object')
    req = Request.blank('/a/c/o', {}, headers={
        'Content-Length': str(MAX_FILE_SIZE + 1),
        'Content-Type': 'foo/bar'})
    self.app.update_request(req)
    res = controller.QUERY(req)
    self.assertEqual(res.status_int, 413)
    def test_QUERY_getresponse_exceptions(self):

    def mock_http_connect(*code_iter, **kwargs):

    class FakeConn(object):

        def __init__(self, status):
            self.status = status
            self.reason = 'Fake'
            self.host = '1.2.3.4'
            self.port = 1024

        def getresponse(self):
            if self.status == -1:
                raise HTTPException()
            return self

        def read(self, amt=None):
            return ''

        def send(self, amt=None):
            pass

        def getheader(self, name):
            return ''

        def getexpect(self):
            return FakeConn(100)
    code_iter = iter(code_iter)

    def connect(*args, **ckwargs):
        return FakeConn(code_iter.next())
    return connect
    with save_globals():
    controller = proxy_server.ObjectController(self.app, 'account',
        'container', 'object')

    def test_status_map(statuses, expected):
        self.app.memcache.store = {}
        proxy_server.http_connect = mock_http_connect(*statuses)
        req = Request.blank('/a/c/o.jpg', {})
        req.content_length = 0
        self.app.update_request(req)
        res = controller.QUERY(req)
        expected = str(expected)
        self.assertEqual(res.status[:len(str(expected))],
                          str(expected))
    test_status_map((200, 200, 201, 201, -1), 201)
    test_status_map((200, 200, 201, -1, -1), 503)
    test_status_map((200, 200, 503, 503, -1), 503)
    def test_QUERY_client_timeout(self):
    with save_globals():
    self.app.account_ring.get_nodes('account')
    for dev in self.app.account_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.container_ring.get_nodes('account')
    for dev in self.app.container_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.object_ring.get_nodes('account')
    for dev in self.app.object_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1

    class SlowBody():

        def __init__(self):
            self.sent = 0

        def read(self, size=-1):
            if self.sent < 4:
                sleep(0.1)
                self.sent += 1
                return ' '
            return ''

    req = Request.blank('/a/c/o',
        environ={'REQUEST_METHOD': 'PUT', 'wsgi.input': SlowBody()},
        headers={'Content-Length': '4', 'Content-Type': 'text/plain'})
    self.app.update_request(req)
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 201, 201, 201)
        #                 acct cont obj  obj  obj
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.app.client_timeout = 0.1
    req = Request.blank('/a/c/o',
        environ={'REQUEST_METHOD': 'PUT', 'wsgi.input': SlowBody()},
        headers={'Content-Length': '4', 'Content-Type': 'text/plain'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(201, 201, 201)
        #                 obj  obj  obj
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 408)
    def test_QUERY_client_disconnect(self):
    with save_globals():
    self.app.account_ring.get_nodes('account')
    for dev in self.app.account_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.container_ring.get_nodes('account')
    for dev in self.app.container_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.object_ring.get_nodes('account')
    for dev in self.app.object_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1

    class SlowBody():

        def __init__(self):
            self.sent = 0

        def read(self, size=-1):
            raise Exception('Disconnected')

    req = Request.blank('/a/c/o',
        environ={'REQUEST_METHOD': 'PUT', 'wsgi.input': SlowBody()},
        headers={'Content-Length': '4', 'Content-Type': 'text/plain'})
    self.app.update_request(req)
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 201, 201, 201)
        #                 acct cont obj  obj  obj
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 499)
    def test_QUERY_node_read_timeout(self):
    with save_globals():
    self.app.account_ring.get_nodes('account')
    for dev in self.app.account_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.container_ring.get_nodes('account')
    for dev in self.app.container_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.object_ring.get_nodes('account')
    for dev in self.app.object_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'GET'})
    self.app.update_request(req)
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, slow=True)
    req.sent_size = 0
    resp = controller.GET(req)
    got_exc = False
    try:
        resp.body
    except proxy_server.ChunkReadTimeout:
        got_exc = True
    self.assert_(not got_exc)
    self.app.node_timeout = 0.1
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, slow=True)
    resp = controller.GET(req)
    got_exc = False
    try:
        resp.body
    except proxy_server.ChunkReadTimeout:
        got_exc = True
    self.assert_(got_exc)
    def test_QUERY_node_write_timeout(self):
    with save_globals():
    self.app.account_ring.get_nodes('account')
    for dev in self.app.account_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.container_ring.get_nodes('account')
    for dev in self.app.container_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    self.app.object_ring.get_nodes('account')
    for dev in self.app.object_ring.devs.values():
        dev['ip'] = '127.0.0.1'
        dev['port'] = 1
    req = Request.blank('/a/c/o',
        environ={'REQUEST_METHOD': 'PUT'},
        headers={'Content-Length': '4', 'Content-Type': 'text/plain'},
        body='    ')
    self.app.update_request(req)
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 201, 201, 201, slow=True)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.app.node_timeout = 0.1
    proxy_server.http_connect = \
        fake_http_connect(201, 201, 201, slow=True)
    req = Request.blank('/a/c/o',
        environ={'REQUEST_METHOD': 'PUT'},
        headers={'Content-Length': '4', 'Content-Type': 'text/plain'},
        body='    ')
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 503)
    def test_QUERY_iter_nodes(self):
    with save_globals():
    try:
        self.app.object_ring.max_more_nodes = 2
        controller = proxy_server.ObjectController(self.app, 'account',
                        'container', 'object')
        partition, nodes = self.app.object_ring.get_nodes('account',
                            'container', 'object')
        collected_nodes = []
        for node in controller.iter_nodes(partition, nodes,
                                          self.app.object_ring):
            collected_nodes.append(node)
        self.assertEqual(len(collected_nodes), 5)

        self.app.object_ring.max_more_nodes = 20
        controller = proxy_server.ObjectController(self.app, 'account',
                        'container', 'object')
        partition, nodes = self.app.object_ring.get_nodes('account',
                            'container', 'object')
        collected_nodes = []
        for node in controller.iter_nodes(partition, nodes,
                                          self.app.object_ring):
            collected_nodes.append(node)
        self.assertEqual(len(collected_nodes), 9)
    finally:
        self.app.object_ring.max_more_nodes = 0
    def test_QUERY_proxy_passes_content_type(self):
    with save_globals():
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'GET'})
    self.app.update_request(req)
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = fake_http_connect(200, 200, 200)
    resp = controller.GET(req)
    self.assertEqual(resp.status_int, 200)
    self.assertEqual(resp.content_type, 'x-application/test')
    proxy_server.http_connect = fake_http_connect(200, 200, 200)
    resp = controller.GET(req)
    self.assertEqual(resp.status_int, 200)
    self.assertEqual(resp.content_length, 0)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, slow=True)
    resp = controller.GET(req)
    self.assertEqual(resp.status_int, 200)
    self.assertEqual(resp.content_length, 4)
    def test_QUERY_proxy_passes_content_length(self):
    with save_globals():
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'HEAD'})
    self.app.update_request(req)
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = fake_http_connect(200, 200, 200)
    resp = controller.HEAD(req)
    self.assertEqual(resp.status_int, 200)
    self.assertEqual(resp.content_length, 0)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, slow=True)
    resp = controller.HEAD(req)
    self.assertEqual(resp.status_int, 200)
    self.assertEqual(resp.content_length, 4)
    def test_QUERY_error_limiting(self):
    with save_globals():
    proxy_server.shuffle = lambda l: None
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    self.assert_status_map(controller.HEAD, (503, 200, 200), 200)
    self.assertEqual(controller.app.object_ring.devs[0]['errors'], 2)
    self.assert_('last_error' in controller.app.object_ring.devs[0])
    for _junk in xrange(self.app.error_suppression_limit):
        self.assert_status_map(controller.HEAD, (503, 503, 503), 503)
    self.assertEqual(controller.app.object_ring.devs[0]['errors'],
                      self.app.error_suppression_limit + 1)
    self.assert_status_map(controller.HEAD, (200, 200, 200), 503)
    self.assert_('last_error' in controller.app.object_ring.devs[0])
    self.assert_status_map(controller.PUT, (200, 201, 201, 201), 503)
    self.assert_status_map(controller.POST,
                           (200, 200, 200, 200, 202, 202, 202), 503)
    self.assert_status_map(controller.DELETE,
                           (200, 204, 204, 204), 503)
    self.app.error_suppression_interval = -300
    self.assert_status_map(controller.HEAD, (200, 200, 200), 200)
    self.assertRaises(BaseException,
        self.assert_status_map, controller.DELETE,
        (200, 204, 204, 204), 503, raise_exc=True)
    def test_QUERY_acc_or_con_missing_returns_404(self):
    with save_globals():
    self.app.memcache = FakeMemcacheReturnsNone()
    for dev in self.app.account_ring.devs.values():
        del dev['errors']
        del dev['last_error']
    for dev in self.app.container_ring.devs.values():
        del dev['errors']
        del dev['last_error']
    controller = proxy_server.ObjectController(self.app, 'account',
                                             'container', 'object')
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 200)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'DELETE'})
    self.app.update_request(req)
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 200)

    proxy_server.http_connect = \
        fake_http_connect(404, 404, 404)
        #                 acct acct acct
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)

    proxy_server.http_connect = \
        fake_http_connect(503, 404, 404)
        #                 acct acct acct
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)

    proxy_server.http_connect = \
        fake_http_connect(503, 503, 404)
        #                 acct acct acct
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)

    proxy_server.http_connect = \
        fake_http_connect(503, 503, 503)
        #                 acct acct acct
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)

    proxy_server.http_connect = \
        fake_http_connect(200, 200, 204, 204, 204)
        #                 acct cont obj  obj  obj
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 204)

    proxy_server.http_connect = \
        fake_http_connect(200, 404, 404, 404)
        #                 acct cont cont cont
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)

    proxy_server.http_connect = \
        fake_http_connect(200, 503, 503, 503)
        #                 acct cont cont cont
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)

    for dev in self.app.account_ring.devs.values():
        dev['errors'] = self.app.error_suppression_limit + 1
        dev['last_error'] = time()
    proxy_server.http_connect = \
        fake_http_connect(200)
        #                 acct [isn't actually called since everything
        #                       is error limited]
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)

    for dev in self.app.account_ring.devs.values():
        dev['errors'] = 0
    for dev in self.app.container_ring.devs.values():
        dev['errors'] = self.app.error_suppression_limit + 1
        dev['last_error'] = time()
    proxy_server.http_connect = \
        fake_http_connect(200, 200)
        #                 acct cont [isn't actually called since
        #                            everything is error limited]
    resp = getattr(controller, 'DELETE')(req)
    self.assertEqual(resp.status_int, 404)
    def test_QUERY_PUT_POST_requires_container_exist(self):
    with save_globals():
    self.app.object_post_as_copy = False
    self.app.memcache = FakeMemcacheReturnsNone()
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')

    proxy_server.http_connect = \
        fake_http_connect(200, 404, 404, 404, 200, 200, 200)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'})
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 404)

    proxy_server.http_connect = \
        fake_http_connect(200, 404, 404, 404, 200, 200)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'POST'},
                        headers={'Content-Type': 'text/plain'})
    self.app.update_request(req)
    resp = controller.POST(req)
    self.assertEqual(resp.status_int, 404)
    def test_QUERY_PUT_POST_as_copy_requires_container_exist(self):
    with save_globals():
    self.app.memcache = FakeMemcacheReturnsNone()
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = \
        fake_http_connect(200, 404, 404, 404, 200, 200, 200)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'})
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 404)

    proxy_server.http_connect = \
        fake_http_connect(200, 404, 404, 404, 200, 200, 200, 200, 200,
                          200)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'POST'},
                        headers={'Content-Type': 'text/plain'})
    self.app.update_request(req)
    resp = controller.POST(req)
    self.assertEqual(resp.status_int, 404)
    def test_QUERY_bad_metadata(self):
    with save_globals():
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 201, 201, 201)
        #                 acct cont obj  obj  obj
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0'})
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)

    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
        headers={'Content-Length': '0',
                 'X-Object-Meta-' + ('a' *
                    MAX_META_NAME_LENGTH): 'v'})
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
        headers={'Content-Length': '0',
                 'X-Object-Meta-' + ('a' *
                    (MAX_META_NAME_LENGTH + 1)): 'v'})
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 400)

    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
        headers={'Content-Length': '0',
                 'X-Object-Meta-Too-Long': 'a' *
                    MAX_META_VALUE_LENGTH})
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
        headers={'Content-Length': '0',
                 'X-Object-Meta-Too-Long': 'a' *
                    (MAX_META_VALUE_LENGTH + 1)})
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 400)

    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    headers = {'Content-Length': '0'}
    for x in xrange(MAX_META_COUNT):
        headers['X-Object-Meta-%d' % x] = 'v'
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers=headers)
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    headers = {'Content-Length': '0'}
    for x in xrange(MAX_META_COUNT + 1):
        headers['X-Object-Meta-%d' % x] = 'v'
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers=headers)
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 400)

    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    headers = {'Content-Length': '0'}
    header_value = 'a' * MAX_META_VALUE_LENGTH
    size = 0
    x = 0
    while size < MAX_META_OVERALL_SIZE - 4 - \
            MAX_META_VALUE_LENGTH:
        size += 4 + MAX_META_VALUE_LENGTH
        headers['X-Object-Meta-%04d' % x] = header_value
        x += 1
    if MAX_META_OVERALL_SIZE - size > 1:
        headers['X-Object-Meta-a'] = \
            'a' * (MAX_META_OVERALL_SIZE - size - 1)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers=headers)
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    proxy_server.http_connect = fake_http_connect(201, 201, 201)
    headers['X-Object-Meta-a'] = \
        'a' * (MAX_META_OVERALL_SIZE - size)
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers=headers)
    self.app.update_request(req)
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 400)
    def test_QUERY_copy_from(self):
    with save_globals():
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    # initial source object PUT
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 201, 201, 201)
        #                 acct cont obj  obj  obj
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)

    # basic copy
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': 'c/o'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 200, 200, 201, 201,
            201)
        #                 acct cont acct cont objc objc objc obj  obj
        #   obj
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.assertEqual(resp.headers['x-copied-from'], 'c/o')

    # non-zero content length
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '5',
                                  'X-Copy-From': 'c/o'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 200, 200)
        #                 acct cont acct cont objc objc objc
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 400)

    # extra source path parsing
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': 'c/o/o2'})
    req.account = 'a'
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 200, 200, 201, 201,
            201)
        #                 acct cont acct cont objc objc objc obj  obj
        #   obj
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.assertEqual(resp.headers['x-copied-from'], 'c/o/o2')

    # space in soure path
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': 'c/o%20o2'})
    req.account = 'a'
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 200, 200, 201, 201,
            201)
        #                 acct cont acct cont objc objc objc obj  obj
        #   obj
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.assertEqual(resp.headers['x-copied-from'], 'c/o%20o2')

    # repeat tests with leading /
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': '/c/o'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 200, 200, 201, 201,
            201)
        #                 acct cont acct cont objc objc objc obj  obj
        #   obj
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.assertEqual(resp.headers['x-copied-from'], 'c/o')

    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': '/c/o/o2'})
    req.account = 'a'
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 200, 200, 201, 201,
            201)
        #                 acct cont acct cont objc objc objc obj  obj
        #   obj
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.assertEqual(resp.headers['x-copied-from'], 'c/o/o2')

    # negative tests

    # invalid x-copy-from path
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': '/c'})
    self.app.update_request(req)
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int // 100, 4)  # client error

    # server error
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': '/c/o'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 503, 503, 503)
        #                 acct cont objc objc objc
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 503)

    # not found
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': '/c/o'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 404, 404, 404)
        #                 acct cont objc objc objc
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 404)

    # some missing containers
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': '/c/o'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 404, 404, 200, 201, 201, 201)
        #                 acct cont objc objc objc obj  obj  obj
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)

    # test object meta data
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0',
                                  'X-Copy-From': '/c/o',
                                  'X-Object-Meta-Ours': 'okay'})
    self.app.update_request(req)
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 201, 201, 201)
        #                 acct cont objc objc objc obj  obj  obj
    self.app.memcache.store = {}
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int, 201)
    self.assertEqual(resp.headers.get('x-object-meta-test'),
                      'testing')
    self.assertEqual(resp.headers.get('x-object-meta-ours'), 'okay')
    def test_QUERY_client_ip_logging(self):
    # test that the client ip field in the log gets populated with the
    # ip instead of being blank
    (prosrv, acc1srv, acc2srv, con2srv, con2srv, obj1srv, obj2srv) = \
        _test_servers
    (prolis, acc1lis, acc2lis, con2lis, con2lis, obj1lis, obj2lis) = \
         _test_sockets

    class Logger(object):

    def info(self, msg):
        self.msg = msg

    orig_logger, orig_access_logger = prosrv.logger, prosrv.access_logger
    prosrv.logger = prosrv.access_logger = Logger()
    sock = connect_tcp(('localhost', prolis.getsockname()[1]))
    fd = sock.makefile()
    fd.write(
    'GET /v1/a?format=json HTTP/1.1\r\nHost: localhost\r\n'
    'Connection: close\r\nX-Auth-Token: t\r\n'
    'Content-Length: 0\r\n'
    '\r\n')
    fd.flush()
    headers = readuntil2crlfs(fd)
    exp = 'HTTP/1.1 200'
    self.assertEqual(headers[:len(exp)], exp)
    exp = '127.0.0.1 127.0.0.1'
    self.assert_(exp in prosrv.logger.msg)
    def test_QUERY_mismatched_etags(self):
    with save_globals():
    # no etag supplied, object servers return success w/ diff values
    controller = proxy_server.ObjectController(self.app, 'account',
                                               'container', 'object')
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'Content-Length': '0'})
    self.app.update_request(req)
    proxy_server.http_connect = fake_http_connect(200, 201, 201, 201,
        etags=[None,
               '68b329da9893e34099c7d8ad5cb9c940',
               '68b329da9893e34099c7d8ad5cb9c940',
               '68b329da9893e34099c7d8ad5cb9c941'])
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int // 100, 5)  # server error

    # req supplies etag, object servers return 422 - mismatch
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={
                            'Content-Length': '0',
                            'ETag': '68b329da9893e34099c7d8ad5cb9c940',
                        })
    self.app.update_request(req)
    proxy_server.http_connect = fake_http_connect(200, 422, 422, 503,
        etags=['68b329da9893e34099c7d8ad5cb9c940',
               '68b329da9893e34099c7d8ad5cb9c941',
               None,
               None])
    resp = controller.PUT(req)
    self.assertEqual(resp.status_int // 100, 4)  # client error
    def test_QUERY_copy_zero_bytes_transferred_attr(self):
    with save_globals():
    proxy_server.http_connect = \
        fake_http_connect(200, 200, 200, 200, 200, 201, 201, 201,
                          body='1234567890')
    controller = proxy_server.ObjectController(self.app, 'account',
                    'container', 'object')
    req = Request.blank('/a/c/o', environ={'REQUEST_METHOD': 'PUT'},
                        headers={'X-Copy-From': 'c/o2',
                                 'Content-Length': '0'})
    self.app.update_request(req)
    res = controller.PUT(req)
    self.assert_(hasattr(req, 'bytes_transferred'))
    self.assertEqual(req.bytes_transferred, 0)
    def test_QUERY_response_bytes_transferred_attr(self):
    with save_globals():
    proxy_server.http_connect = \
        fake_http_connect(200, body='1234567890')
    controller = proxy_server.ObjectController(self.app, 'account',
                    'container', 'object')
    req = Request.blank('/a/c/o')
    self.app.update_request(req)
    res = controller.GET(req)
    res.body
    self.assert_(hasattr(res, 'bytes_transferred'))
    self.assertEqual(res.bytes_transferred, 10)
    '''
