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

from zerocloud.proxyquery import CLUSTER_CONFIG_FILENAME, NODE_CONFIG_FILENAME

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

from zerocloud import proxyquery, objectquery

ZEROVM_DEFAULT_MOCK =\
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
parser.add_argument('-F', action='store_true', dest='validate')
args = parser.parse_args()

valid = 1
if args.skip:
    valid = 0
accounting = [0,0,0,0,0,0,0,0,0,0,0,0]
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
retrieve_mnfst_field('NexeMax', isint=True, optional=True)
retrieve_mnfst_field('SyscallsMax', min=1, isint=True, optional=True)
retrieve_mnfst_field('NexeEtag', optional=True)
retrieve_mnfst_field('Timeout', min=1, isint=True)
retrieve_mnfst_field('MemMax', min=32*1048576, max=4096*1048576, isint=True)
retrieve_mnfst_field('Environment', optional=True)
retrieve_mnfst_field('CommandLine', optional=True)
retrieve_mnfst_field('Channel')
retrieve_mnfst_field('NodeName', optional=True)
retrieve_mnfst_field('NameServer', optional=True)
exe = file(mnfst.Nexe, 'r').read()
if 'INVALID' == exe:
    valid = 2
    retcode = 0
    errdump(8, valid, retcode, '', accounting, 'nexe is invalid')
if args.validate:
    errdump(0, valid, retcode, '', accounting, 'nexe is valid')
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
mnfst.channels = {}
for fname,device,type,rd,rd_byte,wr,wr_byte in zip(*[iter(channel_list)]*7):
    if device == '/dev/stdin' or device == '/dev/input':
        mnfst.input = fname
    elif device == '/dev/stdout' or device == '/dev/output':
        mnfst.output = fname
    elif device == '/dev/stderr':
        mnfst.err = fname
    elif device == '/dev/image':
        mnfst.image = fname
    elif device == '/dev/nvram':
        mnfst.nvram = fname
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
    mnfst.channels[device] = {
        'path': fname,
        'type': type,
        'read': rd,
        'read_bytes': rd_byte,
        'write': wr,
        'write_bytes': wr_byte
    }
request = struct.pack('!I', alias) +\
          struct.pack('!I', bind_count) + bind_data + struct.pack('!I', connect_count) + connect_data
if getattr(mnfst, 'NameServer', None):
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
        obj_ring=FakeRing()
        obj_ring.partition_count = 1
        self.proxy_app = proxy_server.Application(None, FakeMemcache(),
            account_ring=FakeRing(), container_ring=FakeRing(),
            object_ring=obj_ring)
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
            fd, zerovm_mock = mkstemp()
            if mock:
                os.write(fd, mock)
            else:
                os.write(fd, ZEROVM_DEFAULT_MOCK)
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
        raise SkipTest
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
        raise SkipTest
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
                'name':'http',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                    {'device':'stdout', 'content_type': 'text/plain',
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
        conf = [{
                    "name": "hello",
                    "exec": { "path": "/c/hello.nexe" },
                    "file_list": [
                        { "device": "stdout" }
                    ]
                }]
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
                'name':'http',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                    {'device':'stdout', 'content_type': 'message/http',
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
        self.assertEqual(res.headers['content-type'], 'text/html')
        self.assertEqual(res.headers['x-object-meta-key1'], 'value1')
        self.assertEqual(res.headers['x-object-meta-key2'], 'value2')
        self.assertEqual(res.body, '<html><body>Test this</body></html>')
        conf = [
            {
                'name':'http',
                'exec':{'path':'/c/exe2'},
                'file_list':[
                    {
                        'device':'stdout',
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
        print res.headers
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
return [open(mnfst.image).read(), sorted(id)]
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
        _obj1srv = _test_servers[5]
        _obj2srv = _test_servers[6]
        image = 'This is image file'
        sysimage_path = os.path.join(_testdir, 'sysimage.tar')

        @contextmanager
        def replace_conf():
            zerovm_sysimage_devices = prosrv.app.zerovm_sysimage_devices
            zerovm_sysimage_devices1 = _obj1srv.zerovm_sysimage_devices
            zerovm_sysimage_devices2 = _obj2srv.zerovm_sysimage_devices
            img = open(sysimage_path, 'wb')
            img.write(image)
            img.close()
            prosrv.app.zerovm_sysimage_devices = ['sysimage']
            _obj1srv.zerovm_sysimage_devices = { 'sysimage': sysimage_path }
            _obj2srv.zerovm_sysimage_devices = { 'sysimage': sysimage_path }
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
        nexe =\
r'''
return open(mnfst.nvram).read() + \
    str(mnfst.channels['/dev/sysimage']['type']) + ' ' + \
    str(mnfst.channels['/dev/sysimage']['path'])
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        with replace_conf():
            conf = [
                {
                    'name':'sort',
                    'exec':{
                        'path':'/c/exe2'
                    },
                    'file_list':[
                        {'device':'stdin','path':'/c/o'},
                        {'device':'stdout'},
                        {'device':'sysimage'}
                    ]
                }
            ]
            conf = json.dumps(conf)
            req = self.zerovm_request()
            req.body = conf
            res = req.get_response(prosrv)
            self.assertEqual(res.status_int, 200)
            self.assertEqual(res.body,
                '[fstab]\n'
                'channel=/dev/sysimage, mountpoint=/, access=ro\n'
                '[args]\n'
                'args = sort\n'
                '%d %s' % (3, sysimage_path))

    def test_QUERY_use_nvram(self):
        self.setup_QUERY()
        prolis = _test_sockets[0]
        prosrv = _test_servers[0]
        nexe =\
r'''
return open(mnfst.nvram).read()
'''[1:-1]
        self.create_object(prolis, '/v1/a/c/exe2', nexe)
        conf = [
            {
                'name':'sort',
                'exec':{
                    'path':'/c/exe2'
                },
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
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
            '[args]\n'
            'args = sort\n')
        conf = [
            {
                'name':'sort',
                'exec':{
                    'path':'/c/exe2',
                    'args': 'aa bb cc'
                },
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
        self.assertEqual(res.status_int, 200)
        self.assertEqual(res.body,
            '[args]\n'
            'args = sort aa bb cc\n')
        image = 'This is image file'
        self.create_object(prolis, '/v1/a/c/img', image)
        conf = [
            {
                'name':'sort',
                'exec':{
                    'path':'/c/exe2'
                },
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
        self.assertEqual(res.body,
            '[fstab]\n'
            'channel=/dev/image, mountpoint=/, access=rw\n'
            '[args]\n'
            'args = sort\n')
        conf = [
            {
                'name':'sort',
                'exec':{
                    'path':'/c/exe2',
                    'args': 'aa bb cc',
                    'env': {
                        'key1': 'val1',
                        'key2': 'val2'
                    }
                },
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
        self.assertEqual(res.body,
            '[fstab]\n'
            'channel=/dev/image, mountpoint=/, access=rw\n'
            '[args]\n'
            'args = sort aa bb cc\n'
            '[env]\n'
            'key2 = val2\n'
            'key1 = val1\n')

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
        raise SkipTest
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
        raise SkipTest
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
            swift.proxy.controllers.account.http_connect = \
                fake_http_connect(200, 200, body='1234567890')
            swift.proxy.controllers.container.http_connect =\
                fake_http_connect(200, 200, body='1234567890')
            swift.proxy.controllers.obj.http_connect =\
                fake_http_connect(200, 200, 201, 201, 201, body='1234567890')
            controller = proxyquery.ProxyQueryMiddleware(self.proxy_app,{}).\
                get_controller('account', None, None)
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
            res = controller.POST(req)
            self.assertEqual(res.status_int, 200)

    def test_QUERY_config_parser(self):

        fake_controller = proxyquery.ProxyQueryMiddleware(
            self.proxy_app,{'zerovm_sysimage_devices': 'sysimage1 sysimage2'}).get_controller('a', None, None)
        conf = [
            {
                'name':'script',
                'exec':{
                    'path':'boot/lua',
                    'args':'my_script.lua'
                },
                'file_list':[
                    {
                        'device':'image',
                        'path':'/images/lua.img'
                    },
                    {
                        'device': 'stdin',
                        'path': '/c/input'
                    },
                    {
                        'device': 'sysimage1'
                    }
                ],
                'connect':['script'],
                'count':5
            }
        ]
        req = Request.blank('/a', environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/json'})
        error = fake_controller.parse_cluster_config(req, conf)
        self.assertIsNone(error)
        self.assertEqual(len(fake_controller.nodes), 5)
        #print json.dumps(fake_controller.nodes,
        #    cls=proxyquery.NodeEncoder, indent='  ')
