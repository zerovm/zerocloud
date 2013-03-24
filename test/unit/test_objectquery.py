from contextlib import contextmanager
from StringIO import StringIO
import traceback

try:
    import simplejson as json
except ImportError:
    import json
import logging
from posix import rmdir
import struct
import unittest
import os
import random
import cPickle as pickle
from time import time, sleep
from eventlet import GreenPool
from unittest.case import SkipTest
from hashlib import md5
from tempfile import mkstemp, mkdtemp
from shutil import rmtree
from copy import copy
import math
import tarfile

from swift.common import utils
from swift.common.swob import Request
from swift.common.utils import mkdirs, normalize_timestamp, get_logger
from swift.obj.server import ObjectController
from test.unit import FakeLogger

from zerocloud import objectquery
from zerocloud.proxyquery import ZvmNode, NodeEncoder, ACCESS_READABLE, ACCESS_WRITABLE, ACCESS_CDR

class FakeLoggingHandler(logging.Handler):

    def __init__(self, *args, **kwargs):
        self.reset()
        logging.Handler.__init__(self, *args, **kwargs)

    def emit(self, record):
        self.messages[record.levelname.lower()].append(record.getMessage())

    def reset(self):
        self.messages = {
            'debug': [],
            'info': [],
            'warning': [],
            'error': [],
            'critical': [],
            }


class FakeApp(ObjectController):
    def __init__(self, conf):
        ObjectController.__init__(self, conf)
        self.bytes_per_sync = 1
        self.fault = False

    def __call__(self, env, start_response):
        if self.fault:
            raise Exception
        ObjectController.__call__(self, env, start_response)

class OsMock():
    def __init__(self):
        self.closed = False
        self.unlinked = False
        self.path = os.path
        self.SEEK_SET = os.SEEK_SET

    def close(self, fd):
        self.closed = True
        raise OSError

    def unlink(self, fd):
        self.unlinked = True
        raise OSError

    def write(self, fd, str):
        return os.write(fd, str)

    def read(self, fd, bufsize):
        return os.read(fd, bufsize)

    def lseek(self, fd, pos, how):
        return os.lseek(fd, pos, how)

class TestObjectQuery(unittest.TestCase):
    def setUp(self):
        utils.HASH_PATH_SUFFIX = 'endcap'
        self.testdir =\
        os.path.join(mkdtemp(), 'tmp_test_object_server_ObjectController')
        mkdirs(os.path.join(self.testdir, 'sda1', 'tmp'))
        self.conf = {'devices': self.testdir,
                     'mount_check': 'false',
                     'disable_fallocate': 'true' }
        self.obj_controller = FakeApp(self.conf)
        self.app = objectquery.ObjectQueryMiddleware(self.obj_controller, self.conf, logger=FakeLogger())
        self.app.zerovm_maxoutput = 1024 * 1024 * 10

    def tearDown(self):
        """ Tear down for testing swift.object_server.ObjectController """
        rmtree(os.path.dirname(self.testdir))

    def setup_zerovm_query(self, mock=None):
        def set_zerovm_mock():
            default_mock = \
r'''
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
exe = file(mnfst.Nexe, 'r').read()
if 'INVALID' == exe:
    valid = 2
    retcode = 0
if args.validate:
    print '%d\n%d\n%s\n%s\n%s' % (valid, retcode, '',
    ' '.join([str(val) for val in accounting]), status)
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
    errdump(1,valid,0,mnfst.Nexe,accounting,'wrong channel config: %s' % mnfst.Channel)
dev_list = channel_list[1::7]
for i in xrange(0,len(dev_list)):
    device = dev_list[i]
    fname = channel_list[i*7]
    if device == '/dev/stdin' or device == '/dev/input' or device == '/dev/cdr':
        mnfst.input = fname
    elif device == '/dev/stdout' or device == '/dev/output':
        mnfst.output = fname
    elif device == '/dev/stderr':
        logging.basicConfig(filename=fname,level=logging.DEBUG,filemode='w')
if valid < 2:
    try:
        inf = file(mnfst.input, 'r')
        ouf = file(mnfst.output, 'w')
        ins = inf.read()
        accounting[4] += 1
        accounting[5] += len(ins)
        id = pickle.loads(ins)
    except EOFError:
        id = []
    except Exception:
        errdump(1,valid,0,mnfst.Nexe,accounting,'Std files I/O error')

    od = ''
    try:
        od = str(eval_as_function(exe))
    except Exception:
        logging.exception('Exception:')
    ouf.write(od)
    accounting[6] += 1
    accounting[7] += len(od)
    inf.close()
    ouf.close()
    status = 'ok.'
print '%d\n%d\n%s\n%s\n%s' % (valid, retcode, mnfst.NexeEtag,
    ' '.join([str(val) for val in accounting]), status)
logging.info('finished')
exit(0)
'''
            # ensure that python executable is used
            fd, zerovm_mock = mkstemp()
            if mock:
                os.write(fd, mock)
            else:
                os.write(fd, default_mock)
            self.app.zerovm_exename = ['python', zerovm_mock]
            # do not set it lower than 2 * BLOCKSIZE (2 * 512)
            # it will break tar RPC protocol
            self.app.app.network_chunk_size = 2 * 512

        set_zerovm_mock()
        randomnumbers = self.create_random_numbers(10)
        self.create_object(randomnumbers)
        self._nexescript = 'return pickle.dumps(sorted(id))'
        self._sortednumbers = self.get_sorted_numbers()
        self._randomnumbers_etag = md5()
        self._randomnumbers_etag.update(randomnumbers)
        self._randomnumbers_etag = self._randomnumbers_etag.hexdigest()
        self._sortednumbers_etag = md5()
        self._sortednumbers_etag.update(self._sortednumbers)
        self._sortednumbers_etag = self._sortednumbers_etag.hexdigest()
        self._nexescript_etag = md5()
        self._nexescript_etag.update(self._nexescript)
        self._nexescript_etag = self._nexescript_etag.hexdigest()
        self._stderr = 'INFO:root:finished\n'
        self._emptyresult = '(l.'
        self._emptyresult_etag = md5()
        self._emptyresult_etag.update(self._emptyresult)
        self._emptyresult_etag = self._emptyresult_etag.hexdigest()

    def create_random_numbers(self, max_num, proto='pickle'):
        numlist = [i for i in range(max_num)]
        for i in range(max_num):
            randindex1 = random.randrange(max_num)
            randindex2 = random.randrange(max_num)
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

    def create_object(self, body, path='/sda1/p/a/c/o'):
        timestamp = normalize_timestamp(time())
        headers = {'X-Timestamp': timestamp,
                   'Content-Type': 'application/octet-stream'}
        req = Request.blank(path,
            environ={'REQUEST_METHOD': 'PUT'}, headers=headers)
        req.body = body
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 201)

    def zerovm_request(self):
        req = Request.blank('/sda1/p/a/c/o',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/x-gtar',
                     'x-zerovm-execute': '1.0',
                     'x-account-name': 'a'})
        return req

    @contextmanager
    def create_tar(self, dict):
        tarfd, tarname = mkstemp()
        os.close(tarfd)
        tar = tarfile.open(name=tarname, mode='w')
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

    def test_tmpdir_mkstemp_creates_dir(self):
        tmpdir = os.path.join(self.testdir, 'sda1', 'tmp')
        os.rmdir(tmpdir)
        with objectquery.TmpDir(tmpdir, 'sda1').mkstemp():
            self.assert_(os.path.exists(tmpdir))

    def test_QUERY_realzvm(self):
        raise SkipTest
        self.setup_zerovm_query()
        self.app.zerovm_exename = ['./zerovm']
        randomnum = self.create_random_numbers(1024 * 1024 / 4, proto='binary')
        self.create_object(randomnum, path='/sda1/p/a/c/o_binary')
        req = Request.blank('/sda1/p/a/c/o_binary',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/octet-stream',
                     'x-zerovm-execute': '1.0',
                     'x-nexe-args': '%d' % (1024 * 1024)})
        fd = open('sort.nexe')
        real_nexe = fd.read()
        fd.close()
        etag = md5(real_nexe)
        etag = etag.hexdigest()
        req.headers['etag'] = etag
        req.headers['x-nexe-content-type'] = 'text/plain'
        req.body = real_nexe
        resp = self.app.zerovm_query(req)
        #resp = req.get_response(self.app)

        sortednum = self.get_sorted_numbers(min_num=0, max_num=1024 * 1024 / 4, proto='binary')
        self.assertEquals(resp.status_int, 200)
        #fd = open('resp.sorted', 'w')
        #fd.write(resp.body)
        #fd.close()
        #fd = open('my.sorted', 'w')
        #fd.write(sortednum)
        #fd.close()
        self.assertEquals(resp.body, sortednum)
        self.assertEquals(resp.content_length, len(sortednum))
        self.assertEquals(resp.content_type, 'text/plain')
        self.assertEquals(resp.headers['content-length'],
            str(len(sortednum)))
        self.assertEquals(resp.headers['content-type'], 'text/plain')
        self.assertEquals(resp.headers['x-nexe-etag'], 'disabled')
        self.assertEquals(resp.headers['x-nexe-retcode'], 0)
        self.assertEquals(resp.headers['x-nexe-status'], 'ok')
        #timestamp = normalize_timestamp(time())
        #self.assertEquals(math.floor(float(resp.headers['X-Timestamp'])),
        #    math.floor(float(timestamp)))

    def test_QUERY_sort(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            #resp = req.get_response(self.app)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[-1], 'stdout')
            self.assertEqual(members[-1].size, len(self._sortednumbers))
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(), self._sortednumbers)
            self.assertEqual(resp.headers['x-nexe-retcode'], '0')
            self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
            self.assertEqual(resp.headers['x-nexe-validation'], '1')
            self.assertEqual(resp.headers['x-nexe-system'], 'sort')
            timestamp = normalize_timestamp(time())
            self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                math.floor(float(timestamp)))
            self.assertEquals(resp.headers['content-type'], 'application/x-gtar')
            self.assertEqual(self.app.logger.log_dict['info'][0][0][0],
                'Zerovm CDR: 0 0 0 0 1 46 1 46 0 0 0 0')

    def test_QUERY_sort_textout(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO('return str(sorted(id))')
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            #resp = req.get_response(self.app)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[-1], 'stdout')
            #self.assertEqual(members[-1].size, len(self._sortednumbers))
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(), '[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]')
            self.assertEqual(resp.headers['x-nexe-retcode'], '0')
            self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
            self.assertEqual(resp.headers['x-nexe-validation'], '1')
            self.assertEqual(resp.headers['x-nexe-system'], 'sort')
            timestamp = normalize_timestamp(time())
            self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                math.floor(float(timestamp)))
            self.assertEquals(resp.headers['content-type'], 'application/x-gtar')
            self.assertEqual(self.app.logger.log_dict['info'][0][0][0],
                'Zerovm CDR: 0 0 0 0 1 46 1 30 0 0 0 0')

    def test_QUERY_http_message(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE, content_type='message/http')
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        nexefile = StringIO(r'''
resp = '\n'.join([
    'HTTP/1.1 200 OK',
    'Content-Type: application/json',
    'X-Object-Meta-Key1: value1',
    'X-Object-Meta-Key2: value2',
    '', ''
    ])
out = str(sorted(id))
return resp + out
'''[1:-1])
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            #resp = req.get_response(self.app)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[-1], 'stdout')
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(), '[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]')
            self.assertEqual(resp.headers['x-nexe-retcode'], '0')
            self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
            self.assertEqual(resp.headers['x-nexe-validation'], '1')
            self.assertEqual(resp.headers['x-nexe-system'], 'sort')
            timestamp = normalize_timestamp(time())
            self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                math.floor(float(timestamp)))
            self.assertEquals(resp.headers['content-type'], 'application/x-gtar')
            self.assertEqual(names[0], 'sysmap')
            file = tar.extractfile(members[0])
            config = json.load(file)
            self.assertEqual(
                config['channels'][1]['content_type'],
                'application/json')
            self.assertEqual(
                config['channels'][1]['meta'],
                { 'key1': 'value1', 'key2': 'value2' })

    def test_QUERY_invalid_http_message(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE, content_type='message/http')
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        nexefile = StringIO('''
resp = '\\n'.join(['Status: 200 OK', 'Content-Type: application/json', '', ''])
out = str(sorted(id))
return resp + out
'''[1:-1])
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            #resp = req.get_response(self.app)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[-1], 'stdout')
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(),
                'Status: 200 OK\n'
                'Content-Type: application/json\n\n'
                '[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]')
            self.assertEqual(resp.headers['x-nexe-retcode'], '0')
            self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
            self.assertEqual(resp.headers['x-nexe-validation'], '1')
            self.assertEqual(resp.headers['x-nexe-system'], 'sort')
            timestamp = normalize_timestamp(time())
            self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                math.floor(float(timestamp)))
            self.assertEqual(resp.headers['content-type'], 'application/x-gtar')
            self.assertEqual(names[0], 'sysmap')
            file = tar.extractfile(members[0])
            config = json.load(file)
            self.assertEqual(config['channels'][1]['content_type'], 'message/http')

    def test_QUERY_invalid_nexe(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO('INVALID')
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            #resp = req.get_response(self.app)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[-1], 'stdout')
            self.assertEqual(members[-1].size, 0)
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(), '')
            self.assertEqual(resp.headers['x-nexe-retcode'], '0')
            self.assertEqual(resp.headers['x-nexe-status'], 'nexe did not run')
            self.assertEqual(resp.headers['x-nexe-validation'], '2')
            self.assertEqual(resp.headers['x-nexe-system'], 'sort')
            timestamp = normalize_timestamp(time())
            self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                math.floor(float(timestamp)))
            self.assertEqual(resp.headers['content-type'], 'application/x-gtar')
            self.assertEqual(self.app.logger.log_dict['info'][0][0][0],
                'Zerovm CDR: 0 0 0 0 0 0 0 0 0 0 0 0')

    def test_QUERY_freenode(self):
        # check running code without input file
        self.setup_zerovm_query()
        rmdir(os.path.join(self.testdir, 'sda1', 'tmp'))
        req = Request.blank('/sda1/p/a',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/x-gtar',
                     'x-zerovm-execute': '1.0', 'x-account-name': 'a' })
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            #resp = req.get_response(self.app)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[-1], 'stdout')
            self.assertEqual(members[-1].size, len(self._emptyresult))
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(), self._emptyresult)
            self.assertEqual(resp.headers['x-nexe-retcode'], '0')
            self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
            self.assertEqual(resp.headers['x-nexe-validation'], '1')
            self.assertEqual(resp.headers['x-nexe-system'], 'sort')
            timestamp = normalize_timestamp(time())
            self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                math.floor(float(timestamp)))
            self.assertEqual(resp.headers['content-type'], 'application/x-gtar')
            self.assertEqual(self.app.logger.log_dict['info'][0][0][0],
                'Zerovm CDR: 0 0 0 0 1 0 1 3 0 0 0 0')

    def test_QUERY_OsErr(self):
        def mock(*args):
            raise Exception('Mock lseek failed')
        self.app.os_interface = OsMock()
        self.setup_zerovm_query()
        req = Request.blank('/sda1/p/a',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/x-gtar',
                     'x-zerovm-execute': '1.0', 'x-account-name': 'a' })
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            #resp = req.get_response(self.app)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[-1], 'stdout')
            self.assertEqual(members[-1].size, len(self._emptyresult))
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(), self._emptyresult)

        del self.app.zerovm_maxoutput
        self.setup_zerovm_query()
        req = Request.blank('/sda1/p/a',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/x-gtar',
                     'x-zerovm-execute': '1.0', 'x-account-name': 'a' })
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            raised = False
            try:
                resp = self.app.zerovm_query(req)
            except Exception:
                raised = True
            self.assert_(raised, "Exception not raised")

        self.setup_zerovm_query()
        req = Request.blank('/sda1/p/a',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/x-gtar',
                     'x-zerovm-execute': '1.0', 'x-account-name': 'a' })
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stderr', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            raised = False
            try:
                resp = self.app.zerovm_query(req)
            except Exception:
                raised = True
            self.assert_(raised, "Exception not raised")

    def test_QUERY_nexe_environment(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf.args = 'aaa bbb'
        conf.env = {'KEY_A': 'value_a', 'KEY_B': 'value_b'}
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEquals(resp.status_int, 200)

    def test_QUERY_multichannel(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('input', ACCESS_READABLE, '/c/o')
        conf.add_channel('output', ACCESS_WRITABLE, '/c/o2')
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEquals(resp.status_int, 200)

    def test_QUERY_std_list(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE, '/c/o2')
        conf.add_channel('stderr', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEquals(resp.status_int, 200)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            members = tar.getmembers()
            self.assertIn('stderr', names)
            self.assertEqual(names[-1], 'stderr')
            self.assertEqual(members[-1].size, len(self._stderr))
            file = tar.extractfile(members[-1])
            self.assertEqual(file.read(), self._stderr)
            self.assertIn('stdout', names)
            self.assertEqual(names[0], 'stdout')
            self.assertEqual(members[0].size, len(self._sortednumbers))
            file = tar.extractfile(members[0])
            self.assertEqual(file.read(), self._sortednumbers)

    def test_QUERY_logger(self):
        # check logger assignment
        logger = get_logger({}, log_route='obj-query-test')
        self.app = objectquery.ObjectQueryMiddleware(self.obj_controller, self.conf, logger)
        self.assertIs(logger, self.app.logger)

    def test_QUERY_object_not_exists(self):
        # check if querying non existent object
        req = self.zerovm_request()
        req.body = ('SCRIPT')
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 404)

    def test_QUERY_invalid_path(self):
        # check if just querying container fails
        req = Request.blank('/sda1/p/a/c',
            environ={'REQUEST_METHOD': 'POST'},
            headers={'x-zerovm-execute': '1.0', 'x-account-name': 'a' })
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 400)

    def test_QUERY_max_upload_time(self):
        class SlowBody():
            def __init__(self, body):
                self.body = body

            def read(self, size=-1):
                return self.body.read(10)

        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            fp = open(tar, 'rb')
            req.body_file = SlowBody(fp)
            resp = req.get_response(self.app)
            fp.close()
            self.assertEquals(resp.status_int, 200)
            fd, name = mkstemp()
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar_out = tarfile.open(name)
            names = tar_out.getnames()
            members = tar_out.getmembers()
            self.assertIn('stdout', names)
            self.assertEqual(names[0], 'stdout')
            self.assertEqual(members[0].size, len(self._sortednumbers))
            file = tar_out.extractfile(members[0])
            self.assertEqual(file.read(), self._sortednumbers)
            orig_max_upload_time = self.obj_controller.max_upload_time
            self.obj_controller.max_upload_time = 0.001
            fp = open(tar, 'rb')
            req.body_file = SlowBody(fp)
            resp = req.get_response(self.app)
            fp.close()
            self.obj_controller.max_upload_time = orig_max_upload_time
            self.assertEquals(resp.status_int, 408)

    def test_QUERY_no_content_type(self):
        req = self.zerovm_request()
        del req.headers['Content-Type']
        req.body = ('SCRIPT')
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 400)
        self.assert_('No content type' in resp.body)

    def test_QUERY_invalid_content_type(self):
        req = self.zerovm_request()
        req.headers['Content-Type'] = 'application/blah-blah-blah'
        req.body = ('SCRIPT')
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 400)
        self.assert_('Invalid Content-Type' in resp.body)

    def test_QUERY_invalid_path_encoding(self):
        req = Request.blank('/sda1/p/a/c/o'.encode('utf-16'),
            environ={'REQUEST_METHOD': 'POST'},
            headers={'Content-Type': 'application/x-gtar',
                     'x-zerovm-execute': '1.0', 'x-account-name': 'a' })
        req.body = ('SCRIPT')
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 412)
        self.assert_('Invalid UTF8' in resp.body)

    def test_QUERY_error_upstream(self):
        self.obj_controller.fault = True
        req = Request.blank('/sda1/p/a/c/o',
            environ={'REQUEST_METHOD': 'GET'},
            headers={'Content-Type': 'application/x-gtar'})
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 500)
        self.assert_('Traceback' in resp.body)

    def test_QUERY_script_invalid_etag(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            fp = open(tar, 'rb')
            etag = md5()
            etag.update(fp.read())
            fp.close()
            req.headers['etag'] = etag.hexdigest()
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEquals(resp.status_int, 200)
            etag = md5()
            etag.update('blah-blah')
            req.headers['etag'] = etag.hexdigest()
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEquals(resp.status_int, 422)

    def test_QUERY_short_body(self):
        class ShortBody():
            def __init__(self):
                self.sent = False

            def read(self, size=-1):
                if not self.sent:
                    self.sent = True
                    return '   '
                return ''

        self.setup_zerovm_query()
        req = Request.blank('/sda1/p/a/c/o',
            environ={'REQUEST_METHOD': 'POST', 'wsgi.input': ShortBody()},
            headers={'X-Timestamp': normalize_timestamp(time()),
                     'x-zerovm-execute': '1.0',
                     'x-account-name': 'a',
                     'Content-Length': '4',
                     'Content-Type': 'application/x-gtar'})
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 499)

    def test_QUERY_long_body(self):
        class LongBody():
            def __init__(self):
                self.sent = False

            def read(self, size=-1):
                if not self.sent:
                    self.sent = True
                    return '   '
                return ''

        self.setup_zerovm_query()
        req = Request.blank('/sda1/p/a/c/o',
            environ={'REQUEST_METHOD': 'POST', 'wsgi.input': LongBody()},
            headers={'X-Timestamp': normalize_timestamp(time()),
                     'x-zerovm-execute': '1.0',
                     'x-account-name': 'a',
                     'Content-Length': '2',
                     'Content-Type': 'application/x-gtar'})
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 499)

    def test_QUERY_zerovm_stderr(self):
        self.setup_zerovm_query(
r'''
import sys
sys.stderr.write('some shit happened\n')
''')
        req = self.zerovm_request()

        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEquals(resp.status_int, 200)
            self.assertEqual(resp.headers['x-nexe-retcode'], '0')
            self.assertEqual(resp.headers['x-nexe-status'], 'Zerovm crashed')
            self.assertEqual(resp.headers['x-nexe-validation'], '0')
            self.assertEqual(resp.headers['x-nexe-system'], 'sort')

        self.setup_zerovm_query(
r'''
import sys
import time
sys.stdout.write('0\n\nok.\n')
for i in range(20):
    time.sleep(0.1)
    sys.stderr.write(''.zfill(4096))
''')
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEqual(resp.status_int, 503)
            self.assertIn('ERROR OBJ.QUERY retcode=Output too long', resp.body)

        self.setup_zerovm_query(
r'''
import sys, time, signal
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(0.9)
sys.stdout.write('0\n\nok.\n')
sys.stderr.write(''.zfill(4096*20))
''')
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            orig_timeout = self.app.zerovm_timeout
            try:
                self.app.zerovm_timeout = 1
                req.body_file = open(tar, 'rb')
                resp = self.app.zerovm_query(req)
                self.assertEqual(resp.status_int, 503)
                self.assertIn('ERROR OBJ.QUERY retcode=Output too long', resp.body)
            finally:
                self.app.zerovm_timeout = orig_timeout

    def test_QUERY_zerovm_term_timeouts(self):
        self.setup_zerovm_query(
r'''
from time import sleep
sleep(10)
''')
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            orig_timeout = None if not\
            hasattr(self.app, 'zerovm_timeout') else\
            self.app.zerovm_timeout
            try:
                self.app.zerovm_timeout = 1
                resp = self.app.zerovm_query(req)
                self.assertEquals(resp.status_int, 503)
                self.assertIn('ERROR OBJ.QUERY retcode=Timed out', resp.body)
            finally:
                self.app.zerovm_timeout = orig_timeout

    def test_QUERY_zerovm_kill_timeouts(self):
        self.setup_zerovm_query(
r'''
import signal, time
signal.signal(signal.SIGTERM, signal.SIG_IGN)
time.sleep(10)
''')
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            orig_timeout = self.app.zerovm_timeout
            orig_kill_timeout = self.app.zerovm_kill_timeout
            try:
                self.app.zerovm_timeout = 1
                self.app.zerovm_kill_timeout = 1
                resp = self.app.zerovm_query(req)
                self.assertEquals(resp.status_int, 503)
                self.assertIn('ERROR OBJ.QUERY retcode=Killed', resp.body)
            finally:
                self.app.zerovm_timeout = orig_timeout
                self.app.zerovm_kill_timeout = orig_kill_timeout

    def test_QUERY_simulteneous_running_zerovm_limits(self):
        self.setup_zerovm_query()
        nexefile = StringIO('return sleep(.2)')
        conf = ZvmNode(1, 'sleep', '/c/exe')
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        maxreq_factor = 2
        r = range(0, maxreq_factor * 5)
        req = copy(r)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            orig_zerovm_maxqueue = self.app.zerovm_maxqueue
            orig_zerovm_maxpool = self.app.zerovm_maxpool
            orig_timeout = self.app.zerovm_timeout
            try:
                self.app.zerovm_timeout = 5
                pool = GreenPool()
                t = copy(r)

                def make_requests_storm(queue_factor, pool_factor):
                    for i in r:
                        req[i] = self.zerovm_request()
                        req[i].body_file = open(tar, 'rb')
                    self.app.zerovm_maxqueue =\
                        int(maxreq_factor * queue_factor * 5)
                    self.app.zerovm_maxpool =\
                        int(maxreq_factor * pool_factor * 5)
                    self.app.zerovm_thrdpool = GreenPool(self.app.zerovm_maxpool)
                    spil_over = self.app.zerovm_maxqueue\
                        + self.app.zerovm_maxpool
                    for i in r:
                        t[i] = pool.spawn(self.app.zerovm_query, req[i])
                    pool.waitall()
                    resp = copy(r)
                    for i in r[:spil_over]:
                        resp[i] = t[i].wait()
                        #print 'expecting ok #%s: %s' % (i, resp[i])
                        self.assertEqual(resp[i].status_int, 200)
                    for i in r[spil_over:]:
                        resp[i] = t[i].wait()
                        #print 'expecting fail #%s: %s' % (i, resp[i])
                        self.assertEqual(resp[i].status_int, 503)
                        self.assertEqual(resp[i].body, 'Slot not available')

                make_requests_storm(0.2, 0.4)
                make_requests_storm(0, 1)
                make_requests_storm(0.4, 0.6)
                make_requests_storm(0, 0.1)

            finally:
                self.app.zerovm_timeout = orig_timeout
                self.app.zerovm_maxqueue = orig_zerovm_maxqueue
                self.app.zerovm_maxpool = orig_zerovm_maxpool

    def test_QUERY_max_input_size(self):
        self.setup_zerovm_query()
        orig_maxinput = getattr(self.app, 'zerovm_maxinput')
        try:
            self.app.zerovm_maxinput = 0
            req = self.zerovm_request()
            req.body = 'xxxxxxxxx'
            resp = req.get_response(self.app)
            self.assertEqual(resp.status_int, 413)
            self.assertEqual(resp.body, 'RPC request too large')

            nexefile = StringIO(self._nexescript)
            conf = ZvmNode(1, 'sort', '/c/exe')
            conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
            conf.add_channel('stdout', ACCESS_WRITABLE)
            conf = json.dumps(conf, cls=NodeEncoder)
            sysmap = StringIO(conf)
            with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
                self.create_object(self.create_random_numbers(os.path.getsize(tar) + 2))
                self.app.zerovm_maxinput = os.path.getsize(tar) + 1
                req = self.zerovm_request()
                req.body_file = open(tar, 'rb')
                resp = self.app.zerovm_query(req)
                self.assertEqual(resp.status_int, 413)
                self.assertEqual(resp.body, 'Data object too large')
        finally:
            self.create_object(self.create_random_numbers(10))
            self.app.zerovm_maxinput = orig_maxinput

    def test_QUERY_max_nexe_size(self):
        self.setup_zerovm_query()
        orig_maxnexe = getattr(self.app, 'zerovm_maxnexe')
        try:
            setattr(self.app, 'zerovm_maxnexe', 0)
            req = self.zerovm_request()
            nexefile = StringIO(self._nexescript)
            conf = ZvmNode(1, 'sort', '/c/exe')
            conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
            conf.add_channel('stdout', ACCESS_WRITABLE)
            conf = json.dumps(conf, cls=NodeEncoder)
            sysmap = StringIO(conf)
            with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
                req.body_file = open(tar, 'rb')
                resp = self.app.zerovm_query(req)
                self.assertEquals(resp.status_int, 200)
                self.assertEqual(resp.headers['x-nexe-retcode'], '0')
                self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
                self.assertEqual(resp.headers['x-nexe-validation'], '1')
                self.assertEqual(resp.headers['x-nexe-system'], 'sort')
        finally:
            setattr(self.app, 'zerovm_maxnexe', orig_maxnexe)

    def test_QUERY_bad_system_map(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = '{""}'
        sysmap = StringIO(conf)
        with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEqual(resp.status_int, 400)
            self.assertEqual(resp.body, 'Cannot parse system map')
        with self.create_tar({'boot': nexefile}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            self.assertEqual(resp.status_int, 400)
            self.assertEqual(resp.body, 'No system map found in request')

    def test_QUERY_use_image_file(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', 'usr/bin/sort')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf.add_channel('image', ACCESS_CDR)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'usr/bin/sort': nexefile}) as image_tar:
            with self.create_tar({'image': open(image_tar, 'rb'), 'sysmap': sysmap}) as tar:
                req.body_file = open(tar, 'rb')
                resp = self.app.zerovm_query(req)
                fd, name = mkstemp()
                self.assertEqual(resp.status_int, 200)
                for chunk in resp.app_iter:
                    os.write(fd, chunk)
                os.close(fd)
                self.assertEqual(os.path.getsize(name), resp.content_length)
                tar = tarfile.open(name)
                names = tar.getnames()
                members = tar.getmembers()
                self.assertIn('stdout', names)
                self.assertEqual(names[-1], 'stdout')
                self.assertEqual(members[-1].size, len(self._sortednumbers))
                file = tar.extractfile(members[-1])
                self.assertEqual(file.read(), self._sortednumbers)
                self.assertEqual(resp.headers['x-nexe-retcode'], '0')
                self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
                self.assertEqual(resp.headers['x-nexe-validation'], '1')
                self.assertEqual(resp.headers['x-nexe-system'], 'sort')
                timestamp = normalize_timestamp(time())
                self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                    math.floor(float(timestamp)))
                self.assertEquals(resp.headers['content-type'], 'application/x-gtar')
                self.assertEqual(self.app.logger.log_dict['info'][0][0][0],
                    'Zerovm CDR: 0 0 0 0 1 46 1 46 0 0 0 0')

    def test_QUERY_bypass_image_file(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, '/c/o')
        conf.add_channel('stdout', ACCESS_WRITABLE)
        conf.add_channel('image', ACCESS_CDR)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'usr/bin/sort': StringIO('bla-bla')}) as image_tar:
            with self.create_tar({'image': open(image_tar, 'rb'), 'sysmap': sysmap, 'boot': nexefile}) as tar:
                req.body_file = open(tar, 'rb')
                resp = self.app.zerovm_query(req)
                fd, name = mkstemp()
                self.assertEqual(resp.status_int, 200)
                for chunk in resp.app_iter:
                    os.write(fd, chunk)
                os.close(fd)
                self.assertEqual(os.path.getsize(name), resp.content_length)
                tar = tarfile.open(name)
                names = tar.getnames()
                members = tar.getmembers()
                self.assertIn('stdout', names)
                self.assertEqual(names[-1], 'stdout')
                self.assertEqual(members[-1].size, len(self._sortednumbers))
                file = tar.extractfile(members[-1])
                self.assertEqual(file.read(), self._sortednumbers)
                self.assertEqual(resp.headers['x-nexe-retcode'], '0')
                self.assertEqual(resp.headers['x-nexe-status'], 'ok.')
                self.assertEqual(resp.headers['x-nexe-validation'], '1')
                self.assertEqual(resp.headers['x-nexe-system'], 'sort')
                timestamp = normalize_timestamp(time())
                self.assertEqual(math.floor(float(resp.headers['X-Timestamp'])),
                    math.floor(float(timestamp)))
                self.assertEquals(resp.headers['content-type'], 'application/x-gtar')
                self.assertEqual(self.app.logger.log_dict['info'][0][0][0],
                    'Zerovm CDR: 0 0 0 0 1 46 1 46 0 0 0 0')

    def test_QUERY_bad_channel_path(self):
        self.setup_zerovm_query()
        req = self.zerovm_request()
        nexefile = StringIO(self._nexescript)
        conf = ZvmNode(1, 'sort', '/c/exe')
        conf.add_channel('stdin', ACCESS_READABLE, 'bla-bla')
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with self.create_tar({'sysmap': sysmap, 'boot': nexefile}) as tar:
            req.body_file = open(tar, 'rb')
            resp = self.app.zerovm_query(req)
            fd, name = mkstemp()
            self.assertEqual(resp.status_int, 400)
            self.assertEqual(resp.body, 'Could not resolve channel path: bla-bla')

    def test_QUERY_mount_check(self):
        self.setup_zerovm_query()
        orig_mountcheck = getattr(self.obj_controller, 'mount_check')
        self.obj_controller.mount_check = True
        req = self.zerovm_request()
        req.headers['etag'] = self._nexescript_etag
        req.body = self._nexescript
        resp = req.get_response(self.app)

        self.assertEquals(resp.status_int, 507)
        setattr(self.obj_controller, 'mount_check', orig_mountcheck)

    def test_QUERY_filter_factory(self):
        app = objectquery.filter_factory(self.conf)(FakeApp(self.conf))
        self.assertIsInstance(app, objectquery.ObjectQueryMiddleware)

    def test_QUERY_prevalidate(self):
        self.setup_zerovm_query()
        req = Request.blank('/sda1/p/a/c/exe',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Timestamp': normalize_timestamp(time()),
                     'x-validator-exec': '',
                     'Content-Type': 'application/octet-stream'})
        req.body = self._nexescript
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 201)
        self.assertEquals(resp.headers['x-nexe-validation'], '0')

        req = Request.blank('/sda1/p/a/c/exe',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Timestamp': normalize_timestamp(time()),
                     'x-validator-exec': 'fuzzy',
                     'Content-Type': 'application/octet-stream'})
        req.body = self._nexescript
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 201)
        self.assertEquals(resp.headers['x-nexe-validation'], '1')

        req = Request.blank('/sda1/p/a/c/exe',
            environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Timestamp': normalize_timestamp(time()),
                     'x-validator-exec': 'fuzzy',
                     'Content-Type': 'application/octet-stream'})

        req.body = 'INVALID'
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 201)
        self.assertEquals(resp.headers['x-nexe-validation'], '2')

    def test_zerovm_bad_exit_code(self):

        @contextmanager
        def save_zerovm_exename():
            exename = self.app.zerovm_exename
            try:
                yield True
            finally:
                self.app.zerovm_exename = exename

        self.setup_zerovm_query()
        with save_zerovm_exename():
            (zfd, zerovm) = mkstemp()
            os.write(zfd,
r'''
from sys import exit
exit(255)
'''
            )
            os.close(zfd)
            self.app.zerovm_exename = ['python', zerovm]
            req = self.zerovm_request()
            nexefile = StringIO(self._nexescript)
            conf = ZvmNode(1, 'exit', '/c/exe')
            conf = json.dumps(conf, cls=NodeEncoder)
            sysmap = StringIO(conf)
            with self.create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
                req.body_file = open(tar, 'rb')
                resp = self.app.zerovm_query(req)
                self.assertEquals(resp.status_int, 503)
                self.assertEqual(resp.headers['x-nexe-retcode'], '0')
                self.assertEqual(resp.headers['x-nexe-status'], 'ZeroVM runtime error')
                self.assertEqual(resp.headers['x-nexe-validation'], '0')
                self.assertEqual(resp.headers['x-nexe-system'], 'exit')
            os.unlink(zerovm)

if __name__ == '__main__':
    unittest.main()