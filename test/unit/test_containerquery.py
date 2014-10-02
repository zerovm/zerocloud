import json
import os
import tarfile
from tempfile import mkdtemp, mkstemp
import unittest
from shutil import rmtree
from StringIO import StringIO
from swift.common import utils
from swift.common.swob import Request
from swift.common.utils import mkdirs
from swift.container.server import ContainerController
from test.unit import FakeLogger, create_tar, trim
from test.unit.test_proxyquery import ZEROVM_DEFAULT_MOCK
from zerocloud import objectquery
from zerocloud.common import parse_location
from zerocloud.common import ACCESS_READABLE
from zerocloud.common import ACCESS_WRITABLE
from zerocloud.configparser import NodeEncoder
from zerocloud.configparser import ZvmNode
from zerocloud.thread_pool import Zuid
from eventlet.wsgi import Input


class FakeApp(ContainerController):

    def __init__(self, conf):
        ContainerController.__init__(self, conf)
        self.bytes_per_sync = 1
        self.fault = False

    def __call__(self, env, start_response):
        if self.fault:
            raise Exception
        ContainerController.__call__(self, env, start_response)


class TestContainerQuery(unittest.TestCase):

    def setUp(self):
        utils.HASH_PATH_SUFFIX = 'endcap'
        self.testdir = \
            os.path.join(mkdtemp(),
                         'tmp_test_container_server_ContainerController')
        mkdirs(os.path.join(self.testdir, 'sda1', 'tmp'))
        self.conf = {'devices': self.testdir,
                     'mount_check': 'false',
                     'disable_fallocate': 'true',
                     'zerovm_sysimage_devices':
                         'sysimage1 /opt/zerovm/sysimage1 '
                         'sysimage2 /opt/zerovm/sysimage2'
                     }
        self.cont_controller = FakeApp(self.conf)
        self.app = objectquery.ObjectQueryMiddleware(self.cont_controller,
                                                     self.conf,
                                                     logger=FakeLogger())
        self.app.zerovm_maxoutput = 1024 * 1024 * 10
        self.zerovm_mock = None
        self.uid_generator = Zuid()
        self.create_container()

    def tearDown(self):
        rmtree(os.path.dirname(self.testdir))
        if self.zerovm_mock:
            os.unlink(self.zerovm_mock)

    def setup_zerovm_query(self, mock=None):
        # ensure that python executable is used
        zerovm_mock = ZEROVM_DEFAULT_MOCK
        if mock:
            fd, zerovm_mock = mkstemp()
            os.write(fd, mock)
            os.close(fd)
            self.zerovm_mock = zerovm_mock
        self.app.zerovm_exename = ['python', zerovm_mock]
        # do not set it lower than 2 * BLOCKSIZE (2 * 512)
        # it will break tar RPC protocol
        self.app.app.network_chunk_size = 2 * 512

    def create_container(self, url='/sda1/p/a/c'):
        req = Request.blank(
            url, environ={'REQUEST_METHOD': 'PUT',
                          'HTTP_X_TIMESTAMP': '1'})
        resp = req.get_response(self.app)
        self.assertEquals(resp.status_int, 201)

    def add_object(self, url='/sda1/p/a/c', name='o'):
        req = Request.blank(
            '/'.join((url, name)), environ={'REQUEST_METHOD': 'PUT'},
            headers={'X-Timestamp': '1', 'X-Size': '0',
                     'X-Content-Type': 'text/plain', 'X-ETag': 'e'})
        resp = req.get_response(self.app)
        print resp.body
        self.assertEquals(resp.status_int, 201)

    def zerovm_container_request(self):
        req = Request.blank('/sda1/p/a/c',
                            environ={'REQUEST_METHOD': 'POST'},
                            headers={'Content-Type': 'application/x-gtar',
                                     'x-zerovm-execute': '1.0',
                                     'x-account-name': 'a',
                                     'x-zerovm-access': 'GET'})
        req.headers['x-zerocloud-id'] = self.uid_generator.get()
        return req

    def test_select_object_names(self):
        self.setup_zerovm_query()
        self.add_object(name='o1')
        self.add_object(name='o2')
        self.add_object(name='o3')
        req = self.zerovm_container_request()
        nexescript = trim(r'''
            import sqlite3
            import json
            db_path = mnfst.channels['/dev/input']['path']
            con = sqlite3.connect(db_path)
            cursor = con.cursor()
            cursor.execute("SELECT name FROM object;")
            l = []
            for r in cursor.fetchall():
                l.append(str(r[0]))
            return json.dumps(l)
            ''')
        nexefile = StringIO(nexescript)
        conf = ZvmNode(1, 'sort', parse_location('swift://a/c/exe'))
        conf.add_new_channel('input', ACCESS_READABLE,
                             parse_location('swift://a/c'))
        conf.add_new_channel('stdout', ACCESS_WRITABLE)
        conf = json.dumps(conf, cls=NodeEncoder)
        sysmap = StringIO(conf)
        with create_tar({'boot': nexefile, 'sysmap': sysmap}) as tar:
            length = os.path.getsize(tar)
            req.body_file = Input(open(tar, 'rb'), length)
            req.content_length = length
            resp = self.app.zerovm_query(req)
            fd, name = mkstemp()
            self.assertEqual(resp.status_int, 200)
            for chunk in resp.app_iter:
                os.write(fd, chunk)
            os.close(fd)
            self.assertEqual(os.path.getsize(name), resp.content_length)
            tar = tarfile.open(name)
            names = tar.getnames()
            self.assertIn('stdout', names)
            members = tar.getmembers()
            result = None
            for m in members:
                if 'stdout' in m.name:
                    result = json.loads(tar.extractfile(m).read())
                    self.assertEqual(result, ['o1', 'o2', 'o3'])
            self.assertIsNotNone(result)
