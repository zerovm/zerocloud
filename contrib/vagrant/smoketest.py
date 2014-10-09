import json
import os
try:
    from StringIO import StringIO
except ImportError:
    from io import BytesIO as StringIO
import random
import shutil
import string
import tarfile
import tempfile
import unittest

import requests
import swiftclient


class Smoketests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # Set the storage url and auth token:
        cls.conn = swiftclient.Connection(
            'http://127.0.0.1:8080/auth/v1.0', 'adminacct:admin', 'adminpass',
            auth_version='1.0'
        )
        cls.storage_url, cls.auth_token = cls.conn.get_auth()
        # TODO: if this fails, throw a useful error telling the user to run
        # vagrant up

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def _random_name(self, length=10):
        name = ''.join(random.sample(string.ascii_lowercase
                                     + string.ascii_uppercase
                                     + string.digits, length))
        return name

    def _tempfile(self, tempdir, name, contents):
        path = os.path.join(tempdir, name)
        with open(path, 'w') as fp:
            fp.write(contents)

        return path

    def _zapp(self, tempdir, script=None, system_map=None):
        if script is None:
            script = """\
import sys
sys.stdout.write('hello')
"""
        if system_map is None:
            system_map = json.dumps([{
                "name": "example",
                "exec": {
                    "path": "file://python2.7:python",
                    "args": "main.py"
                },
                "devices": [
                    {"name": "python2.7"},
                    {"name": "stdout"}
                ]
            }])

        script_path = self._tempfile(tempdir, 'main.py', script)
        system_map_path = self._tempfile(tempdir, 'system.map', system_map)

        tar_path = os.path.join(tempdir, 'test.tar')
        tar = tarfile.open(name=tar_path, mode='w')
        tar.add(script_path, arcname='main.py')
        tar.add(system_map_path, arcname='boot/system.map')
        tar.close()

        return tar_path

    def test_post_script(self):
        # Test ZeroCloud by posting a python script to a /version/account URL
        # This is the simplest execution method.
        script = StringIO("""\
#!file://python2.7:python
import sys
sys.stdout.write('hello')
""")
        headers = {
            'X-Zerovm-Execute': 1.0,
            'X-Auth-Token': self.auth_token,
            'Content-Type': 'application/python',
        }
        response = requests.post(
            self.storage_url,
            data=script.read(),
            headers=headers
        )
        self.assertEqual(200, response.status_code)
        self.assertEqual('hello', response.content)

    def test_post_tarball(self):
        # Test ZeroCloud by posting a tarball with a system map.
        # This demonstrates sending a packaged ZeroVM application for one-time
        # use.
        tempdir = tempfile.mkdtemp()
        try:
            tar_path = self._zapp(tempdir)
            headers = {
                'X-Zerovm-Execute': 1.0,
                'X-Auth-Token': self.auth_token,
                'Content-Type': 'application/x-tar',
            }

            with open(tar_path) as fp:
                response = requests.post(
                    self.storage_url,
                    data=fp.read(),
                    headers=headers
                )
                self.assertEqual(200, response.status_code)
                self.assertEqual('0', response.headers['x-nexe-retcode'])
                self.assertEqual('hello', response.content)
        finally:
            shutil.rmtree(tempdir)

    def test_post_job_description(self):
        # Test posting a job description / system map to execute a ZeroVM
        # application (or "zapp" -- a tarball) already uploaded into ZeroCloud.
        tempdir = tempfile.mkdtemp()
        try:
            container_name = self._random_name()
            object_name = self._random_name()
            tar_path = self._zapp(tempdir)
            # First, create a container for the zapp
            self.conn.put_container(container_name)
            with open(tar_path) as fp:
                self.conn.put_object(container_name, object_name, fp.read(),
                                     content_type='application/x-tar')

            system_map = StringIO(json.dumps([{
                "name": "example",
                "exec": {
                    "path": "file://python2.7:python",
                    "args": "main.py"
                },
                "devices": [
                    {"name": "python2.7"},
                    {"name": "stdout"},
                    {"name": "image",
                     "path": "swift://~/%s/%s" % (container_name, object_name)}
                ]
            }]))

            headers = {
                'X-Zerovm-Execute': 1.0,
                'X-Auth-Token': self.auth_token,
                'Content-Type': 'application/json',
            }
            response = requests.post(
                self.storage_url,
                data=system_map.read(),
                headers=headers
            )
            self.assertEqual(200, response.status_code)
            self.assertEqual('0', response.headers['x-nexe-retcode'])
            self.assertEqual('hello', response.content)

            # clean up
            self.conn.delete_object(container_name, object_name)
            self.conn.delete_container(container_name)
        finally:
            shutil.rmtree(tempdir)

    def test_get_with_open(self):
        tempdir = tempfile.mkdtemp()
        try:
            container_name = self._random_name()
            zapp_name = self._random_name()

            data = StringIO("""\
{"geometries": [{"coordinates": [100.0, 0.0], "type": "Point"},
                {"coordinates": [[101.0, 0.0], [102.0, 1.0]],
                 "type": "LineString"}],
 "type": "GeometryCollection"}""")
            pprint = """\
import json
import pprint

with open('/dev/input') as fp:
    data = fp.read()
    data = json.loads(data)
    print(pprint.pformat(data))
"""
            system_map = StringIO(json.dumps([{
                "name": "prettyprint",
                "exec": {
                    "path": "file://python2.7:python",
                    "args": "main.py"
                },
                "devices": [
                    {"name": "python2.7"},
                    {"name": "stdout"},
                    {"name": "input", "path": "{.object_path}"},
                    {"name": "image",
                     "path": "swift://~/%s/%s" % (container_name, zapp_name)}
                ]
            }]))

            tar_path = self._zapp(tempdir, script=pprint)
            self.conn.put_container(container_name)
            with open(tar_path) as fp:
                self.conn.put_object(container_name, zapp_name, fp.read(),
                                     content_type='application/x-tar')

            self.conn.put_container('.zvm')
            self.conn.put_object('.zvm', 'application/json/config',
                                 system_map.read())

            self.conn.put_object(container_name, 'data.json', data.read(),
                                 content_type='application/json')
            headers = {
                'X-Zerovm-Execute': 'open/1.0',
                'X-Auth-Token': self.auth_token,
            }
            response = requests.get(
                '%s/%s/%s' % (self.storage_url, container_name, 'data.json'),
                headers=headers
            )
            self.assertEqual(200, response.status_code)
            self.assertEqual('0', response.headers['x-nexe-retcode'])
            expected = """\
{u'geometries': [{u'coordinates': [100.0, 0.0], u'type': u'Point'},
                 {u'coordinates': [[101.0, 0.0], [102.0, 1.0]],
                  u'type': u'LineString'}],
 u'type': u'GeometryCollection'}
"""
            self.assertEqual(expected, response.content)

            # clean up
            self.conn.delete_object(container_name, zapp_name)
            self.conn.delete_object(container_name, 'data.json')
            self.conn.delete_container(container_name)
        finally:
            shutil.rmtree(tempdir)


if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(Smoketests)
    unittest.TextTestRunner(verbosity=2).run(suite)
