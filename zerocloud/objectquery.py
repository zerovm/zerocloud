from StringIO import StringIO
from greenlet import GreenletExit
import re
import shutil
import time
import traceback
import tarfile
from contextlib import contextmanager
from urllib import unquote
from hashlib import md5
from tempfile import mkstemp, mkdtemp

from eventlet import sleep
from eventlet.green import select, subprocess, os, socket
from eventlet.timeout import Timeout
from eventlet.green.httplib import HTTPResponse
import errno
import signal

import zlib
from os.path import exists
from swift.common.swob import Request, Response, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestTimeout, HTTPRequestEntityTooLarge, \
    HTTPBadRequest, HTTPUnprocessableEntity, HTTPServiceUnavailable, \
    HTTPClientDisconnect, HTTPInternalServerError, HeaderKeyDict, \
    HTTPInsufficientStorage
from swift.common.utils import normalize_timestamp, \
    split_path, get_logger, mkdirs, disable_fallocate, config_true_value, \
    hash_path, storage_directory
from swift.container.backend import ContainerBroker
from swift.obj.diskfile import DiskFileManager, DiskFile, DiskFileWriter, \
    write_metadata
from swift.common.constraints import check_utf8
from swift.common.exceptions import DiskFileNotExist, DiskFileNoSpace, \
    DiskFileDeviceUnavailable, DiskFileQuarantined
from swift.proxy.controllers.base import update_headers
from zerocloud.common import TAR_MIMES, ACCESS_READABLE, ACCESS_CDR, \
    ACCESS_WRITABLE, MD5HASH_LENGTH, parse_location, is_image_path, \
    ACCESS_NETWORK, ACCESS_RANDOM, REPORT_VALIDATOR, REPORT_RETCODE, \
    REPORT_ETAG, REPORT_CDR, REPORT_STATUS, SwiftPath, REPORT_LENGTH, \
    REPORT_DAEMON, load_server_conf, is_swift_path
from zerocloud.configparser import ClusterConfigParser
from zerocloud.proxyquery import gunzip_iter

from zerocloud.tarstream import UntarStream, TarStream, \
    REGTYPE, BLOCKSIZE, NUL
import zerocloud.thread_pool as zpool

try:
    import simplejson as json
except ImportError:
    import json

CONT_DATADIR = 'containers'
# mapping between return code and its message
RETCODE_MAP = [
    'OK',              # [0]
    'Error',           # [1]
    'Timed out',       # [2]
    'Killed',          # [3]
    'Output too long'  # [4]
]


class LocalObject(object):

    def __init__(self, account, container, obj,
                 disk_file=None):
        self.account = account
        self.container = container
        self.obj = obj
        self.swift_path = SwiftPath.init(account, container, obj)
        self.disk_file = disk_file
        self.channel = None
        self.path = None
        self.has_local_file = True if container or obj else False


class ZDiskFileManager(DiskFileManager):

    def __init__(self, conf, logger):
        super(ZDiskFileManager, self).__init__(conf, logger)

    def get_diskfile(self, device, partition, account, container, obj,
                     **kwargs):
        dev_path = self.get_dev_path(device)
        if not dev_path:
            raise DiskFileDeviceUnavailable()
        return ZDiskFile(self, dev_path, self.threadpools[device],
                         partition, account, container, obj, **kwargs)

    def get_container_broker(self, device, partition, account, container,
                             **kwargs):
        """
        Get a DB broker for the container.

        :param device: drive that holds the container
        :param partition: partition the container is in
        :param account: account name
        :param container: container name
        :returns: ContainerBroker object
        """
        hsh = hash_path(account, container)
        db_dir = storage_directory(CONT_DATADIR, partition, hsh)
        db_path = os.path.join(self.devices,
                               device, db_dir, hsh + '.db')
        kwargs.setdefault('account', account)
        kwargs.setdefault('container', container)
        kwargs.setdefault('logger', self.logger)
        return ContainerBroker(db_path, **kwargs)


class ZDiskFile(DiskFile):

    def __init__(self, mgr, path, threadpool, partition, account,
                 container, obj, _datadir=None):
        super(ZDiskFile, self).__init__(mgr, path, threadpool,
                                        partition, account, container, obj,
                                        _datadir)
        self.tmppath = None
        self.channel_device = None
        self.new_timestamp = None

    @contextmanager
    def create(self, size=None, fd=None):
        """
        Context manager to create a file. We create a temporary file first, and
        then return a DiskFileWriter object to encapsulate the state.

        .. note::

            An implementation is not required to perform on-disk
            preallocations even if the parameter is specified. But if it does
            and it fails, it must raise a `DiskFileNoSpace` exception.

        :param size: optional initial size of file to explicitly allocate on
                     disk
        :raises DiskFileNoSpace: if a size is specified and allocation fails
        """
        if not exists(self._tmpdir):
            mkdirs(self._tmpdir)
        if fd is None:
            fd, self.tmppath = mkstemp(dir=self._tmpdir)
        try:
            yield DiskFileWriter(self._name, self._datadir, fd,
                                 self.tmppath, self._bytes_per_sync,
                                 self._threadpool)
        finally:
            try:
                os.close(fd)
            except OSError:
                pass
            try:
                os.unlink(self.tmppath)
                self.tmppath = None
            except OSError:
                pass

    @property
    def data_file(self):
        return self._data_file

    @data_file.setter
    def data_file(self, data_file):
        self._data_file = data_file

    @property
    def name(self):
        return self._name

    def put_metadata(self, metadata):
        write_metadata(self._data_file, metadata)


class PseudoSocket():

    def __init__(self, file):
        self.file = file

    def makefile(self, mode, buffering):
        return self.file


class TmpDir(object):
    def __init__(self, path, device, os_interface=os):
        self.os_interface = os_interface
        self.tmpdir = self.os_interface.path.join(path, device, 'tmp')

    @contextmanager
    def mkstemp(self):
        """Contextmanager to make a temporary file."""
        if not self.os_interface.path.exists(self.tmpdir):
            mkdirs(self.tmpdir)
        fd, tmppath = mkstemp(dir=self.tmpdir)
        try:
            yield fd, tmppath
        finally:
            try:
                self.os_interface.close(fd)
            except OSError:
                pass
            try:
                self.os_interface.unlink(tmppath)
            except OSError:
                pass

    @contextmanager
    def mkdtemp(self):
        if not self.os_interface.path.exists(self.tmpdir):
            mkdirs(self.tmpdir)
        tmpdir = mkdtemp(dir=self.tmpdir)
        try:
            yield tmpdir
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)


class DualReader(object):

    def __init__(self, head, tail):
        self.head = head
        self.tail = tail

    def read(self, amt=None):
        if amt is None:
            return self.head.read() + self.tail.read()
        if amt < 0:
            return None
        chunk = self.head.read(amt)
        if chunk:
            if len(chunk) == amt:
                return chunk
            elif len(chunk) < amt:
                chunk += self.tail.read(amt - len(chunk))
                return chunk
        return self.tail.read(amt)

    def readline(self, size=None):
        line = self.head.readline(size)
        if line:
                return line
        line = self.tail.readline(size)
        if line:
                return line
        return None

    def tell(self):
        return self.tail.tell()

    def close(self):
        self.head.close()
        self.tail.close()


class ObjectQueryMiddleware(object):

    DEFAULT_POOL_CONFIG = 'default = WaitPool(10,3); ' \
                          'cluster = PriorityPool(10,100);'

    def __init__(self, app, conf, logger=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='obj-query')

        # let's load appropriate server config sections here
        load_server_conf(conf, ['app:object-server', 'app:container-server'])
        # path to zerovm executable, better use absolute path here
        # for security reasons
        self.zerovm_exename = [i.strip() for i in
                               conf.get('zerovm_exename', 'zerovm').split()
                               if i.strip()]
        # timeout for zerovm between TERM signal and KILL signal
        self.zerovm_kill_timeout = int(conf.get('zerovm_kill_timeout', 1))
        # maximum nexe binary size
        self.zerovm_maxnexe = int(conf.get('zerovm_maxnexe', 256 * 1048576))
        # run the middleware in debug mode
        # will gather temp files and write them into /tmp/zvm_debug/ dir
        self.zerovm_debug = config_true_value(conf.get('zerovm_debug', 'no'))
        # run the middleware in performance check mode
        # will print performance data to system log
        self.zerovm_perf = config_true_value(conf.get('zerovm_perf', 'no'))
        # name-path pairs for sysimage devices on this node
        zerovm_sysimage_devices = {}
        sysimage_list = [i.strip()
                         for i in
                         conf.get('zerovm_sysimage_devices', '').split()
                         if i.strip()]
        for k, v in zip(*[iter(sysimage_list)]*2):
            zerovm_sysimage_devices[k] = v
        # thread pools for advanced scheduling in proxy middleware
        self.zerovm_thread_pools = {}
        threadpool_list = [i.strip()
                           for i in
                           conf.get('zerovm_threadpools',
                                    self.DEFAULT_POOL_CONFIG).split(';')
                           if i.strip()]
        try:
            for pool in threadpool_list:
                name, args = [i.strip() for i in pool.split('=')
                              if i.strip()]
                func, args = [i.strip(')') for i in args.split('(')
                              if i.strip(')')]
                args = [i.strip() for i in args.split(',')
                        if i.strip()]
                self.zerovm_thread_pools[name] = getattr(zpool, func)(*args)
        except ValueError:
            raise ValueError('Cannot parse "zerovm_threadpools" '
                             'configuration variable')
        if len(self.zerovm_thread_pools) < 1 or \
                not self.zerovm_thread_pools.get('default', None):
            raise ValueError('Invalid "zerovm_threadpools" '
                             'configuration variable')

        # hardcoded absolute limits for zerovm executable stdout
        # and stderr size
        # we do not want to crush the server
        self.zerovm_stderr_size = 65536
        self.zerovm_stdout_size = 65536

        # hardcoded dir for zerovm caching daemon sockets
        self.zerovm_sockets_dir = '/tmp/zvm-daemons'
        if not os.path.exists(self.zerovm_sockets_dir):
            mkdirs(self.zerovm_sockets_dir)

        # for unit-tests
        self.fault_injection = conf.get('fault_injection', ' ')
        self.os_interface = os

        self.parser_config = {
            'limits': {
                # maximal number of iops permitted for reads or writes
                # on particular channel
                'reads': int(conf.get('zerovm_maxiops', 1024 * 1048576)),
                'writes': int(conf.get('zerovm_maxiops', 1024 * 1048576)),
                # maximum input data file size
                'rbytes': int(conf.get('zerovm_maxinput', 1024 * 1048576)),
                # maximum output data file size
                'wbytes': int(conf.get('zerovm_maxoutput', 1024 * 1048576))
            },
            'manifest': {
                # zerovm manifest version
                'Version': conf.get('zerovm_manifest_ver', '20130611'),
                # timeout for zerovm to finish execution
                'Timeout': int(conf.get('zerovm_timeout', 5)),
                # max nexe memory size
                'Memory': int(conf.get('zerovm_maxnexemem',
                                       4 * 1024 * 1048576))
            }
        }
        self.parser = ClusterConfigParser(zerovm_sysimage_devices, None,
                                          self.parser_config, None, None)
        self._diskfile_mgr = ZDiskFileManager(conf, self.logger)
        # obey `disable_fallocate` configuration directive
        if config_true_value(conf.get('disable_fallocate', 'no')):
            disable_fallocate()
        self.disk_chunk_size = int(conf.get('disk_chunk_size', 65536))
        self.network_chunk_size = int(conf.get('network_chunk_size', 65536))
        self.max_upload_time = int(conf.get('max_upload_time', 86400))
        self.log_requests = config_true_value(conf.get('log_requests', 'true'))

    def get_disk_file(self, device, partition, account, container, obj,
                      **kwargs):
        return self._diskfile_mgr.get_diskfile(
            device, partition, account, container, obj, **kwargs)

    def send_to_socket(self, sock, zerovm_inputmnfst):
        SIZE = 8
        size = '0x%06x' % len(zerovm_inputmnfst)
        try:
            with Timeout(self.parser_config['manifest']['Timeout']):
                sock.sendall(size + zerovm_inputmnfst)
                try:
                    size = int(sock.recv(SIZE), 0)
                    if not size:
                        return 1, 'Report error', ''
                    if size > self.zerovm_stdout_size:
                        return 4, 'Output too long', ''
                    report = sock.recv(size)
                    return 0, report, ''
                except ValueError:
                    return 1, 'Report error', ''
        except Timeout:
            return 2, 'Timed out', ''
        except IOError:
            return 1, 'Socket error', ''
        finally:
            sock.close()

    def execute_zerovm(self, zerovm_inputmnfst_fn, zerovm_args=None):
        """
        Executes zerovm in a subprocess

        :param zerovm_inputmnfst_fn: file name of zerovm manifest,
                                     can be a relative path
        :param zerovm_args: additional arguments passed to zerovm command line,
                            should be a list of str

        """
        cmdline = []
        cmdline += self.zerovm_exename
        if zerovm_args:
            cmdline += zerovm_args
        cmdline += [zerovm_inputmnfst_fn]
        proc = subprocess.Popen(cmdline,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE)

        def get_final_status(stdout_data, stderr_data, return_code=None):
            (data1, data2) = proc.communicate()
            stdout_data += data1
            stderr_data += data2
            if return_code is None:
                return_code = 0
                if proc.returncode:
                    return_code = 1
            return return_code, stdout_data, stderr_data

        def read_from_std(readable, stdout_data, stderr_data):
            rlist, _junk, __junk = \
                select.select(readable, [], [],
                              self.parser_config['manifest']['Timeout'])
            if rlist:
                for stream in rlist:
                    data = self.os_interface.read(stream.fileno(), 4096)
                    if not data:
                        readable.remove(stream)
                        continue
                    if stream == proc.stdout:
                        stdout_data += data
                    elif stream == proc.stderr:
                        stderr_data += data
            return stdout_data, stderr_data

        stdout_data = ''
        stderr_data = ''
        readable = [proc.stdout, proc.stderr]
        try:
            with Timeout(self.parser_config['manifest']['Timeout'] + 1):
                start = time.time()
                perf = ''
                while len(readable) > 0:
                    stdout_data, stderr_data = \
                        read_from_std(readable, stdout_data, stderr_data)
                    if len(stdout_data) > self.zerovm_stdout_size \
                            or len(stderr_data) > self.zerovm_stderr_size:
                        proc.kill()
                        return 4, stdout_data, stderr_data
                    perf = "%s %.3f" % (perf, time.time() - start)
                    start = time.time()
                perf = "%s %.3f" % (perf, time.time() - start)
                if self.zerovm_perf:
                    self.logger.info("PERF EXEC: %s" % perf)
                return get_final_status(stdout_data, stderr_data)
        except (Exception, Timeout):
            proc.terminate()
            try:
                with Timeout(self.zerovm_kill_timeout):
                    while len(readable) > 0:
                        stdout_data, stderr_data = \
                            read_from_std(readable, stdout_data, stderr_data)
                        if len(stdout_data) > self.zerovm_stdout_size\
                                or len(stderr_data) > self.zerovm_stderr_size:
                            proc.kill()
                            return 4, stdout_data, stderr_data
                    return get_final_status(stdout_data, stderr_data, 2)
            except (Exception, Timeout):
                proc.kill()
                return get_final_status(stdout_data, stderr_data, 3)

    def _extract_boot_file(self, channels, boot_file, image, zerovm_tmp):
        tar = tarfile.open(name=image)
        nexe = None
        try:
            nexe = tar.extractfile(boot_file)
        except KeyError:
            pass
        if not nexe:
            return False
        try:
            channels['boot'] = os.path.join(zerovm_tmp, 'boot')
            fp = open(channels['boot'], 'wb')
            reader = iter(lambda: nexe.read(self.disk_chunk_size), '')
            for chunk in reader:
                fp.write(chunk)
            fp.close()
            return True
        except IOError:
            pass
        finally:
            tar.close()
        return False

    def _placeholder(self):
        try:
            sleep(self.parser_config['manifest']['Timeout'])
        except GreenletExit:
            return

    def _debug_init(self, req):
        trans_id = req.headers.get('x-trans-id', '-')
        debug_dir = os.path.join("/tmp/zvm_debug", trans_id)
        if self.zerovm_debug:
            try:
                os.makedirs(debug_dir)
            except OSError as exc:
                if exc.errno == errno.EEXIST \
                        and os.path.isdir(debug_dir):
                    pass
                else:
                    raise
            return debug_dir

    def _debug_before_exec(self, config, debug_dir, nexe_headers,
                           nvram_file, zerovm_inputmnfst):
        if self.zerovm_debug:
            shutil.copy(nvram_file,
                        os.path.join(debug_dir,
                                     '%s.nvram.%s'
                                     % (nexe_headers['x-nexe-system'],
                                        normalize_timestamp(time.time()))))
            mnfst = open(os.path.join(debug_dir,
                                      '%s.manifest.%s'
                                      % (nexe_headers['x-nexe-system'],
                                         normalize_timestamp(time.time()))),
                         mode='wb')
            mnfst.write(zerovm_inputmnfst)
            mnfst.close()
            sysfile = open(os.path.join(debug_dir,
                                        '%s.json.%s'
                                        % (nexe_headers['x-nexe-system'],
                                           normalize_timestamp(time.time()))),
                           mode='wb')
            json.dump(config, sysfile, sort_keys=True, indent=2)
            sysfile.close()

    def _debug_after_exec(self, debug_dir, nexe_headers, zerovm_retcode,
                          zerovm_stderr, zerovm_stdout):
        if self.zerovm_debug:
            std = open(os.path.join(debug_dir,
                                    '%s.zerovm.stdout.%s'
                                    % (nexe_headers['x-nexe-system'],
                                       normalize_timestamp(time.time()))),
                       mode='wb')
            std.write(zerovm_stdout)
            std.close()
            std = open(os.path.join(debug_dir,
                                    '%s.zerovm.stderr.%s'
                                    % (nexe_headers['x-nexe-system'],
                                       normalize_timestamp(time.time()))),
                       mode='wb')
            std.write('swift retcode = %d\n' % zerovm_retcode)
            std.write(zerovm_stderr)
            std.close()

    def _create_zerovm_thread(self, zerovm_inputmnfst, zerovm_inputmnfst_fd,
                              zerovm_inputmnfst_fn, zerovm_valid,
                              thrdpool, job_id):
        while zerovm_inputmnfst:
            written = self.os_interface.write(zerovm_inputmnfst_fd,
                                              zerovm_inputmnfst)
            zerovm_inputmnfst = zerovm_inputmnfst[written:]
        zerovm_args = None
        if zerovm_valid:
            zerovm_args = ['-s']
        thrd = thrdpool.spawn(job_id, self.execute_zerovm,
                              zerovm_inputmnfst_fn, zerovm_args)
        return thrd

    def _create_exec_error(self, nexe_headers, zerovm_retcode, zerovm_stdout):
        err = 'ERROR OBJ.QUERY retcode=%s, ' \
              ' zerovm_stdout=%s' \
              % (RETCODE_MAP[zerovm_retcode],
                 zerovm_stdout)
        self.logger.exception(err)
        resp = HTTPInternalServerError(body=err)
        nexe_headers['x-nexe-status'] = 'ZeroVM runtime error'
        resp.headers = nexe_headers
        return resp

    def get_writable_tmpdir(self, device):
        writable_tmpdir = os.path.join(self._diskfile_mgr.devices,
                                       device,
                                       'tmp')
        if not os.path.exists(writable_tmpdir):
            mkdirs(writable_tmpdir)
        return writable_tmpdir

    def zerovm_query(self, req):
        """Handle zerovm execution requests for the Swift Object Server."""

        debug_dir = self._debug_init(req)
        daemon_sock = req.headers.get('x-zerovm-daemon', None)
        if daemon_sock:
            daemon_sock = os.path.join(self.zerovm_sockets_dir, daemon_sock)
        job_id = req.headers.get('x-zerocloud-id', None)
        if not job_id:
            return HTTPInternalServerError(request=req)
        # print "URL: " + req.url
        nexe_headers = {
            'x-nexe-retcode': 0,
            'x-nexe-status': 'Zerovm did not run',
            'x-nexe-etag': '',
            'x-nexe-validation': 0,
            'x-nexe-cdr-line': '0 0 0 0 0 0 0 0 0 0',
            'x-nexe-system': ''
        }

        try:
            (device, partition, account, container, obj) = \
                split_path(unquote(req.path), 3, 5, True)
        except ValueError, err:
            return HTTPBadRequest(body=str(err), request=req,
                                  content_type='text/plain')
        local_object = LocalObject(account, container, obj)
        rbytes = self.parser_config['limits']['rbytes']
        if 'content-length' in req.headers \
                and int(req.headers['content-length']) > rbytes:
            return HTTPRequestEntityTooLarge(body='RPC request too large',
                                             request=req,
                                             content_type='text/plain',
                                             headers=nexe_headers)
        if 'content-type' not in req.headers:
            return HTTPBadRequest(request=req,
                                  content_type='text/plain',
                                  body='No content type',
                                  headers=nexe_headers)
        if not req.headers['Content-Type'] in TAR_MIMES:
            return HTTPBadRequest(request=req,
                                  body='Invalid Content-Type',
                                  content_type='text/plain',
                                  headers=nexe_headers)
        access_type = req.headers.get('x-zerovm-access', '')
        if obj:
            try:
                local_object.disk_file = \
                    self.get_disk_file(device,
                                       partition,
                                       account,
                                       container,
                                       obj)
            except DiskFileDeviceUnavailable:
                return HTTPInsufficientStorage(drive=device,
                                               request=req)
            if access_type == 'GET':
                try:
                    local_object.disk_file.open()
                except DiskFileNotExist:
                    return HTTPNotFound(request=req)
            elif access_type == 'PUT':
                try:
                    local_object.disk_file.new_timestamp = \
                        req.headers.get('x-timestamp')
                    float(local_object.disk_file.new_timestamp)
                except (KeyError, ValueError, TypeError):
                    return HTTPBadRequest(
                        body='Locally writable object '
                             'specified but no x-timestamp '
                             'in request')
        elif container:
            if access_type == 'GET':
                local_object.broker = \
                    self._diskfile_mgr.get_container_broker(
                        device, partition,
                        account, container)
                if local_object.broker.is_deleted():
                    return HTTPNotFound(headers=nexe_headers,
                                        request=req)
            else:
                return HTTPBadRequest(
                    body='Containers should be read-only',
                    headers=nexe_headers)
        pool = req.headers.get('x-zerovm-pool', 'default').lower()
        thrdpool = self.zerovm_thread_pools.get(pool, None)
        if not thrdpool:
            return HTTPBadRequest(body='Cannot find pool %s' % pool,
                                  request=req, content_type='text/plain',
                                  headers=nexe_headers)
        if not thrdpool.can_spawn(job_id):
            # if can_spawn() returned True it actually means
            # that spawn() will always succeed
            # unless something really bad happened
            return HTTPServiceUnavailable(body='Slot not available',
                                          request=req,
                                          content_type='text/plain',
                                          headers=nexe_headers)
        zerovm_valid = False
        if config_true_value(req.headers.get('x-zerovm-valid', 'false')):
            zerovm_valid = True
        tmpdir = TmpDir(
            self._diskfile_mgr.devices,
            device,
            os_interface=self.os_interface
        )
        start = time.time()
        channels = {}
        with tmpdir.mkdtemp() as zerovm_tmp:
            read_iter = iter(lambda:
                             req.body_file.read(self.network_chunk_size),
                             '')
            upload_expiration = time.time() + self.max_upload_time
            untar_stream = UntarStream(read_iter)
            perf = "%.3f" % (time.time() - start)
            for chunk in read_iter:
                perf = "%s %.3f" % (perf, time.time() - start)
                if req.body_file.position > rbytes:
                    return HTTPRequestEntityTooLarge(
                        body='RPC request too large',
                        request=req,
                        content_type='text/plain',
                        headers=nexe_headers)
                if time.time() > upload_expiration:
                    return HTTPRequestTimeout(request=req,
                                              headers=nexe_headers)
                untar_stream.update_buffer(chunk)
                info = untar_stream.get_next_tarinfo()
                while info:
                    if info.offset_data:
                        fname = info.name
                        file_iter = untar_stream.untar_file_iter()
                        if fname == 'image.gz':
                            fname = 'image'
                            file_iter = gunzip_iter(
                                untar_stream.untar_file_iter(),
                                self.network_chunk_size)
                        channels[fname] = os.path.join(zerovm_tmp, fname)
                        fp = open(channels[fname], 'ab')
                        untar_stream.to_write = info.size
                        untar_stream.offset_data = info.offset_data
                        try:
                            for data in file_iter:
                                fp.write(data)
                                perf = "%s %s:%.3f" % (perf,
                                                       info.name,
                                                       time.time() - start)
                        except zlib.error:
                            return HTTPUnprocessableEntity(
                                request=req,
                                body='Failed to inflate gzipped image',
                                headers=nexe_headers)
                        fp.close()
                    info = untar_stream.get_next_tarinfo()
            if 'content-length' in req.headers \
                    and int(req.content_length) != req.body_file.position:
                self.logger.warning('Client disconnect %s != %d : %s'
                                    % (req.headers['content-length'],
                                       req.body_file.position,
                                       str(req.headers)))
                return HTTPClientDisconnect(request=req,
                                            headers=nexe_headers)
            perf = "%s %.3f" % (perf, time.time() - start)
            if self.zerovm_perf:
                self.logger.info("PERF UNTAR: %s" % perf)
            if 'sysmap' in channels:
                config_file = channels.pop('sysmap')
                fp = open(config_file, 'rb')
                try:
                    config = json.load(fp)
                except Exception:
                    fp.close()
                    return HTTPBadRequest(request=req,
                                          body='Cannot parse system map')
                fp.close()
            else:
                return HTTPBadRequest(request=req,
                                      body='No system map found in request')

            nexe_headers['x-nexe-system'] = config.get('name', '')
            # print json.dumps(config, indent=2)
            zerovm_nexe = None
            exe_path = parse_location(config['exe'])
            if is_image_path(exe_path):
                if exe_path.image in channels:
                    self._extract_boot_file(channels,
                                            exe_path.path,
                                            channels[exe_path.image],
                                            zerovm_tmp)
                elif not daemon_sock:
                    sysimage_path = self.parser.get_sysimage(exe_path.image)
                    if sysimage_path:
                        if self._extract_boot_file(channels,
                                                   exe_path.path,
                                                   sysimage_path,
                                                   zerovm_tmp):
                            zerovm_valid = True
            if 'boot' in channels:
                zerovm_nexe = channels.pop('boot')
            elif not daemon_sock:
                return HTTPBadRequest(request=req,
                                      body='No executable found in request')
            is_master = True
            replicate = config.get('replicate', 1)
            if replicate > 1 \
                    and len(config.get('replicas', [])) < (replicate - 1):
                is_master = False
            response_channels = []
            for ch in config['channels']:
                chan_path = parse_location(ch['path'])
                if ch['device'] in channels:
                    ch['lpath'] = channels[ch['device']]
                elif local_object.has_local_file and chan_path:
                    if chan_path.url == local_object.swift_path.url:
                        if chan_path.obj:
                            if access_type == 'GET':
                                meta = local_object.disk_file.get_metadata()
                                input_file_size = int(meta['Content-Length'])
                                if input_file_size > rbytes:
                                    return HTTPRequestEntityTooLarge(
                                        body='Data object too large',
                                        request=req,
                                        content_type='text/plain',
                                        headers=nexe_headers)
                                ch['lpath'] = local_object.disk_file.data_file
                                channels[ch['device']] = \
                                    local_object.disk_file.data_file
                                ch['meta'] = meta
                                ch['size'] = input_file_size
                            local_object.disk_file.channel_device = \
                                '/dev/%s' % ch['device']
                            ch['path_info'] = \
                                local_object.disk_file.name
                        elif chan_path.container:
                            if access_type == 'GET':
                                input_file_size = \
                                    self.os_interface.path.getsize(
                                        local_object.broker.db_file)
                                if input_file_size > rbytes:
                                    return HTTPRequestEntityTooLarge(
                                        body='Data object too large',
                                        request=req,
                                        headers=nexe_headers)
                                ch['lpath'] = local_object.broker.db_file
                                channels[ch['device']] = \
                                    local_object.broker.db_file
                                ch['meta'] = {}
                                ch['size'] = input_file_size
                                ch['path_info'] = \
                                    local_object.swift_path.path
                        local_object.channel = ch
                if self.parser.is_sysimage_device(ch['device']):
                    ch['lpath'] = self.parser.get_sysimage(ch['device'])
                elif ch['access'] & (ACCESS_READABLE | ACCESS_CDR):
                    if not ch.get('lpath'):
                        if not chan_path or is_image_path(chan_path)\
                                or is_swift_path(chan_path):
                            return HTTPBadRequest(request=req,
                                                  body='Could not resolve '
                                                       'channel path: %s'
                                                       % ch['path'])
                elif ch['access'] & ACCESS_WRITABLE:
                    writable_tmpdir = self.get_writable_tmpdir(device)
                    (output_fd, output_fn) = mkstemp(dir=writable_tmpdir)
                    os.close(output_fd)
                    ch['lpath'] = output_fn
                    channels[ch['device']] = output_fn
                    if is_master:
                        if not chan_path:
                            response_channels.append(ch)
                        elif ch is not local_object.channel:
                            response_channels.insert(0, ch)
                elif ch['access'] & ACCESS_NETWORK:
                    ch['lpath'] = chan_path.path

            with tmpdir.mkstemp() as (zerovm_inputmnfst_fd,
                                      zerovm_inputmnfst_fn):
                (output_fd, nvram_file) = mkstemp()
                os.close(output_fd)
                start = time.time()
                daemon_status = None
                if daemon_sock:
                    zerovm_inputmnfst = \
                        self.parser.prepare_for_forked(config, nvram_file,
                                                       local_object.channel)
                    self._debug_before_exec(config, debug_dir,
                                            nexe_headers, nvram_file,
                                            zerovm_inputmnfst)
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        sock.connect(daemon_sock)
                        thrd = thrdpool.spawn(job_id, self.send_to_socket,
                                              sock, zerovm_inputmnfst)
                    except IOError:
                        self._cleanup_daemon(daemon_sock)
                        sysimage_path = \
                            self.parser.get_sysimage(exe_path.image)
                        if not sysimage_path:
                            return HTTPInternalServerError(
                                body='System image does not exist: %s'
                                     % exe_path.image)
                        if not self._extract_boot_file(channels,
                                                       exe_path.path,
                                                       sysimage_path,
                                                       zerovm_tmp):
                            return HTTPInternalServerError(
                                body='Cannot find daemon nexe '
                                     'in system image %s'
                                     % sysimage_path)
                        zerovm_nexe = channels.pop('boot')
                        zerovm_inputmnfst = \
                            self.parser.prepare_for_daemon(
                                config, nvram_file,
                                zerovm_nexe, local_object.channel,
                                daemon_sock)
                        self._debug_before_exec(config, debug_dir,
                                                nexe_headers, nvram_file,
                                                zerovm_inputmnfst)
                        thrd = self._create_zerovm_thread(
                            zerovm_inputmnfst,
                            zerovm_inputmnfst_fd,
                            zerovm_inputmnfst_fn,
                            zerovm_valid, thrdpool,
                            job_id)
                        if thrd is None:
                            # something strange happened, let's log it
                            self.logger.warning('Slot not available after '
                                                'can_spawn() succeeded')
                            return HTTPServiceUnavailable(
                                body='Slot not available',
                                request=req,
                                content_type='text/plain',
                                headers=nexe_headers)
                        (zerovm_retcode, zerovm_stdout, zerovm_stderr) = \
                            thrd.wait()
                        self._debug_after_exec(debug_dir,
                                               nexe_headers,
                                               zerovm_retcode,
                                               zerovm_stderr,
                                               zerovm_stdout)
                        if zerovm_stderr:
                            self.logger.warning('zerovm stderr: %s'
                                                % zerovm_stderr)
                            zerovm_stdout += zerovm_stderr
                        report = zerovm_stdout.split('\n', REPORT_LENGTH - 1)
                        if len(report) < REPORT_LENGTH or zerovm_retcode > 1:
                            resp = self._create_exec_error(nexe_headers,
                                                           zerovm_retcode,
                                                           zerovm_stdout)
                            return req.get_response(resp)
                        else:
                            try:
                                daemon_status = int(report[REPORT_DAEMON])
                                _parse_zerovm_report(nexe_headers, report)
                            except Exception:
                                resp = HTTPInternalServerError(
                                    body=zerovm_stdout)
                                return req.get_response(resp)
                        if daemon_status != 1:
                            return HTTPInternalServerError(body=zerovm_stdout)
                        zerovm_inputmnfst = \
                            self.parser.prepare_for_forked(
                                config, nvram_file,
                                local_object.channel)
                        self._debug_before_exec(config, debug_dir,
                                                nexe_headers, nvram_file,
                                                zerovm_inputmnfst)
                        try:
                            sock.connect(daemon_sock)
                            thrd = thrdpool.spawn(job_id,
                                                  self.send_to_socket,
                                                  sock,
                                                  zerovm_inputmnfst)
                        except IOError:
                            return HTTPInternalServerError(
                                body='Cannot connect to daemon '
                                     'even after daemon restart: '
                                     'socket %s' % daemon_sock,
                                headers=nexe_headers)
                else:
                    zerovm_inputmnfst = \
                        self.parser.prepare_for_standalone(
                            config, nvram_file,
                            zerovm_nexe, local_object.channel)
                    self._debug_before_exec(config, debug_dir,
                                            nexe_headers, nvram_file,
                                            zerovm_inputmnfst)
                    thrd = self._create_zerovm_thread(zerovm_inputmnfst,
                                                      zerovm_inputmnfst_fd,
                                                      zerovm_inputmnfst_fn,
                                                      zerovm_valid, thrdpool,
                                                      job_id)
                if thrd is None:
                    # something strange happened, let's log it
                    self.logger.warning('Slot not available after '
                                        'can_spawn() succeeded')
                    return HTTPServiceUnavailable(body='Slot not available',
                                                  request=req,
                                                  content_type='text/plain',
                                                  headers=nexe_headers)
                (zerovm_retcode, zerovm_stdout, zerovm_stderr) = thrd.wait()
                perf = "%.3f" % (time.time() - start)
                if self.zerovm_perf:
                    self.logger.info("PERF SPAWN: %s" % perf)
                self._debug_after_exec(debug_dir,
                                       nexe_headers,
                                       zerovm_retcode,
                                       zerovm_stderr,
                                       zerovm_stdout)
                if nvram_file:
                    try:
                        os.unlink(nvram_file)
                    except OSError:
                        pass
                if zerovm_stderr:
                    self.logger.warning('zerovm stderr: '+zerovm_stderr)
                    zerovm_stdout += zerovm_stderr
                report = zerovm_stdout.split('\n', REPORT_LENGTH - 1)
                if len(report) == REPORT_LENGTH:
                    try:
                        if daemon_status != 1:
                            daemon_status = int(report[REPORT_DAEMON])
                        _parse_zerovm_report(nexe_headers, report)
                    except ValueError:
                        resp = self._create_exec_error(nexe_headers,
                                                       zerovm_retcode,
                                                       zerovm_stdout)
                        _channel_cleanup(response_channels)
                        return req.get_response(resp)
                if zerovm_retcode > 1 or len(report) < REPORT_LENGTH:
                    resp = self._create_exec_error(nexe_headers,
                                                   zerovm_retcode,
                                                   zerovm_stdout)
                    _channel_cleanup(response_channels)
                    return req.get_response(resp)

                self.logger.info('Zerovm CDR: %s'
                                 % nexe_headers['x-nexe-cdr-line'])

                response = Response(request=req)
                update_headers(response, nexe_headers)
                response.headers['X-Timestamp'] =\
                    normalize_timestamp(time.time())
                response.headers['x-nexe-system'] = \
                    nexe_headers['x-nexe-system']
                response.content_type = 'application/x-gtar'
                if daemon_status == 1:
                    response.headers['x-zerovm-daemon'] = \
                        req.headers.get('x-zerovm-daemon', None)
                tar_stream = TarStream()
                resp_size = 0
                immediate_responses = []
                send_config = False
                for ch in response_channels:
                    if ch['content_type'].startswith('message/http'):
                        self._read_cgi_response(ch, nph=True)
                        send_config = True
                    elif ch['content_type'].startswith('message/cgi'):
                        self._read_cgi_response(ch, nph=False)
                        send_config = True
                    else:
                        ch['size'] = \
                            self.os_interface.path.getsize(ch['lpath'])
                    info = tar_stream.create_tarinfo(ftype=REGTYPE,
                                                     name=ch['device'],
                                                     size=ch['size'])
                    tar_size = TarStream.get_archive_size(ch['size'])
                    resp_size += len(info) + tar_size
                    ch['info'] = info
                    immediate_responses.append(ch)
                if local_object.has_local_file \
                    and local_object.obj \
                        and local_object.channel['access'] & ACCESS_WRITABLE:
                    local_object.channel['size'] = \
                        self.os_interface.path.getsize(
                            local_object.channel['lpath'])
                    if local_object.channel['content_type'].startswith(
                            'message/http'):
                        self._read_cgi_response(local_object.channel, nph=True)
                    elif local_object.channel['content_type'].startswith(
                            'message/cgi'):
                        self._read_cgi_response(
                            local_object.channel, nph=False)
                    error = self._finalize_local_file(
                        local_object.channel,
                        local_object.disk_file,
                        nexe_headers['x-nexe-etag'],
                        account,
                        container,
                        obj,
                        req,
                        device)
                    if error:
                        return error
                sysmap_info = ''
                sysmap_dump = ''
                if send_config:
                    sysmap = config.copy()
                    sysmap['channels'] = []
                    for ch in config['channels']:
                        ch = ch.copy()
                        ch.pop('size', None)
                        ch.pop('info', None)
                        ch.pop('lpath', None)
                        ch.pop('offset', None)
                        sysmap['channels'].append(ch)
                    sysmap_dump = json.dumps(sysmap)
                    sysmap_info = \
                        tar_stream.create_tarinfo(ftype=REGTYPE,
                                                  name='sysmap',
                                                  size=len(sysmap_dump))
                    resp_size += len(sysmap_info) + \
                        TarStream.get_archive_size(len(sysmap_dump))

                def resp_iter(channels, chunk_size):
                    tstream = TarStream(chunk_size=chunk_size)
                    if send_config:
                        for chunk in tstream.serve_chunk(sysmap_info):
                            yield chunk
                        for chunk in tstream.serve_chunk(sysmap_dump):
                            yield chunk
                        blocks, remainder = divmod(len(sysmap_dump), BLOCKSIZE)
                        if remainder > 0:
                            nulls = NUL * (BLOCKSIZE - remainder)
                            for chunk in tstream.serve_chunk(nulls):
                                yield chunk
                    for ch in channels:
                        fp = open(ch['lpath'], 'rb')
                        if ch.get('offset', None):
                            fp.seek(ch['offset'])
                        reader = iter(lambda: fp.read(chunk_size), '')
                        for chunk in tstream.serve_chunk(ch['info']):
                            yield chunk
                        for data in reader:
                            for chunk in tstream.serve_chunk(data):
                                yield chunk
                        fp.close()
                        os.unlink(ch['lpath'])
                        blocks, remainder = divmod(ch['size'], BLOCKSIZE)
                        if remainder > 0:
                            nulls = NUL * (BLOCKSIZE - remainder)
                            for chunk in tstream.serve_chunk(nulls):
                                yield chunk
                    if tstream.data:
                        yield tstream.data

                response.app_iter = resp_iter(immediate_responses,
                                              self.network_chunk_size)
                response.content_length = resp_size
                return response

    def _read_cgi_response(self, ch, nph=True):
        if nph:
            fp = open(ch['lpath'], 'rb')
        else:
            status = StringIO('HTTP/1.1 200 OK\n')
            fp = DualReader(status, open(ch['lpath'], 'rb'))
        s = PseudoSocket(fp)
        try:
            resp = HTTPResponse(s, strict=1)
            resp.begin()
        except Exception:
            ch['size'] = self.os_interface.path.getsize(ch['lpath'])
            fp.close()
            self.logger.warning('Invalid message/http')
            return
        headers = dict(resp.getheaders())
        ch['offset'] = fp.tell()
        metadata = {}
        if 'content-type' in headers:
            ch['content_type'] = headers['content-type']
        prefix = 'x-object-meta-'
        for k, v in headers.iteritems():
            if k.lower().startswith(prefix):
                k = k[len(prefix):]
                metadata[k.lower()] = v
        ch['meta'] = metadata
        ch['size'] = self.os_interface.path.getsize(ch['lpath']) - ch['offset']
        fp.close()

    def __call__(self, env, start_response):
        """WSGI Application entry point for the Swift Object Server."""
        start_time = time.time()
        req = Request(env)
        self.logger.txn_id = req.headers.get('x-trans-id', None)
        if not check_utf8(req.path_info):
            res = HTTPPreconditionFailed(body='Invalid UTF8')
        else:
            try:
                if 'x-zerovm-execute' in req.headers and req.method == 'POST':
                    res = self.zerovm_query(req)
                elif req.method in ['PUT', 'POST'] \
                        and ('x-zerovm-validate' in req.headers
                             or req.headers.get('content-type', '')
                             == 'application/x-nexe'):
                    self.logger.info(
                        '%s Started pre-validation due to: '
                        'content-type: %s, x-zerovm-validate: %s'
                        % (req.url,
                           req.headers.get('content-type', ''),
                           str('x-zerovm-validate' in req.headers)))

                    def validate_resp(status, response_headers, exc_info=None):
                        if 200 <= int(status.split(' ')[0]) < 300:
                            if self.validate(req):
                                response_headers.append(
                                    ('X-Zerovm-Valid', 'true'))
                        return start_response(status,
                                              response_headers,
                                              exc_info)
                    return self.app(env, validate_resp)
                elif 'x-zerovm-valid' in req.headers and req.method == 'GET':
                    self.logger.info('%s Started validity check due to: '
                                     'x-zerovm-valid: %s'
                                     % (req.url,
                                        str('x-zerovm-valid' in req.headers)))

                    def validate_resp(status, response_headers, exc_info=None):
                        if 200 <= int(status.split(' ')[0]) < 300:
                            if self.is_validated(req):
                                response_headers.append(
                                    ('X-Zerovm-Valid', 'true'))
                        return start_response(status,
                                              response_headers,
                                              exc_info)

                    return self.app(env, validate_resp)
                else:
                    return self.app(env, start_response)
            except (Exception, Timeout):
                self.logger.exception('ERROR __call__ error with %(method)s'
                                      ' %(path)s ',
                                      {'method': req.method, 'path': req.path})
                res = HTTPInternalServerError(body=traceback.format_exc())
        trans_time = time.time() - start_time
        if 'x-nexe-cdr-line' in res.headers:
            res.headers['x-nexe-cdr-line'] = '%.3f, %s' \
                                             % (trans_time,
                                                res.headers['x-nexe-cdr-line'])
        if self.log_requests:
            log_line = '%s - - [%s] "%s %s" %s %s "%s" "%s" "%s" %.4f' % (
                req.remote_addr,
                time.strftime('%d/%b/%Y:%H:%M:%S +0000', time.gmtime()),
                req.method, req.path, res.status.split()[0],
                res.content_length or '-', req.referer or '-',
                req.headers.get('x-trans-id', '-'),
                req.user_agent or '-',
                trans_time)

            self.logger.info(log_line)

        return res(env, start_response)

    def validate(self, req):
        try:
            (device, partition, account, container, obj) =\
                split_path(unquote(req.path), 5, 5, True)
        except ValueError:
            return False
        try:
            try:
                disk_file = self.get_disk_file(device, partition,
                                               account, container, obj)
            except DiskFileDeviceUnavailable:
                return HTTPInsufficientStorage(drive=device, request=req)
        except DiskFileDeviceUnavailable:
            return False
        with disk_file.open():
            try:
                metadata = disk_file.get_metadata()
                if int(metadata['Content-Length']) > self.zerovm_maxnexe:
                    return False
                tmpdir = TmpDir(
                    self._diskfile_mgr.devices,
                    device,
                    os_interface=self.os_interface
                )
                with tmpdir.mkstemp() as (zerovm_inputmnfst_fd,
                                          zerovm_inputmnfst_fn):
                    zerovm_inputmnfst = (
                        'Version=%s\n'
                        'Program=%s\n'
                        'Timeout=%s\n'
                        'Memory=%s,0\n'
                        'Channel=/dev/null,/dev/stdin, 0,0,1,1,0,0\n'
                        'Channel=/dev/null,/dev/stdout,0,0,0,0,1,1\n'
                        'Channel=/dev/null,/dev/stderr,0,0,0,0,1,1\n'
                        % (
                            self.parser_config['manifest']['Version'],
                            disk_file.data_file,
                            self.parser_config['manifest']['Timeout'],
                            self.parser_config['manifest']['Memory']
                        ))
                    while zerovm_inputmnfst:
                        written = self.os_interface.write(zerovm_inputmnfst_fd,
                                                          zerovm_inputmnfst)
                        zerovm_inputmnfst = zerovm_inputmnfst[written:]

                    thrdpool = self.zerovm_thread_pools['default']
                    thrd = thrdpool.force_spawn(self.execute_zerovm,
                                                zerovm_inputmnfst_fn,
                                                ['-F'])
                    (zerovm_retcode, zerovm_stdout, zerovm_stderr) = \
                        thrd.wait()
                    if zerovm_stderr:
                        self.logger.warning('zerovm stderr: ' + zerovm_stderr)
                    if zerovm_retcode == 0:
                        report = zerovm_stdout.split('\n', 1)
                        try:
                            validated = int(report[REPORT_VALIDATOR])
                        except ValueError:
                            return False
                        if validated == 0:
                            metadata = disk_file.get_metadata()
                            metadata['Validated'] = metadata['ETag']
                            disk_file.put_metadata(metadata)
                            return True
                    return False
            except DiskFileNotExist:
                return False

    def is_validated(self, req):
        try:
            (device, partition, account, container, obj) = \
                split_path(unquote(req.path), 5, 5, True)
        except ValueError:
            return False
        try:
            disk_file = self.get_disk_file(device, partition,
                                           account, container, obj)
        except DiskFileDeviceUnavailable:
                return HTTPInsufficientStorage(drive=device, request=req)
        with disk_file.open():
            try:
                metadata = disk_file.get_metadata()
                status = metadata.get('Validated', None)
                etag = metadata.get('ETag', None)
                if status and etag and etag == status:
                    return True
                return False
            except DiskFileNotExist:
                return False

    def _finalize_local_file(self, local_object, disk_file, nexe_etag,
                             account, container, obj, request, device):
        data = nexe_etag.split(' ')
        # data can contain memory etag, for snapshot usage
        # let's just remember it here: mem_etag
        if data[0].startswith('/'):
            channel_etag = data
        else:
            channel_etag = data[1:]
        reported_etag = None
        for dev, etag in zip(*[iter(channel_etag)]*2):
            if disk_file.channel_device in dev:
                reported_etag = etag
                break
        if not reported_etag:
            return HTTPUnprocessableEntity(
                body='No etag found for resulting object '
                     'after writing channel %s data'
                     % disk_file.channel_device)
        if len(reported_etag) != MD5HASH_LENGTH:
            return HTTPUnprocessableEntity(
                body='Bad etag for %s: %s'
                     % (disk_file.channel_device, reported_etag))
        try:
            old_metadata = disk_file.read_metadata()
        except (DiskFileNotExist, DiskFileQuarantined):
            old_metadata = {}
        old_delete_at = int(old_metadata.get('X-Delete-At') or 0)
        metadata = {
            'X-Timestamp': disk_file.new_timestamp,
            'Content-Type': local_object['content_type'],
            'ETag': reported_etag,
            'Content-Length': str(local_object['size'])}
        metadata.update(('x-object-meta-' + val[0], val[1])
                        for val in local_object['meta'].iteritems())
        fd = os.open(local_object['lpath'], os.O_RDONLY)
        if local_object.get('offset', None):
            # need to re-write the file
            tmpdir = self.get_writable_tmpdir(device)
            newfd, new_name = mkstemp(dir=tmpdir)
            new_etag = md5()
            try:
                os.lseek(fd, local_object['offset'], os.SEEK_SET)
                for chunk in iter(lambda:
                                  os.read(fd, self.disk_chunk_size), ''):
                    os.write(newfd, chunk)
                    new_etag.update(chunk)
            except IOError:
                pass
            os.close(newfd)
            metadata['ETag'] = new_etag.hexdigest()
            os.unlink(local_object['lpath'])
            local_object['lpath'] = new_name
            fd = os.open(local_object['lpath'], os.O_RDONLY)
        elif local_object['access'] & ACCESS_RANDOM:
            # need to re-read the file to get correct md5
            new_etag = md5()
            try:
                for chunk in iter(lambda:
                                  os.read(fd, self.disk_chunk_size), ''):
                    new_etag.update(chunk)
            except IOError:
                return HTTPInternalServerError(
                    body='Cannot read resulting file for device %s'
                         % disk_file.channel_device)
            metadata['ETag'] = new_etag.hexdigest()
        disk_file.tmppath = local_object['lpath']
        try:
            with disk_file.create(fd=fd) as writer:
                writer.put(metadata)
        except DiskFileNoSpace:
            raise HTTPInsufficientStorage(drive=device, request=request)
        if old_delete_at > 0:
            self.app.delete_at_update(
                'DELETE', old_delete_at, account, container, obj,
                request, device)
        self.app.container_update(
            'PUT',
            account,
            container,
            obj,
            request,
            HeaderKeyDict({
                'x-size': metadata['Content-Length'],
                'x-content-type': metadata['Content-Type'],
                'x-timestamp': metadata['X-Timestamp'],
                'x-etag': metadata['ETag']}),
            device)

    def _cleanup_daemon(self, daemon_sock):
        for pid in self._get_daemon_pid(daemon_sock):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                continue
        try:
            os.unlink(daemon_sock)
        except OSError:
            pass

    def _get_daemon_pid(self, daemon_sock):
        result = []
        sock = None
        for l in open('/proc/net/unix').readlines():
            m = re.search('(\d+) %s' % daemon_sock, l)
            if m:
                sock = m.group(1)
        if not sock:
            return []
        for pid in [f for f in os.listdir('/proc') if re.match('\d+$', f)]:
            try:
                for fd in os.listdir('/proc/%s/fd' % pid):
                    l = os.readlink('/proc/%s/fd/%s' % (pid, fd))
                    m = re.match(r'socket:\[(\d+)\]', l)
                    if m and sock in m.group(1):
                        m = re.match('\d+ \(([^\)]+)',
                                     open('/proc/%s/stat' % pid).read())
                        if 'zerovm.daemon' in m.group(1):
                            result.append(pid)
            except OSError:
                continue
        return result


def _parse_zerovm_report(nexe_headers, report):
    nexe_headers['x-nexe-validation'] = int(report[REPORT_VALIDATOR])
    nexe_headers['x-nexe-retcode'] = int(report[REPORT_RETCODE])
    nexe_headers['x-nexe-etag'] = report[REPORT_ETAG]
    nexe_headers['x-nexe-cdr-line'] = report[REPORT_CDR]
    nexe_headers['x-nexe-status'] = \
        report[REPORT_STATUS].replace('\n', ' ').rstrip()


def _channel_cleanup(response_channels):
    for ch in response_channels:
        try:
            os.unlink(ch['lpath'])
        except OSError:
            pass


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def obj_query_filter(app):
        return ObjectQueryMiddleware(app, conf)
    return obj_query_filter
