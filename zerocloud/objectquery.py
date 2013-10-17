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

from eventlet import GreenPool, sleep, spawn
from eventlet.green import select, subprocess, os, socket
from eventlet.timeout import Timeout
from eventlet.green.httplib import HTTPResponse
import errno
import signal

from swift.common.swob import Request, Response, HTTPNotFound, \
    HTTPPreconditionFailed, HTTPRequestTimeout, HTTPRequestEntityTooLarge, \
    HTTPBadRequest, HTTPUnprocessableEntity, HTTPServiceUnavailable, \
    HTTPClientDisconnect, HTTPInternalServerError, HeaderKeyDict, HTTPConflict
from swift.common.utils import normalize_timestamp, fallocate, \
    split_path, get_logger, mkdirs, disable_fallocate, TRUE_VALUES
from swift.obj.server import DiskFile, write_metadata, read_metadata
from swift.common.constraints import check_mount, check_utf8, check_float
from swift.common.exceptions import DiskFileError, DiskFileNotExist
from swift.proxy.controllers.base import update_headers
from zerocloud.common import TAR_MIMES, ACCESS_READABLE, ACCESS_CDR, ACCESS_WRITABLE, \
    CHANNEL_TYPE_MAP, MD5HASH_LENGTH, STD_DEVICES, ENV_ITEM, quote_for_env, parse_location, \
    is_image_path, ACCESS_NETWORK, ACCESS_RANDOM, REPORT_VALIDATOR, REPORT_RETCODE, REPORT_ETAG, \
    REPORT_CDR, REPORT_STATUS, SwiftPath, REPORT_LENGTH, REPORT_DAEMON, NodeEncoder

from zerocloud.tarstream import UntarStream, TarStream, REGTYPE, BLOCKSIZE, NUL

try:
    import simplejson as json
except ImportError:
    import json


class PseudoSocket():

    def __init__(self, file):
        self.file = file

    def makefile(self, mode, buffering):
        return self.file


class TmpDir(object):
    def __init__(self, path, device, disk_chunk_size=65536, os_interface=os):
        self.os_interface = os_interface
        self.tmpdir = self.os_interface.path.join(path, device, 'tmp')
        self.disk_chunk_size = disk_chunk_size

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

    def __init__(self, app, conf, logger=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='obj-query')

        self.zerovm_manifest_ver = conf.get('zerovm_manifest_ver', '20130611')
        self.zerovm_exename = [i.strip() for i in conf.get('zerovm_exename', 'zerovm').split() if i.strip()]

        # maximum number of simultaneous running zerovms, others are queued
        #self.zerovm_maxpool = int(conf.get('zerovm_maxpool', 10))

        # maximum number of simultaneous running zerovms with dependent nodes, no queue
        #self.zerovm_max_cluster_pool = int(conf.get('zerovm_maxpool', 10))

        # maximum length of queue for requests awaiting zerovm execution
        #self.zerovm_maxqueue = int(conf.get('zerovm_maxqueue', 3))

        # timeout for zerovm to finish execution
        self.zerovm_timeout = int(conf.get('zerovm_timeout', 5))

        # timeout for zerovm between TERM signal and KILL signal
        self.zerovm_kill_timeout = int(conf.get('zerovm_kill_timeout', 1))

        # maximum input data file size
        self.zerovm_maxinput = int(conf.get('zerovm_maxinput', 1024 * 1048576))

        # maximal number of iops permitted for reads or writes on particular channel
        self.zerovm_maxiops = int(conf.get('zerovm_maxiops', 1024 * 1048576))

        # maximum nexe size
        self.zerovm_maxnexe = int(conf.get('zerovm_maxnexe', 256 * 1048576))

        # maximum output data file size
        self.zerovm_maxoutput = int(conf.get('zerovm_maxoutput', 1024 * 1048576))

        # max nexe memory size
        self.zerovm_maxnexemem = int(conf.get('zerovm_maxnexemem', 4 * 1024 * 1048576))

        self.zerovm_debug = conf.get('zerovm_debug', 'no').lower() in TRUE_VALUES
        self.zerovm_perf = conf.get('zerovm_perf', 'no').lower() in TRUE_VALUES

        # name-path pairs for sysimage devices on this node
        self.zerovm_sysimage_devices = {}
        sysimage_list = [i.strip() for i in conf.get('zerovm_sysimage_devices', '').split() if i.strip()]
        for k, v in zip(*[iter(sysimage_list)]*2):
            self.zerovm_sysimage_devices[k] = v

        # threadpolls for advanced scheduling in proxy middleware
        self.zerovm_threadpools = {}
        threadpool_list = [i.strip()
                           for i in conf.get('zerovm_threadpools', 'default 10 3 cluster 10 0').split()
                           if i.strip()]
        try:
            for name, size, queue in zip(*[iter(threadpool_list)]*3):
                self.zerovm_threadpools[name] = (GreenPool(int(size)), int(queue))
        except ValueError:
            raise ValueError('Cannot parse "zerovm_threadpools" configuration variable')
        if len(self.zerovm_threadpools) < 1 or not self.zerovm_threadpools.get('default', None):
            raise ValueError('Invalid "zerovm_threadpools" configuration variable')

        # hardcoded, we don't want to crush the server
        self.zerovm_stderr_size = 65536
        self.zerovm_stdout_size = 65536

        self.zerovm_sockets_dir = '/tmp/zvm-daemons'
        if not os.path.exists(self.zerovm_sockets_dir):
            mkdirs(self.zerovm_sockets_dir)
        self.retcode_map = ['OK', 'Error', 'Timed out', 'Killed', 'Output too long']

        self.fault_injection = conf.get('fault_injection', ' ')  # for unit-tests
        self.os_interface = os  # for unit-tests

        # green thread pool for zerovm execution
        #self.zerovm_thrdpool = GreenPool(self.zerovm_maxpool)

        # obey `disable_fallocate` configuration directive
        if conf.get('disable_fallocate', 'no').lower() in TRUE_VALUES:
            disable_fallocate()

    def is_sysimage_device(self, device_name):
        return device_name in self.zerovm_sysimage_devices.keys()

    def send_to_socket(self, sock, zerovm_inputmnfst):
        SIZE = 8
        size = '0x%06x' % len(zerovm_inputmnfst)
        try:
            with Timeout(self.zerovm_timeout):
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

        :param zerovm_inputmnfst_fn: file name of zerovm manifest, can be relative path
        :param zerovm_args: additional arguments passed to zerovm command line, should be a list of str

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
                select.select(readable, [], [], self.zerovm_timeout)
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
            with Timeout(self.zerovm_timeout):
                start = time.time()
                perf = ''
                while len(readable) > 0:
                    stdout_data, stderr_data = read_from_std(readable, stdout_data, stderr_data)
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
                        stdout_data, stderr_data = read_from_std(readable, stdout_data, stderr_data)
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
            reader = iter(lambda: nexe.read(self.app.disk_chunk_size), '')
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
            sleep(self.zerovm_timeout)
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

    def _debug_before_exec(self, config, debug_dir, nexe_headers, nvram_file, zerovm_inputmnfst):
        if self.zerovm_debug:
            shutil.copy(nvram_file, os.path.join(debug_dir, '%s.nvram.%s'
                                                            % (nexe_headers['x-nexe-system'],
                                                               normalize_timestamp(time.time()))))
            mnfst = open(os.path.join(debug_dir, '%s.manifest.%s' % (nexe_headers['x-nexe-system'],
                                                                     normalize_timestamp(time.time()))),
                         mode='wb')
            mnfst.write(zerovm_inputmnfst)
            mnfst.close()
            sysfile = open(os.path.join(debug_dir, '%s.json.%s' % (nexe_headers['x-nexe-system'],
                                                                   normalize_timestamp(time.time()))),
                           mode='wb')
            json.dump(config, sysfile, sort_keys=True, indent=2)
            sysfile.close()

    def _debug_after_exec(self, debug_dir, nexe_headers, zerovm_retcode, zerovm_stderr, zerovm_stdout):
        if self.zerovm_debug:
            std = open(os.path.join(debug_dir, '%s.zerovm.stdout.%s'
                                               % (nexe_headers['x-nexe-system'],
                                                  normalize_timestamp(time.time()))), mode='wb')
            std.write(zerovm_stdout)
            std.close()
            std = open(os.path.join(debug_dir, '%s.zerovm.stderr.%s'
                                               % (nexe_headers['x-nexe-system'],
                                                  normalize_timestamp(time.time()))), mode='wb')
            std.write('swift retcode = %d\n' % zerovm_retcode)
            std.write(zerovm_stderr)
            std.close()

    def _create_zerovm_thread(self, zerovm_inputmnfst, zerovm_inputmnfst_fd, zerovm_inputmnfst_fn, zerovm_valid,
                             thrdpool):
        while zerovm_inputmnfst:
            written = self.os_interface.write(zerovm_inputmnfst_fd,
                                              zerovm_inputmnfst)
            zerovm_inputmnfst = zerovm_inputmnfst[written:]
        zerovm_args = None
        if zerovm_valid:
            zerovm_args = ['-s']
        thrd = thrdpool.spawn(self.execute_zerovm, zerovm_inputmnfst_fn, zerovm_args)
        return thrd

    def _create_exec_error(self, nexe_headers, zerovm_retcode, zerovm_stdout):
        err = 'ERROR OBJ.QUERY retcode=%s, ' \
              ' zerovm_stdout=%s' \
              % (self.retcode_map[zerovm_retcode],
                 zerovm_stdout)
        self.logger.exception(err)
        resp = HTTPInternalServerError(body=err)
        nexe_headers['x-nexe-status'] = 'ZeroVM runtime error'
        resp.headers = nexe_headers
        return resp

    def _parse_zerovm_report(self, nexe_headers, report):
        nexe_headers['x-nexe-validation'] = int(report[REPORT_VALIDATOR])
        nexe_headers['x-nexe-retcode'] = int(report[REPORT_RETCODE])
        nexe_headers['x-nexe-etag'] = report[REPORT_ETAG]
        nexe_headers['x-nexe-cdr-line'] = report[REPORT_CDR]
        nexe_headers['x-nexe-status'] = report[REPORT_STATUS].replace('\n', ' ').rstrip()

    def zerovm_query(self, req):
        """Handle zerovm execution requests for the Swift Object Server."""

        debug_dir = self._debug_init(req)
        daemon_sock = req.headers.get('x-zerovm-daemon', None)
        if daemon_sock:
            daemon_sock = os.path.join(self.zerovm_sockets_dir, daemon_sock)
        #print "URL: " + req.url
        nexe_headers = {
            'x-nexe-retcode': 0,
            'x-nexe-status': 'Zerovm did not run',
            'x-nexe-etag': '',
            'x-nexe-validation': 0,
            'x-nexe-cdr-line': '0 0 0 0 0 0 0 0 0 0 0 0',
            'x-nexe-system': ''
        }

        zerovm_execute_only = False
        try:
            (device, partition, account) = \
                split_path(unquote(req.path), 3, 3)
            # if we run with only the account part in url there is no local object to work with
            # we are just executing code and returning the result over network
            zerovm_execute_only = True
        except ValueError:
            pass
        if not zerovm_execute_only:
            try:
                (device, partition, account, container, obj) = \
                    split_path(unquote(req.path), 5, 5, True)
            except ValueError, err:
                return HTTPBadRequest(body=str(err), request=req,
                                      content_type='text/plain')
        if self.app.mount_check and not check_mount(self.app.devices, device):
            return Response(status='507 %s is not mounted' % device,
                            headers=nexe_headers)
        if 'content-length' in req.headers \
                and int(req.headers['content-length']) > self.zerovm_maxinput:
            return HTTPRequestEntityTooLarge(body='RPC request too large',
                                             request=req,
                                             content_type='text/plain',
                                             headers=nexe_headers)
        if 'content-type' not in req.headers:
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body='No content type', headers=nexe_headers)
        if not req.headers['Content-Type'] in TAR_MIMES:
            return HTTPBadRequest(request=req,
                                  body='Invalid Content-Type',
                                  content_type='text/plain', headers=nexe_headers)

        pool = req.headers.get('x-zerovm-pool', 'default').lower()
        (thrdpool, queue) = self.zerovm_threadpools.get(pool, None)
        if not thrdpool:
            return HTTPBadRequest(body='Cannot find pool %s' % pool,
                                  request=req, content_type='text/plain',
                                  headers=nexe_headers)
        if thrdpool.free() <= 0 and thrdpool.waiting() >= queue:
            return HTTPServiceUnavailable(body='Slot not available',
                                          request=req, content_type='text/plain',
                                          headers=nexe_headers)
        holder = thrdpool.spawn(self._placeholder)
        zerovm_valid = False
        if req.headers.get('x-zerovm-valid', 'false').lower() in TRUE_VALUES:
            zerovm_valid = True
        tmpdir = TmpDir(
            self.app.devices,
            device,
            disk_chunk_size=self.app.disk_chunk_size,
            os_interface=self.os_interface
        )
        disk_file = None
        start = time.time()
        channels = {}
        with tmpdir.mkdtemp() as zerovm_tmp:
            read_iter = iter(lambda: req.body_file.read(self.app.network_chunk_size),'')
            upload_expiration = time.time() + self.app.max_upload_time
            untar_stream = UntarStream(read_iter)
            perf = "%.3f" % (time.time() - start)
            for chunk in read_iter:
                perf = "%s %.3f" % (perf, time.time() - start)
                if req.body_file.position > self.zerovm_maxinput:
                    return HTTPRequestEntityTooLarge(body='RPC request too large',
                                                     request=req,
                                                     content_type='text/plain',
                                                     headers=nexe_headers)
                if time.time() > upload_expiration:
                    return HTTPRequestTimeout(request=req, headers=nexe_headers)
                untar_stream.update_buffer(chunk)
                info = untar_stream.get_next_tarinfo()
                while info:
                    if info.offset_data:
                        channels[info.name] = os.path.join(zerovm_tmp, info.name)
                        fp = open(channels[info.name], 'ab')
                        untar_stream.to_write = info.size
                        untar_stream.offset_data = info.offset_data
                        for data in untar_stream.untar_file_iter():
                            fp.write(data)
                            perf = "%s %s:%.3f" % (perf, info.name, time.time() - start)
                        fp.close()
                    info = untar_stream.get_next_tarinfo()
            if 'content-length' in req.headers\
                    and int(req.headers['content-length']) != req.body_file.position:
                return HTTPClientDisconnect(request=req,
                                            headers=nexe_headers)
            perf = "%s %.3f" % (perf, time.time() - start)
            if self.zerovm_perf:
                self.logger.info("PERF UNTAR: %s" % perf)
            config = None
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
            #print json.dumps(config, cls=NodeEncoder, indent=2)
            zerovm_nexe = None
            exe_path = parse_location(config['exe'])
            if is_image_path(exe_path):
                if exe_path.image in channels:
                    self._extract_boot_file(channels, exe_path.path, channels[exe_path.image], zerovm_tmp)
                elif not daemon_sock:
                    sysimage_path = self.zerovm_sysimage_devices.get(exe_path.image, None)
                    if sysimage_path:
                        if self._extract_boot_file(channels, exe_path.path, sysimage_path, zerovm_tmp):
                            zerovm_valid = True
            if 'boot' in channels:
                zerovm_nexe = channels.pop('boot')
            elif not daemon_sock:
                return HTTPBadRequest(request=req,
                                      body='No executable found in request')

            fstab = None

            def add_to_fstab(fstab, device, access, warmup='yes', mountpoint='/'):
                if not fstab:
                    fstab = '[fstab]\n'
                fstab += 'channel=/dev/%s, mountpoint=%s, access=%s, warmup=%s\n' \
                         % (device, mountpoint, access, warmup)
                return fstab

            is_master = True
            if config.get('replicate', 1) > 1 and len(config.get('replicas', [])) < (config.get('replicate', 1) - 1):
                is_master = False
            response_channels = []
            local_object = {}
            if not zerovm_execute_only:
                local_object['path'] = SwiftPath.init(account, container, obj).url
            for ch in config['channels']:
                chan_path = parse_location(ch['path'])
                if ch['device'] in channels:
                    ch['lpath'] = channels[ch['device']]
                elif local_object and chan_path:
                    if chan_path.url in local_object['path']:
                        disk_file = DiskFile(
                            self.app.devices,
                            device,
                            partition,
                            account,
                            container,
                            obj,
                            self.logger,
                            disk_chunk_size=self.app.disk_chunk_size,)
                        if ch['access'] & (ACCESS_READABLE | ACCESS_CDR):
                            try:
                                input_file_size = disk_file.get_data_file_size()
                            except (DiskFileError, DiskFileNotExist):
                                return HTTPNotFound(request=req, headers=nexe_headers)
                            if input_file_size > self.zerovm_maxinput:
                                return HTTPRequestEntityTooLarge(body='Data object too large',
                                                                 request=req,
                                                                 content_type='text/plain',
                                                                 headers=nexe_headers)
                            ch['lpath'] = disk_file.data_file
                            channels[ch['device']] = disk_file.data_file
                        elif ch['access'] & ACCESS_WRITABLE:
                            try:
                                disk_file.timestamp = req.headers.get('x-timestamp')
                                float(disk_file.timestamp)
                            except (KeyError, ValueError, TypeError):
                                return HTTPBadRequest(body='Locally writable object specified '
                                                           'but no x-timestamp in request')
                        disk_file.channel_device = '/dev/%s' % ch['device']
                        local_object = ch
                if self.is_sysimage_device(ch['device']):
                    ch['lpath'] = self.zerovm_sysimage_devices[ch['device']]
                    fstab = add_to_fstab(fstab, ch['device'], 'ro')
                elif ch['access'] & (ACCESS_READABLE | ACCESS_CDR):
                    if not ch.get('lpath'):
                        if not chan_path or is_image_path(chan_path):
                            return HTTPBadRequest(request=req,
                                                  body='Could not resolve channel path: %s'
                                                       % ch['path'])
                    if ch['device'] in 'image':
                        fstab = add_to_fstab(fstab, ch['device'], 'ro', warmup=ch['warmup'])
                elif ch['access'] & ACCESS_WRITABLE:
                    writable_tmpdir = os.path.join(self.app.devices, device, 'tmp')
                    if not os.path.exists(writable_tmpdir):
                        mkdirs(writable_tmpdir)
                    (output_fd, output_fn) = mkstemp(dir=writable_tmpdir)
                    fallocate(output_fd, self.zerovm_maxoutput)
                    os.close(output_fd)
                    ch['lpath'] = output_fn
                    channels[ch['device']] = output_fn
                    if is_master:
                        if not chan_path:
                            response_channels.append(ch)
                        elif not ch is local_object:
                            response_channels.insert(0, ch)
                elif ch['access'] & ACCESS_NETWORK:
                    ch['lpath'] = chan_path.path

            with tmpdir.mkstemp() as (zerovm_inputmnfst_fd,
                                      zerovm_inputmnfst_fn):
                zerovm_inputmnfst = (
                    'Version=%s\n'
                    'Program=%s\n'
                    'Timeout=%s\n'
                    'Memory=%s,0\n'
                    % (
                        self.zerovm_manifest_ver,
                        zerovm_nexe or '/dev/null',
                        self.zerovm_timeout,
                        self.zerovm_maxnexemem
                    ))

                mode_mapping = {}
                for ch in config['channels']:
                    type = CHANNEL_TYPE_MAP.get(ch['device'])
                    if type is None:
                        if self.is_sysimage_device(ch['device']):
                            type = CHANNEL_TYPE_MAP.get('sysimage')
                        else:
                            return HTTPBadRequest(request=req,
                                                  body='Could not resolve channel type for: %s'
                                                       % ch['device'])
                    access = ch['access']
                    if access & ACCESS_READABLE:
                        zerovm_inputmnfst += \
                            'Channel=%s,/dev/%s,%s,0,%s,%s,0,0\n' % \
                            (ch['lpath'], ch['device'], type,
                             self.zerovm_maxiops, self.zerovm_maxinput)
                    elif access & ACCESS_CDR:
                        zerovm_inputmnfst += \
                            'Channel=%s,/dev/%s,%s,0,%s,%s,%s,%s\n' % \
                            (ch['lpath'], ch['device'], type,
                             self.zerovm_maxiops, self.zerovm_maxinput,
                             self.zerovm_maxiops, self.zerovm_maxoutput)
                    elif access & ACCESS_WRITABLE:
                        tag = '0'
                        if not ch['path'] or ch is local_object:
                            tag = '1'
                        zerovm_inputmnfst += \
                            'Channel=%s,/dev/%s,%s,%s,0,0,%s,%s\n' % \
                            (ch['lpath'], ch['device'], type, tag,
                             self.zerovm_maxiops, self.zerovm_maxoutput)
                    elif access & ACCESS_NETWORK:
                        zerovm_inputmnfst += \
                            'Channel=%s,/dev/%s,%s,0,0,0,%s,%s\n' % \
                            (ch['lpath'], ch['device'], type,
                             self.zerovm_maxiops, self.zerovm_maxoutput)
                    mode = ch.get('mode', None)
                    if mode:
                        mode_mapping[ch['device']] = mode

                network_devices = []
                for conn in config['connect'] + config['bind']:
                    zerovm_inputmnfst += 'Channel=%s\n' % conn
                    dev = conn.split(',', 2)[1][5:]  # len('/dev/') = 5
                    if dev in STD_DEVICES:
                        network_devices.append(dev)

                for dev in STD_DEVICES:
                    if not dev in channels and not dev in network_devices:
                        if 'stdin' in dev:
                            zerovm_inputmnfst += \
                                'Channel=/dev/null,/dev/stdin,0,0,%s,%s,0,0\n' % \
                                (self.zerovm_maxiops, self.zerovm_maxinput)
                        else:
                            zerovm_inputmnfst += \
                                'Channel=/dev/null,/dev/%s,0,0,0,0,%s,%s\n' % \
                                (dev, self.zerovm_maxiops, self.zerovm_maxoutput)
                if not daemon_sock:
                    zerovm_inputmnfst += \
                        'Channel=%s,/dev/self,3,0,%s,%s,0,0\n' % \
                        (zerovm_nexe, self.zerovm_maxiops, self.zerovm_maxinput)
                env = None
                if config.get('env'):
                    env = '[env]\n'
                    if local_object:
                        if local_object['access'] & (ACCESS_READABLE | ACCESS_CDR):
                            env += ENV_ITEM % ('CONTENT_LENGTH', disk_file.get_data_file_size())
                            env += ENV_ITEM % ('CONTENT_TYPE',
                                               quote_for_env(disk_file.metadata.get('Content-Type',
                                                                                    'application/octet-stream')))
                            for k, v in disk_file.metadata.iteritems():
                                meta = k.upper()
                                if meta.startswith('X-OBJECT-META-'):
                                    env += ENV_ITEM % ('HTTP_%s' % meta.replace('-', '_'),
                                                       quote_for_env(v))
                                    continue
                                for hdr in ['X-TIMESTAMP', 'ETAG', 'CONTENT-ENCODING']:
                                    if hdr in meta:
                                        env += ENV_ITEM % ('HTTP_%s' % meta.replace('-', '_'),
                                                           quote_for_env(v))
                                        break
                        elif local_object['access'] & ACCESS_WRITABLE:
                            env += ENV_ITEM % ('CONTENT_TYPE',
                                               quote_for_env(local_object.get('content_type',
                                                                              'application/octet-stream')))
                            meta = local_object.get('meta', None)
                            if meta:
                                for k, v in meta.iteritems():
                                    env += ENV_ITEM % ('HTTP_X_OBJECT_META_%s' % k.upper().replace('-', '_'),
                                                       quote_for_env(v))
                        env += ENV_ITEM % ('DOCUMENT_ROOT', disk_file.channel_device)
                        config['env']['REQUEST_METHOD'] = 'POST'
                        config['env']['PATH_INFO'] = disk_file.name
                    for k, v in config['env'].iteritems():
                        if v:
                            env += ENV_ITEM % (k, quote_for_env(v))

                args = '[args]\nargs = %s' % config['name']
                if config.get('args'):
                    # zerovm_inputmnfst += 'CommandLine=%s\n'\
                    #                      % config['args']
                    args += ' %s' % config['args']
                args += '\n'

                mapping = None
                if mode_mapping:
                    mapping = '[mapping]\n'
                    for ch_device, mode in mode_mapping.iteritems():
                        mapping += 'channel=/dev/%s, mode=%s\n' % (ch_device, mode)
                (output_fd, nvram_file) = mkstemp()
                for chunk in [fstab, args, env, mapping]:
                    os.write(output_fd, chunk or '')
                os.close(output_fd)
                zerovm_inputmnfst += \
                    'Channel=%s,/dev/nvram,3,0,%s,%s,%s,%s\n' % \
                    (nvram_file, self.zerovm_maxiops, self.zerovm_maxinput, 0, 0)

                zerovm_inputmnfst += 'Node=%d\n' \
                                     % (config['id'])
                if 'name_service' in config:
                    zerovm_inputmnfst += 'NameServer=%s\n'\
                                         % config['name_service']
                #print json.dumps(config, sort_keys=True, indent=2)
                #print zerovm_inputmnfst
                #print open(nvram_file).read()
                holder.kill()
                if thrdpool.free() <= 0 and thrdpool.waiting() >= queue:
                    return HTTPServiceUnavailable(body='Slot not available',
                                                  request=req, content_type='text/plain',
                                                  headers=nexe_headers)
                self._debug_before_exec(config, debug_dir, nexe_headers, nvram_file, zerovm_inputmnfst)
                start = time.time()
                daemon_status = None
                if daemon_sock:
                    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                    try:
                        sock.connect(daemon_sock)
                        thrd = thrdpool.spawn(self.send_to_socket, sock, zerovm_inputmnfst)
                    except IOError:
                        self._cleanup_daemon(daemon_sock)
                        sysimage_path = self.zerovm_sysimage_devices.get(exe_path.image, None)
                        if not sysimage_path:
                            return HTTPInternalServerError(body='System image does not exist: %s'
                                                                % exe_path.image)
                        if not self._extract_boot_file(channels, exe_path.path, sysimage_path, zerovm_tmp):
                            return HTTPInternalServerError(body='Cannot find daemon nexe in system image %s'
                                                                % sysimage_path)
                        zerovm_nexe = channels.pop('boot')
                        zerovm_inputmnfst = re.sub(r'^(?m)Program=.*',
                                                   'Program=%s' % zerovm_nexe,
                                                   zerovm_inputmnfst)
                        zerovm_inputmnfst += 'Job = %s\n' % daemon_sock
                        #print zerovm_inputmnfst
                        thrd = self._create_zerovm_thread(zerovm_inputmnfst,
                                                          zerovm_inputmnfst_fd, zerovm_inputmnfst_fn,
                                                          zerovm_valid, thrdpool)
                        (zerovm_retcode, zerovm_stdout, zerovm_stderr) = thrd.wait()
                        self._debug_after_exec(debug_dir, nexe_headers, zerovm_retcode, zerovm_stderr, zerovm_stdout)
                        if zerovm_stderr:
                            self.logger.warning('zerovm stderr: '+zerovm_stderr)
                            zerovm_stdout += zerovm_stderr
                        report = zerovm_stdout.split('\n', REPORT_LENGTH - 1)
                        if len(report) < REPORT_LENGTH or zerovm_retcode > 1:
                            resp = self._create_exec_error(nexe_headers, zerovm_retcode, zerovm_stdout)
                            return req.get_response(resp)
                        else:
                            try:
                                daemon_status = int(report[REPORT_DAEMON])
                                self._parse_zerovm_report(nexe_headers, report)
                            except Exception:
                                resp = HTTPInternalServerError(body=zerovm_stdout)
                                return req.get_response(resp)
                        if daemon_status != 1:
                            return HTTPInternalServerError(body=zerovm_stdout)
                        try:
                            sock.connect(daemon_sock)
                            thrd = thrdpool.spawn(self.send_to_socket, sock, zerovm_inputmnfst)
                        except IOError:
                            return HTTPInternalServerError(body='Cannot connect to daemon even after daemon restart: '
                                                                'socket %s' % daemon_sock,
                                                           headers=nexe_headers)
                else:
                    thrd = self._create_zerovm_thread(zerovm_inputmnfst,
                                                      zerovm_inputmnfst_fd, zerovm_inputmnfst_fn,
                                                      zerovm_valid, thrdpool)
                (zerovm_retcode, zerovm_stdout, zerovm_stderr) = thrd.wait()
                perf = "%.3f" % (time.time() - start)
                if self.zerovm_perf:
                    self.logger.info("PERF SPAWN: %s" % perf)
                self._debug_after_exec(debug_dir, nexe_headers, zerovm_retcode, zerovm_stderr, zerovm_stdout)
                if nvram_file:
                    try:
                        os.unlink(nvram_file)
                    except OSError:
                        pass
                if zerovm_stderr:
                    self.logger.warning('zerovm stderr: '+zerovm_stderr)
                    zerovm_stdout += zerovm_stderr
                # if zerovm_retcode:
                #     err = 'ERROR OBJ.QUERY retcode=%s, '\
                #           ' zerovm_stdout=%s'\
                #             % (self.retcode_map[zerovm_retcode],
                #                zerovm_stdout)
                #     self.logger.exception(err)
                report = zerovm_stdout.split('\n', REPORT_LENGTH - 1)
                if len(report) < REPORT_LENGTH or zerovm_retcode > 1:
                    resp = self._create_exec_error(nexe_headers, zerovm_retcode, zerovm_stdout)
                    return req.get_response(resp)
                else:
                    try:
                        if daemon_status != 1:
                            daemon_status = int(report[REPORT_DAEMON])
                        self._parse_zerovm_report(nexe_headers, report)
                    except Exception:
                        resp = HTTPInternalServerError(body=zerovm_stdout)
                        return req.get_response(resp)

                self.logger.info('Zerovm CDR: %s' % nexe_headers['x-nexe-cdr-line'])

                response = Response(request=req)
                update_headers(response, nexe_headers)
                response.headers['X-Timestamp'] =\
                    normalize_timestamp(time.time())
                response.headers['x-nexe-system'] = nexe_headers['x-nexe-system']
                response.content_type = 'application/x-gtar'
                if daemon_status == 1:
                    response.headers['x-zerovm-daemon'] = req.headers.get('x-zerovm-daemon', None)
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
                        ch['size'] = self.os_interface.path.getsize(ch['lpath'])
                    info = tar_stream.create_tarinfo(ftype=REGTYPE, name=ch['device'],
                                                     size=ch['size'])
                    #print [ch['device'], ch['size'], ch['lpath']]
                    resp_size += len(info) + TarStream.get_archive_size(ch['size'])
                    ch['info'] = info
                    immediate_responses.append(ch)
                if local_object and local_object['access'] & ACCESS_WRITABLE:
                    local_object['size'] = self.os_interface.path.getsize(local_object['lpath'])
                    if local_object['content_type'].startswith('message/http'):
                        self._read_cgi_response(local_object, nph=True)
                    elif local_object['content_type'].startswith('message/cgi'):
                        self._read_cgi_response(local_object, nph=False)
                    error = self._finalize_local_file(local_object, disk_file, nexe_headers['x-nexe-etag'],
                                                      account, container, obj, req, device)
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
                    sysmap_info = tar_stream.create_tarinfo(ftype=REGTYPE, name='sysmap',
                                                            size=len(sysmap_dump))
                    resp_size += len(sysmap_info) + TarStream.get_archive_size(len(sysmap_dump))

                def resp_iter(channels, chunk_size):
                    tar_stream = TarStream(chunk_size=chunk_size)
                    if send_config:
                        for chunk in tar_stream._serve_chunk(sysmap_info):
                            yield chunk
                        for chunk in tar_stream._serve_chunk(sysmap_dump):
                            yield chunk
                        blocks, remainder = divmod(len(sysmap_dump), BLOCKSIZE)
                        if remainder > 0:
                            nulls = NUL * (BLOCKSIZE - remainder)
                            for chunk in tar_stream._serve_chunk(nulls):
                                yield chunk
                    for ch in channels:
                        fp = open(ch['lpath'], 'rb')
                        if ch.get('offset', None):
                            fp.seek(ch['offset'])
                        reader = iter(lambda: fp.read(chunk_size), '')
                        for chunk in tar_stream._serve_chunk(ch['info']):
                            yield chunk
                        for data in reader:
                            for chunk in tar_stream._serve_chunk(data):
                                yield chunk
                        fp.close()
                        os.unlink(ch['lpath'])
                        blocks, remainder = divmod(ch['size'], BLOCKSIZE)
                        if remainder > 0:
                            nulls = NUL * (BLOCKSIZE - remainder)
                            for chunk in tar_stream._serve_chunk(nulls):
                                yield chunk
                    if tar_stream.data:
                        yield tar_stream.data

                response.app_iter=resp_iter(immediate_responses, self.app.network_chunk_size)
                response.content_length = resp_size
                return req.get_response(response)

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
                         or req.headers.get('content-type', '') in 'application/x-nexe'):
                    self.logger.info('%s Started pre-validation due to: content-type: %s, x-zerovm-validate: %s'
                                     % (req.url,
                                        req.headers.get('content-type', ''),
                                        str('x-zerovm-validate' in req.headers)))

                    def validate_resp(status, response_headers, exc_info=None):
                        if 200 <= int(status.split(' ')[0]) < 300:
                            if self.validate(req):
                                response_headers.append(('X-Zerovm-Valid', 'true'))
                        return start_response(status, response_headers, exc_info)

                    return self.app(env, validate_resp)
                elif 'x-zerovm-valid' in req.headers and req.method == 'GET':
                    self.logger.info('%s Started validity check due to: x-zerovm-valid: %s'
                                     % (req.url, str('x-zerovm-valid' in req.headers)))

                    def validate_resp(status, response_headers, exc_info=None):
                        if 200 <= int(status.split(' ')[0]) < 300:
                            if self.is_validated(req):
                                response_headers.append(('X-Zerovm-Valid', 'true'))
                        return start_response(status, response_headers, exc_info)

                    return self.app(env, validate_resp)
                else:
                    return self.app(env, start_response)
            except (Exception, Timeout):
                self.logger.exception(_('ERROR __call__ error with %(method)s'
                                        ' %(path)s '), {'method': req.method, 'path': req.path})
                res = HTTPInternalServerError(body=traceback.format_exc())
        trans_time = time.time() - start_time
        if 'x-nexe-cdr-line' in res.headers:
            res.headers['x-nexe-cdr-line'] = '%.3f, %s' % (trans_time, res.headers['x-nexe-cdr-line'])
        if self.app.log_requests:
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
        if self.app.mount_check and not check_mount(self.app.devices, device):
            return False
        file = DiskFile(
            self.app.devices,
            device,
            partition,
            account,
            container,
            obj,
            self.logger,
            disk_chunk_size=self.app.disk_chunk_size,
        )
        try:
            nexe_size = os.path.getsize(file.data_file)
        except (DiskFileError, DiskFileNotExist):
            return False
        if nexe_size > self.zerovm_maxnexe:
            return False
        if file.is_deleted():
            return False
        tmpdir = TmpDir(
            self.app.devices,
            device,
            disk_chunk_size=self.app.disk_chunk_size,
            os_interface=self.os_interface
        )
        with tmpdir.mkstemp() as (zerovm_inputmnfst_fd, zerovm_inputmnfst_fn):
            zerovm_inputmnfst = (
                'Version=%s\n'
                'Program=%s\n'
                'Timeout=%s\n'
                'Memory=%s,0\n'
                'Channel=/dev/null,/dev/stdin, 0,0,1,1,0,0\n'
                'Channel=/dev/null,/dev/stdout,0,0,0,0,1,1\n'
                'Channel=/dev/null,/dev/stderr,0,0,0,0,1,1\n'
                % (
                    self.zerovm_manifest_ver,
                    file.data_file,
                    self.zerovm_timeout,
                    self.zerovm_maxnexemem
                ))
            while zerovm_inputmnfst:
                written = self.os_interface.write(zerovm_inputmnfst_fd,
                                                  zerovm_inputmnfst)
                zerovm_inputmnfst = zerovm_inputmnfst[written:]

            (thrdpool, queue) = self.zerovm_threadpools['default']
            thrd = thrdpool.spawn(self.execute_zerovm, zerovm_inputmnfst_fn, ['-F'])
            (zerovm_retcode, zerovm_stdout, zerovm_stderr) = thrd.wait()
            if zerovm_stderr:
                self.logger.warning('zerovm stderr: ' + zerovm_stderr)
            if zerovm_retcode == 0:
                report = zerovm_stdout.split('\n', 1)
                try:
                    validated = int(report[REPORT_VALIDATOR])
                except ValueError:
                    return False
                if validated == 0:
                    metadata = file.metadata
                    metadata['Validated'] = metadata['ETag']
                    write_metadata(file.data_file, metadata)
                    return True
            return False

    def is_validated(self, req):
        try:
            (device, partition, account, container, obj) = \
                split_path(unquote(req.path), 5, 5, True)
        except ValueError:
            return False
        if self.app.mount_check and not check_mount(self.app.devices, device):
            return False
        file = DiskFile(
            self.app.devices,
            device,
            partition,
            account,
            container,
            obj,
            self.logger,
            disk_chunk_size=self.app.disk_chunk_size,
        )
        if file.is_deleted():
            return False
        metadata = read_metadata(file.data_file)
        status = metadata.get('Validated', None)
        etag = metadata.get('ETag', None)
        if status and etag and etag == status:
            return True
        return False

    def _finalize_local_file(self, local_object, disk_file, nexe_etag,
                             account, container, obj, request, device):
        data = nexe_etag.split(' ')
        if data[0].startswith('/'):
            mem_etag = None
            channel_etag = data
        else:
            mem_etag = data[0]
            channel_etag = data[1:]
        reported_etag = None
        for dev, etag in zip(*[iter(channel_etag)]*2):
            if disk_file.channel_device in dev:
                reported_etag = etag
                break
        if not reported_etag:
            return HTTPUnprocessableEntity(body='No etag found for resulting object '
                                                'after writing channel %s data' % disk_file.channel_device)
        if len(reported_etag) != MD5HASH_LENGTH:
            return HTTPUnprocessableEntity(body='Bad etag for %s: %s'
                                                % (disk_file.channel_device, reported_etag))
        old_delete_at = int(disk_file.metadata.get('X-Delete-At') or 0)
        metadata = {
            'X-Timestamp': disk_file.timestamp,
            'Content-Type': local_object['content_type'],
            'ETag': reported_etag,
            'Content-Length': str(local_object['size'])}
        metadata.update(('x-object-meta-' + val[0], val[1]) for val in local_object['meta'].iteritems())
        fd = os.open(local_object['lpath'], os.O_RDONLY)
        if local_object.get('offset', None):
            # need to re-write the file
            newfd, new_name = mkstemp()
            new_etag = md5()
            try:
                os.lseek(fd, local_object['offset'], os.SEEK_SET)
                for chunk in iter(lambda: os.read(fd, self.app.disk_chunk_size), ''):
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
                for chunk in iter(lambda: os.read(fd, self.app.disk_chunk_size), ''):
                    new_etag.update(chunk)
            except IOError:
                return HTTPInternalServerError(body='Cannot read resulting file for device %s'
                                                    % disk_file.channel_device)
            metadata['ETag'] = new_etag.hexdigest()
        disk_file.tmppath = local_object['lpath']
        disk_file.put(fd, metadata)
        disk_file.unlinkold(metadata['X-Timestamp'])
        if old_delete_at > 0:
            self.app.delete_at_update(
                'DELETE', old_delete_at, account, container, obj,
                request, device)
        self.app.container_update(
            'PUT',
            account,
            container,
            obj,
            request.headers,
            HeaderKeyDict({
                'x-size': disk_file.metadata['Content-Length'],
                'x-content-type': disk_file.metadata['Content-Type'],
                'x-timestamp': disk_file.metadata['X-Timestamp'],
                'x-etag': disk_file.metadata['ETag']}),
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
                        m = re.match('\d+ \(([^\)]+)', open('/proc/%s/stat' % pid).read())
                        if 'zerovm.daemon' in m.group(1):
                            result.append(pid)
            except OSError:
                continue
        return result


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def obj_query_filter(app):
        return ObjectQueryMiddleware(app, conf)
    return obj_query_filter
