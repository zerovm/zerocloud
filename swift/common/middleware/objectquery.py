from string import split
from swift.common.bufferedhttp import http_connect, http_connect_raw

try:
    import simplejson as json
except ImportError:
    import json
from contextlib import contextmanager
import os
import shutil
import time
import traceback
import tarfile
from eventlet import GreenPool, sleep
from eventlet.green import select, subprocess
from eventlet.timeout import Timeout
from urllib import unquote
from hashlib import md5
from tempfile import mkstemp, mkdtemp
from swift.common.swob import Request, Response, HTTPNotFound, HTTPPreconditionFailed,\
    HTTPRequestTimeout, HTTPRequestEntityTooLarge, HTTPBadRequest,\
    HTTPUnprocessableEntity, HTTPServiceUnavailable, HTTPClientDisconnect, HTTPInternalServerError
from swift.common.middleware.proxyquery import TAR_MIMES, ACCESS_CDR, ACCESS_READABLE, ACCESS_WRITABLE
from swift.common.tarstream import UntarStream, TarStream, REGTYPE, BLOCKSIZE, NUL

from swift.common.utils import normalize_timestamp,\
    fallocate, split_path, get_logger, mkdirs, disable_fallocate, TRUE_VALUES
from swift.obj.server import DiskFile, write_metadata, read_metadata
from swift.common.constraints import check_mount, check_utf8
from swift.common.exceptions import DiskFileError, DiskFileNotExist

channel_type_map = {
    'stdin': 0, 'stdout': 0, 'stderr': 0,
    'input': 3, 'output': 3,
    'debug': 0, 'image': 1, 'sysimage': 3
}

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


class ObjectQueryMiddleware(object):

    def __init__(self, app, conf, logger=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='obj-query')

        self.direct_put = conf.get('zerovm_direct_put_url', None)
        if self.direct_put:
            self.proxy_addr, self.proxy_port = self.direct_put.split(':')[1:3]
            self.proxy_port, self.proxy_version = self.proxy_port.split('/')[:2]
            self.proxy_addr = self.proxy_addr.split('//')[1]
        self.zerovm_manifest_ver = conf.get('zerovm_manifest_ver','09082012')
        self.zerovm_exename = [i.strip() for i in conf.get('zerovm_exename', 'zerovm').split() if i.strip()]
        #self.zerovm_xparams = set(i.strip() for i in conf.get('zerovm_xparams', '').split() if i.strip())

        # maximum number of simultaneous running zerovms, others are queued
        self.zerovm_maxpool = int(conf.get('zerovm_maxpool', 10))

        # maximum length of queue of request awaiting zerovm executions
        self.zerovm_maxqueue = int(conf.get('zerovm_maxqueue', 3))

        # timeout for zerovm to finish execution
        self.zerovm_timeout = int(conf.get('zerovm_timeout', 5))

        # timeout for zerovm between TERM signal and KILL signal
        self.zerovm_kill_timeout = int(conf.get('zerovm_kill_timeout', 1))

        # maximum length of manifest line (both input and output)
        #self.zerovm_maxmnfstline = int(conf.get('zerovm_maxmnfstline', 1024))

        # maximum number of lines in input and output manifest files
        #self.zerovm_maxmnfstlines = int(conf.get('zerovm_maxmnfstlines', 128))

        # maximum input data file size
        self.zerovm_maxinput = int(conf.get('zerovm_maxinput', 1024 * 1048576))

        self.zerovm_maxiops = int(conf.get('zerovm_maxiops', 1024 * 1048576))

        # maximum nexe size
        self.zerovm_maxnexe = int(conf.get('zerovm_maxnexe', 256 * 1048576))

        # maximum output data file size
        self.zerovm_maxoutput = int(conf.get('zerovm_maxoutput', 1024 * 1048576))

        self.zerovm_maxchunksize = int(conf.get('zerovm_maxchunksize', 1024 * 1024))

        # max syscall number
        self.zerovm_maxsyscalls = int(conf.get('zerovm_maxsyscalls', 1024 * 1048576))

        # max nexe memory size
        self.zerovm_maxnexemem = int(conf.get('zerovm_maxnexemem', 4 * 1024 * 1048576))

        # hardcoded, we don't want to crush the server
        self.zerovm_stderr_size = 65536
        self.zerovm_stdout_size = 65536
        self.retcode_map = ('OK', 'Error', 'Timed out', 'Killed', 'Output too long')

        self.fault_injection = conf.get('fault_injection', ' ') # for unit-tests.
        self.os_interface = os

        # green thread for zerovm execution
        self.zerovm_thrdpool = GreenPool(self.zerovm_maxpool)

        if conf.get('disable_fallocate', 'no').lower() in TRUE_VALUES:
            disable_fallocate()

    def execute_zerovm(self, zerovm_inputmnfst_fn):
        cmdline = []
        cmdline += self.zerovm_exename
        cmdline += ['-M%s' % zerovm_inputmnfst_fn]
        proc = subprocess.Popen(cmdline, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)

        stdout_data = ''
        stderr_data = ''
        readable = [proc.stdout, proc.stderr]
        start = time.time()

        def get_output(stdout_data, stderr_data):
            (data1, data2) = proc.communicate()
            stdout_data += data1
            stderr_data += data2
            return stdout_data, stderr_data

        while time.time() - start < self.zerovm_timeout:
            rlist, wlist, xlist =\
            select.select(readable, [], [], start - time.time() + self.zerovm_timeout)
            if not rlist:
                continue
            for stream in rlist:
                data = self.os_interface.read(stream.fileno(), 4096)
                if not data:
                    readable.remove(stream)
                    continue
                if stream == proc.stdout:
                    stdout_data += data
                elif stream == proc.stderr:
                    stderr_data += data
                if len(stdout_data) > self.zerovm_stdout_size\
                or len(stderr_data) > self.zerovm_stderr_size:
                    proc.kill()
                    return 4, stdout_data, stderr_data
            if proc.poll() is not None:
                stdout_data, stderr_data = get_output(stdout_data, stderr_data)
                ret = 0
                if proc.returncode:
                    ret = 1
                return ret, stdout_data, stderr_data
            sleep(0.1)
        if proc.poll() is None:
            proc.terminate()
            start = time.time()
            while time.time() - start\
            < self.zerovm_kill_timeout:
                if proc.poll() is not None:
                    stdout_data, stderr_data = get_output(stdout_data, stderr_data)
                    return 2, stdout_data, stderr_data
                sleep(0.1)
            proc.kill()
            stdout_data, stderr_data = get_output(stdout_data, stderr_data)
            return 3, stdout_data, stderr_data

    def zerovm_query(self, req):
        """Handle HTTP QUERY requests for the Swift Object Server."""

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
            zerovm_execute_only = True
        except ValueError:
            pass
        if not zerovm_execute_only:
            try:
                (device, partition, account, container, obj) =\
                split_path(unquote(req.path), 5, 5, True)
            except ValueError, err:
                return HTTPBadRequest(body=str(err), request=req,
                    content_type='text/plain')

        if self.zerovm_thrdpool.free() <= 0\
        and self.zerovm_thrdpool.waiting() >= self.zerovm_maxqueue:
            return HTTPServiceUnavailable(body='Slot not available',
                request=req, content_type='text/plain', headers=nexe_headers)
        if self.app.mount_check and not check_mount(self.app.devices, device):
            return Response(status='507 %s is not mounted' % device, headers=nexe_headers)
        if 'content-length' in req.headers\
        and int(req.headers['content-length']) > self.zerovm_maxinput:
            return HTTPRequestEntityTooLarge(body='Your request is too large'
                , request=req, content_type='text/plain', headers=nexe_headers)
        if 'content-type' not in req.headers:
            return HTTPBadRequest(request=req, content_type='text/plain'
                , body='No content type', headers=nexe_headers)
        if not req.headers['Content-Type'] in TAR_MIMES:
            return HTTPBadRequest(request=req,
                body='Invalid Content-Type',
                content_type='text/plain', headers=nexe_headers)

        tmpdir = TmpDir(
            self.app.devices,
            device,
            disk_chunk_size=self.app.disk_chunk_size,
            os_interface=self.os_interface
        )
        file = None
        if not zerovm_execute_only:
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
                input_file_size = file.get_data_file_size()
            except (DiskFileError, DiskFileNotExist):
                return HTTPNotFound(request=req, headers=nexe_headers)
            if input_file_size > self.zerovm_maxinput:
                return HTTPRequestEntityTooLarge(body='Data Object is too large'
                    , request=req, content_type='text/plain', headers=nexe_headers)

        channels = {}
        with tmpdir.mkdtemp() as zerovm_tmp:
            reader = req.environ['wsgi.input'].read
            read_iter = iter(lambda: reader(self.app.network_chunk_size),'')
            upload_size = 0
            etag = md5()
            upload_expiration = time.time() + self.app.max_upload_time
            untar_stream = UntarStream(read_iter)
            for chunk in read_iter:
                upload_size += len(chunk)
                if time.time() > upload_expiration:
                    return HTTPRequestTimeout(request=req, headers=nexe_headers)
                etag.update(chunk)
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
                        fp.close()
                    info = untar_stream.get_next_tarinfo()
            if 'content-length' in req.headers\
            and int(req.headers['content-length']) != upload_size:
                return HTTPClientDisconnect(request=req, headers=nexe_headers)
            etag = etag.hexdigest()
            if 'etag' in req.headers and req.headers['etag'].lower()\
            != etag:
                return HTTPUnprocessableEntity(request=req, headers=nexe_headers)

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

            zerovm_nexe = None
            if config['exe'][0] != '/' and 'image' in channels:
                tar = tarfile.open(name=channels['image'])
                nexe = tar.extractfile(config['exe'])
                if nexe:
                    channels['boot'] = os.path.join(zerovm_tmp, 'boot')
                    fp = open(channels['boot'], 'wb')
                    reader = iter(lambda: nexe.read(self.app.disk_chunk_size),'')
                    for chunk in reader:
                        fp.write(chunk)
                    fp.close()
                tar.close()
            if 'boot' in channels:
                zerovm_nexe = channels.pop('boot')
            else:
                return HTTPBadRequest(request=req,
                    body='No executable found in request')

            response_channels = []
            local_object = None
            if not zerovm_execute_only:
                local_object = '/'.join(['', container, obj])
            for ch in config['channels']:
                if ch['device'] in channels:
                    ch['lpath'] = channels[ch['device']]
                if ch['access'] & (ACCESS_READABLE | ACCESS_CDR):
                    if not ch['path'] or ch['path'][0] != '/':
                        return HTTPBadRequest(request=req,
                            body='Could not resolve channel path %s'
                                 % ch['path'])
                    if local_object:
                        if ch['path'] in local_object:
                            ch['lpath'] = file.data_file
                            channels[ch['device']] = file.data_file
                elif ch['access'] & ACCESS_WRITABLE:
                    (output_fd, output_fn) = mkstemp()
                    fallocate(output_fd, self.zerovm_maxoutput)
                    #self.os_interface.close(output_fd)
                    ch['lpath'] = output_fn
                    channels[ch['device']] = output_fn
                    if not ch['path']:
                        response_channels.append(ch)
                    else:
                        response_channels.insert(0, ch)

            with tmpdir.mkstemp() as (zerovm_inputmnfst_fd,
                                    zerovm_inputmnfst_fn):
                zerovm_inputmnfst = (
                    'Version=%s\n'
                    'Nexe=%s\n'
                    'NexeMax=%s\n'
                    'Timeout=%s\n'
                    'MemMax=%s\n'
                    % (
                        self.zerovm_manifest_ver,
                        zerovm_nexe,
                        self.zerovm_maxnexe,
                        self.zerovm_timeout,
                        self.zerovm_maxnexemem
                        ))


                for ch in config['channels']:
                    type = channel_type_map.get(ch['device'])
                    if type is None:
                        return HTTPBadRequest(request=req,
                            body='Could not resolve channel type for: %s'
                                 % ch['device'])
                    access = ch['access']
                    if access & ACCESS_READABLE:
                        zerovm_inputmnfst += \
                            'Channel=%s,/dev/%s,%s,%s,%s,0,0\n' % \
                            (ch['lpath'], ch['device'], type,
                             self.zerovm_maxiops, self.zerovm_maxinput)
                    elif access & ACCESS_CDR:
                        zerovm_inputmnfst +=\
                        'Channel=%s,/dev/%s,%s,%s,%s,%s,%s\n' %\
                        (ch['lpath'], ch['device'], type,
                         self.zerovm_maxiops, self.zerovm_maxinput,
                         self.zerovm_maxiops, self.zerovm_maxoutput)
                    elif access & ACCESS_WRITABLE:
                        zerovm_inputmnfst +=\
                        'Channel=%s,/dev/%s,%s,0,0,%s,%s\n' %\
                        (ch['lpath'], ch['device'], type,
                         self.zerovm_maxiops, self.zerovm_maxoutput)

                for conn in config['connect'] + config['bind']:
                    zerovm_inputmnfst += 'Channel=%s\n' % conn

                for dev in ['stdin', 'stdout', 'stderr']:
                    if not dev in channels:
                        if 'stdin' in dev:
                            zerovm_inputmnfst +=\
                            'Channel=/dev/null,/dev/stdin,0,%s,%s,0,0\n' %\
                            (self.zerovm_maxiops, self.zerovm_maxinput)
                        else:
                            zerovm_inputmnfst +=\
                            'Channel=/dev/null,/dev/%s,0,0,0,%s,%s\n' %\
                            (dev, self.zerovm_maxiops, self.zerovm_maxoutput)

                if config['env']:
                    zerovm_inputmnfst += 'Environment=%s\n' % ','.join(
                        reduce(lambda x, y: x + y, config['env'].items()))

                if config['args']:
                    zerovm_inputmnfst += 'CommandLine=%s\n'\
                                         % config['args']

                nexe_name = config['name']
                zerovm_inputmnfst += 'NodeName=%s,%d\n' \
                                     % (nexe_name, config['id'])
                if 'name_service' in config:
                    zerovm_inputmnfst += 'NameServer=%s\n'\
                                         % config['name_service']
                #print config
                #print zerovm_inputmnfst
                while zerovm_inputmnfst:
                    written = self.os_interface.write(zerovm_inputmnfst_fd,
                        zerovm_inputmnfst)
                    zerovm_inputmnfst = zerovm_inputmnfst[written:]

                thrd = self.zerovm_thrdpool.spawn(self.execute_zerovm, zerovm_inputmnfst_fn)
                (zerovm_retcode, zerovm_stdout, zerovm_stderr) = thrd.wait()
                if zerovm_stderr:
                    self.logger.warning('zerovm stderr: '+zerovm_stderr)
                if zerovm_retcode:
                    err = 'ERROR OBJ.QUERY retcode=%s, '\
                          ' zerovm_stdout=%s'\
                            % (self.retcode_map[zerovm_retcode],
                               zerovm_stdout)
                    self.logger.exception(err)
                    resp = Response(body=err,status='503 Internal Error')
                    nexe_headers['x-nexe-status'] = 'ZeroVM runtime error'
                    resp.headers = nexe_headers
                    return resp
                report = zerovm_stdout.splitlines()
                if len(report) < 5:
                    nexe_validation = 0
                    nexe_retcode = 0
                    nexe_etag = ''
                    nexe_cdr_line = '0 0 0 0 0 0 0 0 0 0 0 0'
                    nexe_status = 'Zerovm crashed'
                else:
                    nexe_validation = int(report[0])
                    nexe_retcode = int(report[1])
                    nexe_etag = report[2]
                    nexe_cdr_line = report[3]
                    nexe_status = '\n'.join(report[4:])

                self.logger.info('Zerovm CDR: %s' % nexe_cdr_line)

                response = Response(request=req)
                response.headers['x-nexe-retcode'] = nexe_retcode
                response.headers['x-nexe-status'] = nexe_status
                response.headers['x-nexe-etag'] = nexe_etag
                response.headers['x-nexe-validation'] = nexe_validation
                response.headers['x-nexe-cdr-line'] = nexe_cdr_line
                response.headers['X-Timestamp'] =\
                normalize_timestamp(time.time())
                if nexe_name:
                    response.headers['x-nexe-system'] = nexe_name
                response.content_type = 'application/x-gtar'

                tar_stream = TarStream()
                resp_size = 0
#                account = req.headers['x-account-name']
                immediate_responses = []
                for ch in response_channels:
                    file_size = self.os_interface.path.getsize(ch['lpath'])
#                    path = ch.get('path', None)
#                    if self.direct_put and path:
#                        dest_header = '/%s/%s%s' % (self.proxy_version, account, unquote(path))
#                        dest_req = Request.blank(dest_header,
#                            environ=req.environ, headers=req.headers)
#                        dest_req.path_info = dest_header
#                        dest_req.method = 'PUT'
#                        dest_req.headers['Content-Length'] = file_size
#                        if 'expect' in dest_req.headers:
#                            del dest_req.headers['expect']
#                        if 'transfer-encoding' in dest_req.headers:
#                            del dest_req.headers['transfer-encoding']
#                        reader = iter(lambda: open(ch['lpath'], 'rb').read(self.app.network_chunk_size), '')
#                        print dest_req.__dict__
#                        conn = http_connect_raw(self.proxy_addr, self.proxy_port, 'PUT', dest_req.path_info, dest_req.headers)
#                        if conn:
#                            for chunk in reader:
#                                conn.send(chunk)
#                            resp = conn.getresponse()
#                            print [resp.status, resp.reason, resp.getheaders()]
#                            if resp.status >= 300:
#                                response.body = resp.read()
#                                response.status = '%d %s' % (resp.status, resp.reason)
#                                return response
#                            resp.read()
#                            continue
                    info = tar_stream.create_tarinfo(REGTYPE, ch['device'],
                        file_size)
                    resp_size += len(info) + \
                                 tar_stream.get_archive_size(file_size)
                    ch['info'] = info
                    ch['size'] = file_size
                    immediate_responses.append(ch)

                def resp_iter(channels, chunk_size):
                    tar_stream = TarStream(chunk_size=chunk_size)
                    for ch in channels:
                        fp = open(ch['lpath'], 'rb')
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

                response.app_iter=resp_iter(immediate_responses,
                    self.app.network_chunk_size)
                response.content_length = resp_size
                return req.get_response(response)

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
                elif 'x-validator-exec' in req.headers and req.method == 'PUT':
                    def validate_resp(status, response_headers, exc_info=None):
                        if 200 <= int(status.split(' ')[0]) < 300:
                            valid = self.validate(req)
                            response_headers.append(('x-nexe-validation',str(valid)))
                        return start_response(status, response_headers, exc_info)
                    return self.app(env, validate_resp)
                elif 'x-nexe-validation' in req.headers and req.method == 'GET':
                    def validate_resp(status, response_headers, exc_info=None):
                        if 200 <= int(status.split(' ')[0]) < 300:
                            valid = self.get_validation_status(req)
                            response_headers.append(('x-nexe-validation',str(valid)))
                        return start_response(status, response_headers, exc_info)
                    return self.app(env, validate_resp)
                else:
                    return self.app(env, start_response)
            except (Exception, Timeout):
                self.logger.exception(_('ERROR __call__ error with %(method)s'
                                        ' %(path)s '), {'method': req.method, 'path': req.path})
                res = HTTPInternalServerError(body=traceback.format_exc())
        trans_time = time.time() - start_time
        if self.app.log_requests:
            log_line = '%s - - [%s] "%s %s" %s %s "%s" "%s" "%s" %.4f' % (
                req.remote_addr,
                time.strftime('%d/%b/%Y:%H:%M:%S +0000',
                    time.gmtime()),
                req.method, req.path, res.status.split()[0],
                res.content_length or '-', req.referer or '-',
                req.headers.get('x-trans-id', '-'),
                req.user_agent or '-',
                trans_time)

            self.logger.info(log_line)

        return res(env, start_response)

    def validate(self, req):
        validator = str(req.headers.get('x-validator-exec', ''))
        if 'fuzzy' in validator:
            self.zerovm_exename.append('-z')
        else:
            return 0
        try:
            (device, partition, account, container, obj) =\
                split_path(unquote(req.path), 5, 5, True)
        except ValueError:
            return 0
        if self.app.mount_check and not check_mount(self.app.devices, device):
            return 0
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
            return 0
        if nexe_size > self.zerovm_maxnexe:
            return 0
        if file.is_deleted():
            return 0
        with file.mkstemp() as zerovm_inputmnfst_fd:
            zerovm_inputmnfst_fn = file.tmppath
            zerovm_inputmnfst = (
                'Version=%s\n'
                'Nexe=%s\n'
                % (
                    self.zerovm_manifest_ver,
                    file.data_file,
                    ))
            while zerovm_inputmnfst:
                written = self.os_interface.write(zerovm_inputmnfst_fd,
                    zerovm_inputmnfst)
                zerovm_inputmnfst = zerovm_inputmnfst[written:]

            thrd = self.zerovm_thrdpool.spawn(self.execute_zerovm, zerovm_inputmnfst_fn)
            (zerovm_retcode, zerovm_stdout, zerovm_stderr) = thrd.wait()
            if zerovm_retcode:
                err = 'ERROR OBJ.QUERY retcode=%s, '\
                      ' zerovm_stdout=%s'\
                % (self.retcode_map[zerovm_retcode],
                   zerovm_stdout)
                self.logger.exception(err)
                return 0
            if zerovm_stderr:
                self.logger.warning('zerovm stderr: '+zerovm_stderr)
            report = zerovm_stdout.splitlines()
            if len(report) < 5:
                return 0
            else:
                metadata = file.metadata
                metadata['Validation-Status'] = report[0]
                write_metadata(file.data_file, metadata)
                return int(report[0])

    def get_validation_status(self, req):
        try:
            (device, partition, account, container, obj) =\
            split_path(unquote(req.path), 5, 5, True)
        except ValueError:
            return 0
        if self.app.mount_check and not check_mount(self.app.devices, device):
            return 0
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
        metadata = read_metadata(file.data_file)
        status = int(metadata.get('Validation-Status', '0'))
        return status


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def obj_query_filter(app):
        return ObjectQueryMiddleware(app, conf)
    return obj_query_filter
