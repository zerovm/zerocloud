

"""
``shared_containers`` middleware implements Swift proxy/container/object server functions
needed for proper Zerocloud shared container support

Implemented features are:
- shared folder add, loads shared folder data into account metadata
- shared folder remove, drops shared folder from account metadata
- account <-> account x-copy headers, allows server-side object copy between different accounts

"""

from eventlet import GreenPile, Queue, Timeout
import mimetypes
from urllib import unquote, quote
import time
from liteauth.liteauth import retrieve_metadata, store_metadata
from swift.common.constraints import MAX_FILE_SIZE, check_object_creation
from swift.common.exceptions import ChunkReadTimeout
from swift.common.http import HTTP_NOT_FOUND, is_client_error, is_success, HTTP_MULTIPLE_CHOICES, \
    HTTP_INTERNAL_SERVER_ERROR, HTTP_SERVICE_UNAVAILABLE

from swift.common.swob import wsgify, HTTPNotFound, HTTPBadRequest, HTTPNotImplemented, \
    HTTPRequestEntityTooLarge, Request, HTTPAccepted, HTTPPreconditionFailed, \
    HTTPServiceUnavailable, HTTPRequestTimeout, HTTPClientDisconnect, HTTPServerError, Response, HTTPUnauthorized
from swift.common.utils import public, normalize_timestamp, GreenthreadSafeIterator, ContextPool, config_true_value
from swift.proxy.controllers.base import cors_validation, delay_denial
from swift.proxy.controllers.obj import check_content_type, copy_headers_into, ObjectController


class SharedContainersMiddleware(object):

    def __init__(self, app, *args, **kwargs):
        self.app = app
        self.shared_container_add = 'load-share'
        self.shared_container_remove = 'drop-share'
        self.version = 'v1'

    @wsgify
    def __call__(self, request):
        try:
            (version, account, container, obj) = request.split_path(2, 4, True)
        except ValueError:
            return self.app
        if version in self.version:
            src_path = request.headers.get('X-Copy-From-Account', None)
            if request.method == 'PUT' and src_path and container and obj:
                controller = SharedController(self.app, account, container, obj)
                return controller.PUT(request)
        elif version in (self.shared_container_add, self.shared_container_remove):
            if container:
                return self.handle_shared(version, request.remote_user, account, container)
            return HTTPBadRequest(body='Cannot parse url path %s/%s'
                                       % (request.environ.get('SCRIPT_NAME', ''),
                                          request.environ['PATH_INFO']))
        return self.app

    def handle_shared(self, version, account, shared_account, shared_container):
        if not account:
            return HTTPUnauthorized()
        shared = retrieve_metadata(self.app, self.version, account, 'shared')
        if not shared:
            shared = {}
        if version in self.shared_container_add:
            shared['%s/%s' % (shared_account, shared_container)] = 'shared'
        elif version in self.shared_container_remove:
            try:
                del shared['%s/%s' % (shared_account, shared_container)]
            except KeyError:
                return HTTPNotFound(body='Could not remove shared container %s/%s'
                                         % (shared_account, shared_container))
        if store_metadata(self.app, self.version, account, 'shared', shared):
            return Response(body='Successfully handled shared container %s/%s'
                                 % (shared_account, shared_container))
        return HTTPNotFound(body='Could not handle shared container %s/%s'
                                 % (shared_account, shared_container))


class SharedController(ObjectController):

    @public
    @cors_validation
    @delay_denial
    def PUT(self, req):
        """HTTP PUT request handler."""
        container_info = self.container_info(
            self.account_name, self.container_name, req)
        container_partition = container_info['partition']
        containers = container_info['nodes']
        req.acl = container_info['write_acl']
        req.environ['swift_sync_key'] = container_info['sync_key']
        object_versions = container_info['versions']
        if 'swift.authorize' in req.environ:
            aresp = req.environ['swift.authorize'](req)
            if aresp:
                return aresp
        if not containers:
            return HTTPNotFound(request=req)
        try:
            ml = req.message_length()
        except ValueError as e:
            return HTTPBadRequest(request=req, content_type='text/plain',
                                  body=str(e))
        except AttributeError as e:
            return HTTPNotImplemented(request=req, content_type='text/plain',
                                      body=str(e))
        if ml is not None and ml > MAX_FILE_SIZE:
            return HTTPRequestEntityTooLarge(request=req)
        if 'x-delete-after' in req.headers:
            try:
                x_delete_after = int(req.headers['x-delete-after'])
            except ValueError:
                    return HTTPBadRequest(request=req,
                                          content_type='text/plain',
                                          body='Non-integer X-Delete-After')
            req.headers['x-delete-at'] = '%d' % (time.time() + x_delete_after)
        partition, nodes = self.app.object_ring.get_nodes(
            self.account_name, self.container_name, self.object_name)
        # do a HEAD request for container sync and checking object versions
        if 'x-timestamp' in req.headers or \
                (object_versions and not
                 req.environ.get('swift_versioned_copy')):
            hreq = Request.blank(req.path_info, headers={'X-Newest': 'True'},
                                 environ={'REQUEST_METHOD': 'HEAD'})
            hresp = self.GETorHEAD_base(
                hreq, _('Object'), self.app.object_ring, partition,
                hreq.path_info)
        # Used by container sync feature
        if 'x-timestamp' in req.headers:
            try:
                req.headers['X-Timestamp'] = \
                    normalize_timestamp(float(req.headers['x-timestamp']))
                if hresp.environ and 'swift_x_timestamp' in hresp.environ and \
                    float(hresp.environ['swift_x_timestamp']) >= \
                        float(req.headers['x-timestamp']):
                    return HTTPAccepted(request=req)
            except ValueError:
                return HTTPBadRequest(
                    request=req, content_type='text/plain',
                    body='X-Timestamp should be a UNIX timestamp float value; '
                         'was %r' % req.headers['x-timestamp'])
        else:
            req.headers['X-Timestamp'] = normalize_timestamp(time.time())
        # Sometimes the 'content-type' header exists, but is set to None.
        content_type_manually_set = True
        if not req.headers.get('content-type'):
            guessed_type, _junk = mimetypes.guess_type(req.path_info)
            req.headers['Content-Type'] = guessed_type or \
                'application/octet-stream'
            content_type_manually_set = False
        error_response = check_object_creation(req, self.object_name) or \
            check_content_type(req)
        if error_response:
            return error_response
        if object_versions and not req.environ.get('swift_versioned_copy'):
            is_manifest = 'x-object-manifest' in req.headers or \
                          'x-object-manifest' in hresp.headers
            if hresp.status_int != HTTP_NOT_FOUND and not is_manifest:
                # This is a version manifest and needs to be handled
                # differently. First copy the existing data to a new object,
                # then write the data from this request to the version manifest
                # object.
                lcontainer = object_versions.split('/')[0]
                prefix_len = '%03x' % len(self.object_name)
                lprefix = prefix_len + self.object_name + '/'
                ts_source = hresp.environ.get('swift_x_timestamp')
                if ts_source is None:
                    ts_source = time.mktime(time.strptime(
                                            hresp.headers['last-modified'],
                                            '%a, %d %b %Y %H:%M:%S GMT'))
                new_ts = normalize_timestamp(ts_source)
                vers_obj_name = lprefix + new_ts
                copy_headers = {
                    'Destination': '%s/%s' % (lcontainer, vers_obj_name)}
                copy_environ = {'REQUEST_METHOD': 'COPY',
                                'swift_versioned_copy': True
                                }
                copy_req = Request.blank(req.path_info, headers=copy_headers,
                                         environ=copy_environ)
                copy_resp = self.COPY(copy_req)
                if is_client_error(copy_resp.status_int):
                    # missing container or bad permissions
                    return HTTPPreconditionFailed(request=req)
                elif not is_success(copy_resp.status_int):
                    # could not copy the data, bail
                    return HTTPServiceUnavailable(request=req)

        reader = req.environ['wsgi.input'].read
        data_source = iter(lambda: reader(self.app.client_chunk_size), '')
        source_header = req.headers.get('X-Copy-From-Account')
        source_resp = None
        if source_header:
            source_header = unquote(source_header)
            #acct = req.path_info.split('/', 2)[1]
            #if isinstance(acct, unicode):
            #    acct = acct.encode('utf-8')
            if not source_header.startswith('/'):
                source_header = '/' + source_header
            #source_header = '/' + acct + source_header
            try:
                src_account_name, src_container_name, src_obj_name = \
                    source_header.split('/', 3)[1:]
            except ValueError:
                return HTTPPreconditionFailed(
                    request=req,
                    body='X-Copy-From-Account header must be of the form'
                         '<account name>/<container name>/<object name>')
            source_req = req.copy_get()
            source_req.path_info = source_header
            source_req.headers['X-Newest'] = 'true'
            orig_obj_name = self.object_name
            orig_container_name = self.container_name
            orig_account_name = self.account_name
            self.object_name = src_obj_name
            self.container_name = src_container_name
            self.account_name = src_account_name
            source_resp = self.GET(source_req)
            if source_resp.status_int >= HTTP_MULTIPLE_CHOICES:
                return source_resp
            self.object_name = orig_obj_name
            self.container_name = orig_container_name
            self.account_name = orig_account_name
            new_req = Request.blank(req.path_info,
                                    environ=req.environ, headers=req.headers)
            data_source = source_resp.app_iter
            new_req.content_length = source_resp.content_length
            if new_req.content_length is None:
                # This indicates a transfer-encoding: chunked source object,
                # which currently only happens because there are more than
                # CONTAINER_LISTING_LIMIT segments in a segmented object. In
                # this case, we're going to refuse to do the server-side copy.
                return HTTPRequestEntityTooLarge(request=req)
            if new_req.content_length > MAX_FILE_SIZE:
                return HTTPRequestEntityTooLarge(request=req)
            new_req.etag = source_resp.etag
            # we no longer need the X-Copy-From-Account header
            del new_req.headers['X-Copy-From-Account']
            if not content_type_manually_set:
                new_req.headers['Content-Type'] = \
                    source_resp.headers['Content-Type']
            if not config_true_value(
                    new_req.headers.get('x-fresh-metadata', 'false')):
                copy_headers_into(source_resp, new_req)
                copy_headers_into(req, new_req)
            # copy over x-static-large-object for POSTs and manifest copies
            if 'X-Static-Large-Object' in source_resp.headers and \
                    req.params.get('multipart-manifest') == 'get':
                new_req.headers['X-Static-Large-Object'] = \
                    source_resp.headers['X-Static-Large-Object']

            req = new_req

        if 'x-delete-at' in req.headers:
            try:
                x_delete_at = int(req.headers['x-delete-at'])
                if x_delete_at < time.time():
                    return HTTPBadRequest(
                        body='X-Delete-At in past', request=req,
                        content_type='text/plain')
            except ValueError:
                return HTTPBadRequest(request=req, content_type='text/plain',
                                      body='Non-integer X-Delete-At')
            req.environ.setdefault('swift.log_info', []).append(
                'x-delete-at:%d' % x_delete_at)
            delete_at_container = str(
                x_delete_at /
                self.app.expiring_objects_container_divisor *
                self.app.expiring_objects_container_divisor)
            delete_at_part, delete_at_nodes = \
                self.app.container_ring.get_nodes(
                    self.app.expiring_objects_account, delete_at_container)
        else:
            delete_at_container = delete_at_part = delete_at_nodes = None

        node_iter = GreenthreadSafeIterator(
            self.iter_nodes_local_first(self.app.object_ring, partition))
        pile = GreenPile(len(nodes))
        te = req.headers.get('transfer-encoding', '')
        chunked = ('chunked' in te)

        outgoing_headers = self._backend_requests(
            req, len(nodes), container_partition, containers,
            delete_at_container, delete_at_part, delete_at_nodes)

        for nheaders in outgoing_headers:
            # RFC2616:8.2.3 disallows 100-continue without a body
            if (req.content_length > 0) or chunked:
                nheaders['Expect'] = '100-continue'
            pile.spawn(self._connect_put_node, node_iter, partition,
                       req.path_info, nheaders, self.app.logger.thread_locals)

        conns = [conn for conn in pile if conn]
        if len(conns) <= len(nodes) / 2:
            self.app.logger.error(
                _('Object PUT returning 503, %(conns)s/%(nodes)s '
                  'required connections'),
                {'conns': len(conns), 'nodes': len(nodes) // 2 + 1})
            return HTTPServiceUnavailable(request=req)
        bytes_transferred = 0
        try:
            with ContextPool(len(nodes)) as pool:
                for conn in conns:
                    conn.failed = False
                    conn.queue = Queue(self.app.put_queue_depth)
                    pool.spawn(self._send_file, conn, req.path)
                while True:
                    with ChunkReadTimeout(self.app.client_timeout):
                        try:
                            chunk = next(data_source)
                        except StopIteration:
                            if chunked:
                                [conn.queue.put('0\r\n\r\n') for conn in conns]
                            break
                    bytes_transferred += len(chunk)
                    if bytes_transferred > MAX_FILE_SIZE:
                        return HTTPRequestEntityTooLarge(request=req)
                    for conn in list(conns):
                        if not conn.failed:
                            conn.queue.put(
                                '%x\r\n%s\r\n' % (len(chunk), chunk)
                                if chunked else chunk)
                        else:
                            conns.remove(conn)
                    if len(conns) <= len(nodes) / 2:
                        self.app.logger.error(_(
                            'Object PUT exceptions during'
                            ' send, %(conns)s/%(nodes)s required connections'),
                            {'conns': len(conns), 'nodes': len(nodes) / 2 + 1})
                        return HTTPServiceUnavailable(request=req)
                for conn in conns:
                    if conn.queue.unfinished_tasks:
                        conn.queue.join()
            conns = [conn for conn in conns if not conn.failed]
        except ChunkReadTimeout, err:
            self.app.logger.warn(
                _('ERROR Client read timeout (%ss)'), err.seconds)
            self.app.logger.increment('client_timeouts')
            return HTTPRequestTimeout(request=req)
        except (Exception, Timeout):
            self.app.logger.exception(
                _('ERROR Exception causing client disconnect'))
            return HTTPClientDisconnect(request=req)
        if req.content_length and bytes_transferred < req.content_length:
            req.client_disconnect = True
            self.app.logger.warn(
                _('Client disconnected without sending enough data'))
            self.app.logger.increment('client_disconnects')
            return HTTPClientDisconnect(request=req)
        statuses = []
        reasons = []
        bodies = []
        etags = set()
        for conn in conns:
            try:
                with Timeout(self.app.node_timeout):
                    if conn.resp:
                        response = conn.resp
                    else:
                        response = conn.getresponse()
                    statuses.append(response.status)
                    reasons.append(response.reason)
                    bodies.append(response.read())
                    if response.status >= HTTP_INTERNAL_SERVER_ERROR:
                        self.error_occurred(
                            conn.node,
                            _('ERROR %(status)d %(body)s From Object Server '
                              're: %(path)s') %
                            {'status': response.status,
                             'body': bodies[-1][:1024], 'path': req.path})
                    elif is_success(response.status):
                        etags.add(response.getheader('etag').strip('"'))
            except (Exception, Timeout):
                self.exception_occurred(
                    conn.node, _('Object'),
                    _('Trying to get final status of PUT to %s') % req.path)
        if len(etags) > 1:
            self.app.logger.error(
                _('Object servers returned %s mismatched etags'), len(etags))
            return HTTPServerError(request=req)
        etag = etags.pop() if len(etags) else None
        while len(statuses) < len(nodes):
            statuses.append(HTTP_SERVICE_UNAVAILABLE)
            reasons.append('')
            bodies.append('')
        resp = self.best_response(req, statuses, reasons, bodies,
                                  _('Object PUT'), etag=etag)
        if source_header:
            resp.headers['X-Copied-From-Account'] = quote(
                source_header.split('/', 3)[3])
            if 'last-modified' in source_resp.headers:
                resp.headers['X-Copied-From-Last-Modified'] = \
                    source_resp.headers['last-modified']
            copy_headers_into(req, resp)
        resp.last_modified = float(req.headers['X-Timestamp'])
        return resp


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    def shared_containers_filter(app):
        return SharedContainersMiddleware(app)
    return shared_containers_filter