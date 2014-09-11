from eventlet import Timeout
from time import time
import uuid

from swift.common.exceptions import ListingIterNotFound
from swift.common.exceptions import ListingIterError
from swift.common.http import HTTP_NOT_FOUND
from swift.common.http import is_success
from swift.common.swob import wsgify
from swift.common.swob import HTTPNotFound
from swift.common.swob import HTTPRequestEntityTooLarge
from swift.common.swob import HTTPException
from swift.common.swob import HTTPServerError
from swift.common.swob import HTTPUnprocessableEntity
from swift.common.swob import HTTPPreconditionFailed
from swift.common.swob import Response
from swift.common.swob import HTTPNoContent
from swift.common.swob import HTTPCreated
from swift.common.utils import get_logger
from swift.common.utils import split_path
from swift.common.utils import json
from swift.common.utils import normalize_timestamp
from swift.common.utils import readconf
from swift.common.wsgi import make_subrequest
from swiftclient.utils import TRUE_VALUES


QUEUE_ENDPOINT = 'queue'


def _create_message(msg_path, msg_id, orig_id, data):
    msg = {
        'claim_id': msg_path,
        'msg_id': msg_id,
        'client_id': orig_id,
        'data': data
    }
    return msg


def load_server_conf(conf, sections):
    server_conf_file = conf.get('__file__', None)
    if server_conf_file:
        server_conf = readconf(server_conf_file)
        for sect in sections:
            if server_conf.get(sect, None):
                conf.update(server_conf[sect])


class QueueMiddleware(object):
    def __init__(self, app, conf, logger=None,
                 object_ring=None, container_ring=None):
        self.app = app
        if logger:
            self.logger = logger
        else:
            self.logger = get_logger(conf, log_route='zqueue')
        # let's load appropriate server config sections here
        load_server_conf(conf, ['app:proxy-server'])
        self.network_chunk_size = int(conf.get('network_chunk_size',
                                               65536))
        self.max_message_size = int(conf.get('max_message_size', 65536))
        self.max_message_ttl = int(conf.get('max_message_ttl', 3600))
        self.swift_version = 'v1'
        self.listing_limit = int(conf.get('max_message_listing_limit', 1000))
        self.claim_limit = int(conf.get('max_claim_limit', 10))
        self.max_claim_ttl = int(conf.get('max_claim_ttl', 60))
        self.queue_prefix = '.queue_'
        self.storage_policy = conf.get('queue_storage_policy')

    def list_queues(self, account, req):
        """
        List all queues for account

        GET /queue/<account>

        """
        path = '/%s/%s' % (self.swift_version, account)
        queues = {}
        for item in self.list_iterator(req, path, self.queue_prefix):
            name = item['name'][len(self.queue_prefix):]
            queues[name] = {'message_count': item['count']}
        return Response(body=json.dumps(queues))

    def create_queue(self, account, queue_name, req):
        """
        Create a new queue in account

        PUT /queue/<account>/<queue_name>

        Has no effect if queue already exists
        """
        path = self.queue_path(account, queue_name)
        put_req = make_subrequest(req.environ, method='PUT',
                                  path=path, swift_source='queue')
        if self.storage_policy:
            put_req.headers['X-Storage-Policy'] = self.storage_policy
        put_resp = put_req.get_response(self.app)
        if not is_success(put_resp.status_int):
            put_resp.body = 'Failed to create queue %s' % queue_name
            put_resp.content_type = 'text/plain'
            return put_resp
        return put_resp

    def delete_queue(self, account, queue_name, req):
        """
        Delete queue in account

        DELETE /queue/<account>/<queue_name>?force=true

        """
        # TODO: add ability to purge even non-empty queue (with `force`)
        # force = req.params.get('force', 'f').lower() in TRUE_VALUES
        path = self.queue_path(account, queue_name)
        del_req = make_subrequest(req.environ, method='DELETE',
                                  path=path, swift_source='queue')
        del_resp = del_req.get_response(self.app)
        if not is_success(del_resp.status_int):
            del_resp.body = 'Failed to delete queue %s' % queue_name
            del_resp.content_type = 'text/plain'
            return del_resp
        return del_resp

    def list_messages(self, account, queue_name, req):
        """
        List messages in the queue

        GET /queue/<account>/<queue_name>/message?limit=<>&echo=false

        header: `Client-Id` - unique client ID string,
                clients should persist it somewhere, optional header
        limit - max length of the returned message list, default 1
        echo - if `True` echo display messages put by the `Client-ID`,
                default `False`
        returns JSON response:
            [
                {
                    "claim_id": <claim id>,
                    "msg_id": <message id>,
                    "client_id": <original creator id>,
                    "data": <message data>
                },
                ......
            ]
        """
        req = self.verify_message_query_params(req)
        client_id = req.headers.get('client-id', '')
        msg_list = self._list_messages(client_id, account, queue_name, req)
        return Response(body=json.dumps(msg_list))

    def put_message(self, account, queue_name, req):
        """
        Add a new message to the queue

        POST /queue/<account>/<queue_name>/message?ttl=<>

        header: Client-Id` - unique client ID string,
                clients should persist it somewhere, required header
        ttl - message time-to-live in seconds,
              will be capped at `max_message_ttl`
        request body: message data, serialized to JSON
        returns JSON response:
            {
                "claim_id": <client id>,
                "msg_id": <message id>,
                "client_id": <client id>,
                "data": <message data>
            }
        """
        client_id = req.headers.get('client-id')
        if not client_id:
            return HTTPPreconditionFailed(request=req,
                                          body='Client-Id header missing',
                                          content_type='text/plain')
        data = self._read_body(req)
        try:
            data = json.loads(data)
        except ValueError:
            return HTTPUnprocessableEntity(
                request=req,
                body='Could not load message content as JSON',
                content_type='text/plain')
        req = self.verify_message_query_params(req)
        msg_id = uuid.uuid4().hex[:16]
        now = normalize_timestamp(time())
        queue_path = self.queue_path(account, queue_name)
        msg_path = '%s/%s/%s/%s' % (now, msg_id, client_id, client_id)
        path = '%s/%s' % (queue_path, msg_path)
        put_req = make_subrequest(req.environ, method='PUT',
                                  path=path, swift_source='queue')
        put_req.headers['content-type'] = \
            json.dumps(data)
        put_req.headers['x-delete-at'] = int(time() + req.params['ttl'])
        put_req.content_length = 0
        put_resp = put_req.get_response(self.app)
        if not is_success(put_resp.status_int):
            put_resp.body = 'Failed to put message into %s' % queue_name
            put_resp.content_type = 'text/plain'
            return put_resp
        msg = _create_message(msg_path, msg_id, client_id, data)
        return HTTPCreated(request=req, body=json.dumps(msg),
                           content_type='application/json')

    def delete_message(self, account, queue_name, claim_id, req):
        """
        Delete message from queue

        DELETE /queue/<account>/<queue_name>/message/<claim_id>

        """
        queue_path = self.queue_path(account, queue_name)
        path = '%s/%s' % (queue_path, claim_id)
        del_req = make_subrequest(req.environ, method='DELETE',
                                  path=path, swift_source='queue')
        del_resp = del_req.get_response(self.app)
        if not is_success(del_resp.status_int):
            del_resp.body = 'Failed to delete message %s from %s' \
                            % (claim_id, queue_name)
            del_resp.content_type = 'text/plain'
        return del_resp

    def claim_messages(self, account, queue_name, req):
        """
        Claim message(s)

        POST /queue/<account>/<queue_name>/claim?limit=<>&ttl=<>&echo=false

        header: Client-Id` - unique client ID string,
                clients should persist it somewhere, required header
        ttl - claim time-to-live in seconds,
              will be capped at `max_message_ttl`
        limit - claim multiple messages if set, default 1
        echo - if `True` claim messages put by the `Client-ID`,
                default `False`

        No other clients will be able to claim message(s) for the ttl duration
        Will also be removed from the `list_message` list for the ttl duration
        May return less than `limit` messages, even if there are
            more messages in queue

        returns JSON response:
            [
                {
                    "claim_id": <new claim id>,
                    "msg_id": <message id>,
                    "client_id": <original creator id>,
                    "data": <message data>
                },
                ......
            ]
        """
        client_id = req.headers.get('client-id')
        if not client_id:
            return HTTPPreconditionFailed(request=req,
                                          body='Client-Id header missing',
                                          content_type='text/plain')
        req = self.verify_claim_query_params(req)
        msg_list = self._list_messages(client_id, account, queue_name, req)
        queue_path = self.queue_path(account, queue_name)
        claimed_list = []
        for msg in msg_list:
            claimed_msg = self._claim_message(
                client_id, msg, msg['claim_id'],
                queue_path, req)
            claimed_list.append(claimed_msg)
        return Response(request=req, body=json.dumps(claimed_list),
                        content_type='application/json')

    def update_claim(self, account, queue_name, claim_id, req):
        """
        Update ttl for an existing claim

        POST /queue/<account>/<queue_name>/claim/<claim_id>?ttl=<>

        header: Client-Id` - unique client ID string,
                clients should persist it somewhere, required header
        ttl - claim time-to-live in seconds,
              will be capped at `max_message_ttl`

        Message id will change when claim is updated
        Will not update claim if was originally claimed by different client

        returns JSON response:
            {
                "claim_id": <new claim id>,
                "msg_id": <message id>,
                "client_id": <original creator id>,
                "data": <message data>
            }
        """
        client_id = req.headers.get('client-id')
        if not client_id:
            return HTTPPreconditionFailed(
                request=req,
                body='Client-Id header missing',
                content_type='text/plain')
        if not claim_id.endswith('/' + client_id):
            return HTTPPreconditionFailed(
                request=req,
                body='Client-Id does not match claim id',
                content_type='text/plain')
        req = self.verify_claim_query_params(req)
        msg = self._get_message(account, queue_name, claim_id, req)
        if not msg:
            return HTTPNotFound(request=req)
        queue_path = self.queue_path(account, queue_name)
        claimed_msg = self._claim_message(client_id, msg, claim_id,
                                          queue_path, req)
        if not claimed_msg:
            return HTTPNotFound(request=req)
        return Response(request=req, body=json.dumps(claimed_msg),
                        content_type='application/json')

    def remove_claim(self, account, queue_name, msg_id, req):
        """
        Delete existing claim

        DELETE /queue/<account>/<queue_name>/claim/<msg_id>

        header: Client-Id` - unique client ID string,
                clients should persist it somewhere, required header

        Message id will change when claim is updated
        Will not update claim if was originally claimed by different client
        Deleting claim, is actually akin to resetting its ttl to 0,
            i.e. making it immediately available to other clients
        """
        req.params['ttl'] = 0
        resp = self.update_claim(account, queue_name, msg_id, req)
        if not is_success(resp.status_int):
            return resp
        return HTTPNoContent(request=req)

    @wsgify
    def __call__(self, req):
        try:
            version, account, queue, _rest = split_path(req.path, 1, 4, True)
        except ValueError:
            return self.app
        try:
            if version == QUEUE_ENDPOINT:
                if not account:
                    return HTTPPreconditionFailed(request=req)
                if req.method == 'GET':
                    if not queue:
                        return self.list_queues(account, req)
                    if queue and _rest == 'message':
                        return self.list_messages(account, queue, req)
                elif req.method == 'PUT':
                    if queue and not _rest:
                        return self.create_queue(account, queue, req)
                elif req.method == 'POST':
                    if not queue and not _rest:
                        return HTTPUnprocessableEntity(request=req)
                    if queue and _rest == 'message':
                        return self.put_message(account, queue, req)
                    if queue and _rest == 'claim':
                        return self.claim_messages(account, queue, req)
                    if queue and _rest.startswith('claim/'):
                        msg_id = _rest[len('claim/'):]
                        return self.update_claim(account, queue,
                                                 msg_id, req)
                elif req.method == 'DELETE':
                    if account and queue:
                        if not _rest:
                            return self.delete_queue(account, queue, req)
                        if _rest.startswith('message/'):
                            msg_id = _rest[len('message/'):]
                            return self.delete_message(account, queue,
                                                       msg_id, req)
                        if _rest.startswith('claim/'):
                            msg_id = _rest[len('claim/'):]
                            return self.remove_claim(account, queue,
                                                     msg_id, req)
                return HTTPUnprocessableEntity(request=req)
        except HTTPException as error_response:
            return error_response
        except ListingIterNotFound:
            return HTTPNotFound(request=req)
        except (Exception, Timeout):
            self.logger.exception('ERROR Unhandled exception in request')
            return HTTPServerError(request=req)
        return self.app

    def _read_body(self, req):
        body = ''
        reader = iter(lambda: req.body_file.read(self.network_chunk_size), '')
        bytes_transferred = 0
        for chunk in reader:
            bytes_transferred += len(chunk)
            if bytes_transferred > self.max_message_size:
                raise HTTPRequestEntityTooLarge(request=req)
            body += chunk
        return body

    def list_iterator(self, request, path, prefix, end_marker=''):
        for page in self.listing_page_iter(request, path, prefix, end_marker):
            for item in page:
                yield item

    def listing_page_iter(self, request, path, prefix, end_marker):
        marker = ''
        while True:
            list_req = make_subrequest(request.environ, method='GET',
                                       path=path, swift_source='queue')
            list_req.query_string = \
                'format=json&limit=%d&prefix=%s&marker=%s&end_marker=%s' \
                % (self.listing_limit, prefix, marker, end_marker)
            list_resp = list_req.get_response(self.app)
            if list_resp.status_int == HTTP_NOT_FOUND:
                raise ListingIterNotFound()
            elif not is_success(list_resp.status_int):
                raise ListingIterError()
            if not list_resp.body:
                break
            sublisting = json.loads(list_resp.body)
            if not sublisting:
                break
            marker = sublisting[-1]['name'].encode('utf-8')
            yield sublisting
            if len(sublisting) < self.listing_limit:
                break

    def _list_messages(self, client_id, account, queue_name, req):
        path = self.queue_path(account, queue_name)
        now = time()
        end_marker = normalize_timestamp(now)
        msg_list = []
        length = 0
        for item in self.list_iterator(req, path, '', end_marker=end_marker):
            _ts, msg_id, orig_id, _claim_id = \
                split_path('/' + item['name'], 4, 4)
            if not req.params['echo'] and orig_id == client_id:
                continue
            data = json.loads(item['content_type'])
            msg = _create_message(item['name'], msg_id, orig_id, data)
            msg_list.append(msg)
            length += 1
            if length >= req.params['limit']:
                break
        return msg_list

    def _get_message(self, account, queue_name, msg_path, req):
        path = self.queue_path(account, queue_name)
        for item in self.list_iterator(req, path, msg_path, end_marker=''):
            _ts, msg_id, orig_id, _claim_id = \
                split_path('/' + item['name'], 4, 4)
            data = json.loads(item['content_type'])
            msg = _create_message(item['name'], msg_id, orig_id, data)
            return msg
        return None

    def _claim_message(self, client_id, msg, msg_path, queue_path, req):
        del_path = '%s/%s' % (queue_path, msg_path)
        del_req = make_subrequest(req.environ, method='DELETE',
                                  path=del_path, swift_source='queue')
        timestamp = normalize_timestamp(time() + req.params['ttl'])
        _ts, msg_id, orig_id, _claim_id = split_path('/' + msg_path, 4, 4)
        msg_path = '%s/%s/%s/%s' % (timestamp, msg_id, orig_id, client_id)
        put_path = '%s/%s' % (queue_path, msg_path)
        put_req = make_subrequest(req.environ, method='PUT',
                                  path=put_path, swift_source='queue')
        msg['claim_id'] = msg_path
        put_req.headers['content-type'] = \
            json.dumps(msg['data'])
        put_req.content_length = 0
        resp = del_req.get_response(self.app)
        if not is_success(resp.status_int):
            # we could not claim that one
            # need to be faster next time :)
            return None
        resp = put_req.get_response(self.app)
        if not is_success(resp.status_int):
            # something strange happened we should die here,
            # but let's return some clue to the user
            raise resp
        return msg

    def queue_path(self, account, queue_name):
        return '/%s/%s/%s%s' % (self.swift_version, account,
                                self.queue_prefix, queue_name)

    def verify_message_query_params(self, req):
        ttl = int(req.params.get('ttl', self.max_message_ttl))
        if ttl > self.max_message_ttl:
            ttl = self.max_message_ttl
        req.params['ttl'] = ttl
        limit = int(req.params.get('limit', 1))
        if limit > self.listing_limit:
            limit = self.listing_limit
        req.params['limit'] = limit
        req.params['echo'] = \
            req.params.get('echo', 'f').lower() in TRUE_VALUES
        return req

    def verify_claim_query_params(self, req):
        ttl = int(req.params.get('ttl', self.max_claim_ttl))
        if ttl > self.max_claim_ttl:
            ttl = self.max_claim_ttl
        req.params['ttl'] = ttl
        limit = int(req.params.get('limit', 1))
        if limit > self.claim_limit:
            limit = self.claim_limit
        req.params['limit'] = limit
        req.params['echo'] = \
            req.params.get('echo', 'f').lower() in TRUE_VALUES
        return req


def filter_factory(global_conf, **local_conf):
    """
    paste.deploy app factory for creating WSGI proxy apps.
    """
    conf = global_conf.copy()
    conf.update(local_conf)

    def query_filter(app):
        return QueueMiddleware(app, conf)

    return query_filter
