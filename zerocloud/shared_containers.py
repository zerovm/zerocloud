"""
``shared_containers`` middleware implements Swift proxy/container/object server functions
needed for proper Zerocloud shared container support

Implemented features are:
- shared folder add, loads shared folder data into account metadata
- shared folder remove, drops shared folder from account metadata

"""
from urllib import unquote

from liteauth.liteauth import retrieve_metadata, store_metadata, get_account_from_whitelist
from swift.common.swob import wsgify, HTTPNotFound, HTTPBadRequest, HTTPUnauthorized, Response
from swift.common.utils import get_logger


class SharedContainersMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
        self.app = app
        self.shared_container_add = 'load-share'
        self.shared_container_remove = 'drop-share'
        self.version = 'v1'
        self.google_prefix = 'g_'
        # url for whitelist objects
        # Example: /v1/liteauth/whitelist
        self.whitelist_url = conf.get('whitelist_url', '').lower().rstrip('/')
        self.logger = get_logger(conf, log_route='lite-auth')

    @wsgify
    def __call__(self, request):
        try:
            (version, account, container, obj) = request.split_path(2, 4, True)
        except ValueError:
            return self.app
        if version in (self.shared_container_add, self.shared_container_remove):
            if container:
                return self.handle_shared(version, request.remote_user, account, container, request.environ)
            return HTTPBadRequest(body='Cannot parse url path %s%s'
                                       % (request.environ.get('SCRIPT_NAME', ''),
                                          request.environ['PATH_INFO']))
        return self.app

    def handle_shared(self, version, account, shared_account, shared_container, env):
        if not account:
            return HTTPUnauthorized()
        email = 'shared'
        if self.whitelist_url:
            acc_id = get_account_from_whitelist(self.whitelist_url, self.app, unquote(shared_account), self.logger, env)
            if acc_id and acc_id.startswith(self.google_prefix):
                email = unquote(shared_account)
                shared_account = acc_id
        shared = retrieve_metadata(self.app, self.version, account, 'shared', env)
        if not shared:
            shared = {}
        if version in self.shared_container_add:
            shared['%s/%s' % (shared_account, shared_container)] = email
        elif version in self.shared_container_remove:
            try:
                del shared['%s/%s' % (shared_account, shared_container)]
            except KeyError:
                return HTTPNotFound(body='Could not remove shared container %s/%s'
                                         % (shared_account, shared_container))
        if store_metadata(self.app, self.version, account, 'shared', shared, env):
            return Response(body='Successfully handled shared container %s/%s'
                                 % (shared_account, shared_container))
        return HTTPNotFound(body='Could not handle shared container %s/%s'
                                 % (shared_account, shared_container))


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def shared_containers_filter(app):
        return SharedContainersMiddleware(app, conf)

    return shared_containers_filter