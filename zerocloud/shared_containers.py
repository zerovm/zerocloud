"""
``shared_containers`` middleware implements Swift proxy/container/object server functions
needed for proper Zerocloud shared container support

Implemented features are:
- shared folder add, loads shared folder data into account metadata
- shared folder remove, drops shared folder from account metadata

"""

from liteauth.liteauth import retrieve_metadata, store_metadata
from swift.common.swob import wsgify, HTTPNotFound, HTTPBadRequest, HTTPUnauthorized, Response


class SharedContainersMiddleware(object):
    def __init__(self, app, conf, *args, **kwargs):
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
        if version in (self.shared_container_add, self.shared_container_remove):
            if container:
                return self.handle_shared(version, request.remote_user, account, container)
            return HTTPBadRequest(body='Cannot parse url path %s%s'
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


def filter_factory(global_conf, **local_conf):
    """Returns a WSGI filter app for use with paste.deploy."""
    conf = global_conf.copy()
    conf.update(local_conf)

    def shared_containers_filter(app):
        return SharedContainersMiddleware(app, conf)

    return shared_containers_filter