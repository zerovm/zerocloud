from copy import deepcopy
import re
from hashlib import md5
from swift.common.constraints import MAX_META_NAME_LENGTH, \
    MAX_META_VALUE_LENGTH, MAX_META_COUNT, MAX_META_OVERALL_SIZE
from swift.common.swob import Response
from swift.common.utils import split_path, readconf

try:
    import simplejson as json
except ImportError:
    import json

ACCESS_READABLE = 0x1
ACCESS_WRITABLE = 0x1 << 1
ACCESS_RANDOM = 0x1 << 2
ACCESS_NETWORK = 0x1 << 3
ACCESS_CDR = 0x1 << 4
ACCESS_CHECKPOINT = 0x1 << 5

DEVICE_MAP = {
    'stdin': ACCESS_READABLE,
    'stdout': ACCESS_WRITABLE,
    'stderr': ACCESS_WRITABLE,
    'input': ACCESS_RANDOM | ACCESS_READABLE,
    'output': ACCESS_RANDOM | ACCESS_WRITABLE,
    'debug': ACCESS_NETWORK,
    'image': ACCESS_CDR,
    'db': ACCESS_CHECKPOINT
}

TAR_MIMES = ['application/x-tar', 'application/x-gtar', 'application/x-ustar']
CLUSTER_CONFIG_FILENAME = 'boot/cluster.map'
NODE_CONFIG_FILENAME = 'boot/system.map'
STREAM_CACHE_SIZE = 128 * 1024

DEFAULT_EXE_SYSTEM_MAP = r'''
    [{
        "name": "executable",
        "exec": {
            "path": "{.object_path}",
            "args": "{.args}"
        },
        "file_list": [
            {
                "device": "stdout",
                "content_type": "{.content_type=text/plain}"
            }
        ]
    }]
    '''

POST_TEXT_ACCOUNT_SYSTEM_MAP = r'''
    [{
        "name": "script",
        "exec": {
            "path": "{.exe_path}",
            "args": "{.args}script"
        },
        "file_list": [
            {
                "device": "stdout",
                "content_type": "text/plain"
            }
        ]
    }]
'''

POST_TEXT_OBJECT_SYSTEM_MAP = r'''
    [{
        "name": "script",
        "exec": {
            "path": "{.exe_path}",
            "args": "{.args}script"
        },
        "file_list": [
            {
                "device": "stdin",
                "path": {.object_path}
            },
            {
                "device": "stdout",
                "content_type": "text/plain"
            }
        ]
    }]
'''

ACCOUNT_HOME_PATH = ['.', '~']

MD5HASH_LENGTH = len(md5('').hexdigest())
REPORT_LENGTH = 6
REPORT_VALIDATOR = 0
REPORT_DAEMON = 1
REPORT_RETCODE = 2
REPORT_ETAG = 3
REPORT_CDR = 4
REPORT_STATUS = 5

RE_ILLEGAL = u'([\u0000-\u0008\u000b-\u000c\u000e-\u001f\ufffe-\uffff])' + \
             u'|' + \
             u'([%s-%s][^%s-%s])|([^%s-%s][%s-%s])|([%s-%s]$)|(^[%s-%s])' % \
             (unichr(0xd800), unichr(0xdbff), unichr(0xdc00), unichr(0xdfff),
              unichr(0xd800), unichr(0xdbff), unichr(0xdc00), unichr(0xdfff),
              unichr(0xd800), unichr(0xdbff), unichr(0xdc00), unichr(0xdfff),)


def merge_headers(current, new):
    if hasattr(new, 'keys'):
        for key in new.keys():
            if not current[key.lower()]:
                current[key.lower()] = str(new[key])
            else:
                current[key.lower()] += ',' + str(new[key])
    else:
        for key, value in new:
            if not current[key.lower()]:
                current[key.lower()] = str(value)
            else:
                current[key.lower()] += ',' + str(value)


def has_control_chars(line):
    if line:
        if re.search(RE_ILLEGAL, line):
            return True
        if re.search(r"[\x01-\x1F\x7F]", line):
            return True
    return False


def update_metadata(request, meta_data):
    if not meta_data:
        return None
    meta_count = 0
    meta_size = 0
    for key, value in meta_data.iteritems():
        meta_count += 1
        meta_size += len(key) + len(value)
        if len(key) > MAX_META_NAME_LENGTH:
            return 'Metadata name too long; max %d' % MAX_META_NAME_LENGTH
        elif len(value) > MAX_META_VALUE_LENGTH:
            return 'Metadata value too long; max %d' % MAX_META_VALUE_LENGTH
        elif meta_count > MAX_META_COUNT:
            return 'Too many metadata items; max %d' % MAX_META_COUNT
        elif meta_size > MAX_META_OVERALL_SIZE:
            return 'Total metadata too large; max %d' % MAX_META_OVERALL_SIZE
        request.headers['x-object-meta-%s' % key] = value


def can_run_as_daemon(node_conf, daemon_conf):
    if node_conf.exe != daemon_conf.exe:
        return False
    if not node_conf.channels:
        return False
    if len(node_conf.channels) != len(daemon_conf.channels):
        return False
    if node_conf.connect or node_conf.bind:
        return False
    channels = sorted(node_conf.channels, key=lambda ch: ch.device)
    for n, d in zip(channels, daemon_conf.channels):
        if n.device not in d.device:
            return False
    return True


def expand_account_path(account_name, path):
    if path.account in ACCOUNT_HOME_PATH:
        return SwiftPath.init(account_name,
                              path.container,
                              path.obj)
    return path


class ObjPath:

    def __init__(self, url, path):
        self.url = url
        self.path = path

    def __eq__(self, other):
        if not isinstance(other, ObjPath):
            return False
        if self.url == other.url:
            return True
        return False

    def __ne__(self, other):
        if not isinstance(other, ObjPath):
            return True
        if self.url != other.url:
            return True
        return False


class SwiftPath(ObjPath):

    def __init__(self, url):
        (_junk, path) = url.split('swift:/')
        ObjPath.__init__(self, url, path)
        (account, container, obj) = split_path(path, 1, 3, True)
        self.account = account
        self.container = container
        self.obj = obj

    @classmethod
    def init(cls, account, container, obj):
        if not account:
            return None
        return cls('swift://' +
                   '/'.join(filter(None,
                                   (account, container, obj))))


class ImagePath(ObjPath):

    def __init__(self, url):
        (_junk, path) = url.split('file://')
        ObjPath.__init__(self, url, path)
        parts = path.split(':', 1)
        if len(parts) > 1:
            self.image = parts[0]
            self.path = parts[1]
        else:
            self.image = 'image'


class ZvmPath(ObjPath):

    def __init__(self, url):
        (_junk, path) = url.split('zvm://')
        ObjPath.__init__(self, url, path)
        (host, device) = path.split(':', 1)
        self.host = host
        if device.startswith('/dev/'):
            self.device = device
        else:
            self.device = '/dev/%s' % device


class CachePath(ObjPath):

    def __init__(self, url):
        (_junk, path) = url.split('cache:/')
        ObjPath.__init__(self, url, path)
        (etag, account, container, obj) = split_path(path, 1, 4, True)
        self.etag = etag
        self.account = account
        self.container = container
        self.obj = obj
        self.path = '/%s/%s/%s' % (account, container, obj)


class NetPath(ObjPath):

    def __init__(self, url):
        (proto, path) = url.split('://')
        ObjPath.__init__(self, url, '%s:%s' % (proto, path))


def parse_location(url):
    if not url:
        return None
    if url.startswith('swift://'):
        return SwiftPath(url)
    elif url.startswith('file://'):
        return ImagePath(url)
    elif url.startswith('zvm://'):
        return ZvmPath(url)
    elif url.startswith('cache://'):
        return CachePath(url)
    elif url.startswith('tcp://') or url.startswith('udp://'):
        return NetPath(url)
    return None


def is_swift_path(location):
    if isinstance(location, SwiftPath):
        return True
    return False


def is_zvm_path(location):
    if isinstance(location, ZvmPath):
        return True
    return False


def is_image_path(location):
    if isinstance(location, ImagePath):
        return True
    return False


def is_cache_path(location):
    if isinstance(location, CachePath):
        return True
    return False


class ZvmNode(object):
    def __init__(self, id=None, name=None, exe=None, args=None, env=None,
                 replicate=1, attach=None):
        self.id = id
        self.name = name
        self.exe = exe
        self.args = args
        self.env = env
        self.replicate = replicate
        self.channels = []
        self.connect = []
        self.bind = []
        self.replicas = []
        self.skip_validation = False
        self.wildcards = None
        self.attach = attach
        self.access = ''

    def copy(self, id, name=None):
        newnode = deepcopy(self)
        newnode.id = id
        if name:
            newnode.name = name
        return newnode

    def add_channel(self, path=None,
                    content_type=None, channel=None):
        channel = deepcopy(channel)
        if path:
            channel.path = path
        if content_type:
            channel.content_type = content_type
        self.channels.append(channel)

    def add_new_channel(self, device=None, access=None, path=None,
                        content_type='application/octet-stream',
                        meta_data=None, mode=None, removable='no',
                        mountpoint='/'):
        channel = ZvmChannel(device, access, path,
                             content_type=content_type,
                             meta_data=meta_data, mode=mode,
                             removable=removable, mountpoint=mountpoint)
        self.channels.append(channel)

    def get_channel(self, device=None, path=None):
        if device:
            for chan in self.channels:
                if chan.device == device:
                    return chan
        if path:
            for chan in self.channels:
                if chan.path == path:
                    return chan
        return None

    def copy_cgi_env(self, request):
        if not self.env:
            self.env = {}
        self.env['HTTP_HOST'] = request.host
        self.env['REMOTE_ADDR'] = request.remote_addr
        self.env['REMOTE_USER'] = request.remote_user
        self.env['HTTP_USER_AGENT'] = request.user_agent
        self.env['QUERY_STRING'] = request.query_string
        self.env['SERVER_NAME'] = \
            request.environ.get('SERVER_NAME', 'localhost')
        self.env['SERVER_PORT'] = request.environ.get('SERVER_PORT', '80')
        self.env['SERVER_PROTOCOL'] = \
            request.environ.get('SERVER_PROTOCOL', 'HTTP/1.0')
        self.env['SERVER_SOFTWARE'] = 'zerocloud'
        self.env['GATEWAY_INTERFACE'] = 'CGI/1.1'
        self.env['SCRIPT_NAME'] = self.exe
        self.env['PATH_INFO'] = request.path_info
        self.env['REQUEST_METHOD'] = 'GET'
        self.env['HTTP_REFERER'] = request.referer
        self.env['HTTP_ACCEPT'] = request.headers.get('accept')
        self.env['HTTP_ACCEPT_ENCODING'] = \
            request.headers.get('accept-encoding')
        self.env['HTTP_ACCEPT_LANGUAGE'] = \
            request.headers.get('accept-language')

    def create_sysmap_resp(self):
        sysmap = self.dumps()
        # print self.dumps(indent=2)
        sysmap_iter = iter([sysmap])
        return Response(app_iter=sysmap_iter,
                        headers={'Content-Length': str(len(sysmap))})

    def add_data_source(self, data_sources, resp, dev='sysmap', append=False):
        if append:
            data_sources.append(resp)
        else:
            data_sources.insert(0, resp)
        if not getattr(self, 'last_data', None) or append:
            self.last_data = resp
        resp.nodes = [{'node': self, 'dev': dev}]

    def store_wildcards(self, path, mask):
        new_match = mask.match(path.path)
        self.wildcards = map(lambda idx: new_match.group(idx),
                             range(1, new_match.lastindex + 1))

    def dumps(self, indent=None):
        return json.dumps(self, cls=NodeEncoder, indent=indent)


class ZvmChannel(object):
    def __init__(self, device, access, path=None,
                 content_type=None, meta_data=None,
                 mode=None, removable='no', mountpoint='/'):
        self.device = device
        self.access = access
        self.path = path
        self.content_type = content_type
        self.meta = meta_data if meta_data else {}
        self.mode = mode
        self.removable = removable
        self.mountpoint = mountpoint


class NodeEncoder(json.JSONEncoder):

    def default(self, o):
        if isinstance(o, ZvmNode) or isinstance(o, ZvmChannel):
            return o.__dict__
        elif isinstance(o, Response):
            return str(o.__dict__)
        if isinstance(o, ObjPath):
            return o.url
        return json.JSONEncoder.default(self, o)


def load_server_conf(conf, sections):
    server_conf_file = conf.get('__file__', None)
    if server_conf_file:
        server_conf = readconf(server_conf_file)
        for sect in sections:
            if server_conf.get(sect, None):
                conf.update(server_conf[sect])
