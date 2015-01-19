import re

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
    'db': ACCESS_CHECKPOINT,
    'script': ACCESS_RANDOM | ACCESS_READABLE,
}

CLUSTER_CONFIG_FILENAME = 'boot/cluster.map'
NODE_CONFIG_FILENAME = 'boot/system.map'
ACCOUNT_HOME_PATH = ['.', '~']

RE_ILLEGAL = u'([\u0000-\u0008\u000b-\u000c\u000e-\u001f\ufffe-\uffff])' + \
             u'|' + \
             u'([%s-%s][^%s-%s])|([^%s-%s][%s-%s])|([%s-%s]$)|(^[%s-%s])' % \
             (unichr(0xd800), unichr(0xdbff), unichr(0xdc00), unichr(0xdfff),
              unichr(0xd800), unichr(0xdbff), unichr(0xdc00), unichr(0xdfff),
              unichr(0xd800), unichr(0xdbff), unichr(0xdc00), unichr(0xdfff),)


def split_path(path, minsegs=1, maxsegs=None, rest_with_last=False):
    """
    Validate and split the given HTTP request path.

    **Examples**::

        ['a'] = split_path('/a')
        ['a', None] = split_path('/a', 1, 2)
        ['a', 'c'] = split_path('/a/c', 1, 2)
        ['a', 'c', 'o/r'] = split_path('/a/c/o/r', 1, 3, True)

    :param path: HTTP Request path to be split
    :param minsegs: Minimum number of segments to be extracted
    :param maxsegs: Maximum number of segments to be extracted
    :param rest_with_last: If True, trailing data will be returned as part
                           of last segment.  If False, and there is
                           trailing data, raises ValueError.
    :returns: list of segments with a length of maxsegs (non-existent
              segments will return as None)
    :raises: ValueError if given an invalid path
    """
    if not maxsegs:
        maxsegs = minsegs
    if minsegs > maxsegs:
        raise ValueError('minsegs > maxsegs: %d > %d' % (minsegs, maxsegs))
    if rest_with_last:
        segs = path.split('/', maxsegs)
        minsegs += 1
        maxsegs += 1
        count = len(segs)
        if (segs[0] or count < minsegs or count > maxsegs or
                '' in segs[1:minsegs]):
            raise ValueError('Invalid path: %s' % path)
    else:
        minsegs += 1
        maxsegs += 1
        segs = path.split('/', maxsegs)
        count = len(segs)
        if (segs[0] or count < minsegs or count > maxsegs + 1 or
                '' in segs[1:minsegs] or
                (count == maxsegs + 1 and segs[maxsegs])):
            raise ValueError('Invalid path: %s' % path)
    segs = segs[1:maxsegs]
    segs.extend([None] * (maxsegs - 1 - len(segs)))
    return segs


def has_control_chars(line):
    if line:
        if re.search(RE_ILLEGAL, line):
            return True
        if re.search(r"[\x01-\x1F\x7F]", line):
            return True
    return False


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


class ZvmChannel(object):
    def __init__(self, device, access, path=None,
                 content_type=None, meta_data=None,
                 mode=None, removable='no', mountpoint='/', min_size=0):
        self.device = device
        self.access = access
        self.path = path
        self.content_type = content_type
        self.meta = meta_data if meta_data else {}
        self.mode = mode
        self.removable = removable
        self.mountpoint = mountpoint
        self.min_size = min_size
