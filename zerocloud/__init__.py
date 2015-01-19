from hashlib import md5
from swift.common.utils import readconf


def load_server_conf(conf, sections):
    server_conf_file = conf.get('__file__', None)
    if server_conf_file:
        server_conf = readconf(server_conf_file)
        for sect in sections:
            if server_conf.get(sect, None):
                conf.update(server_conf[sect])

TAR_MIMES = ['application/x-tar', 'application/x-gtar', 'application/x-ustar',
             'application/x-gzip']
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

MD5HASH_LENGTH = len(md5('').hexdigest())
REPORT_LENGTH = 6
REPORT_VALIDATOR = 0
REPORT_DAEMON = 1
REPORT_RETCODE = 2
REPORT_ETAG = 3
REPORT_CDR = 4
REPORT_STATUS = 5

TIMEOUT_GRACE = 0.5


def merge_headers(final, mergeable, new):
    key_list = mergeable.keys()
    for key in key_list:
        mergeable[key] = new.get(key, mergeable[key])
        if not final.get(key):
            final[key] = str(mergeable[key])
        else:
            final[key] += ',' + str(mergeable[key])
    for key in new.keys():
        if key not in key_list:
            final[key] = new[key]


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
