from eventlet.green import os
from hashlib import md5
import socket
import struct
from sys import exit
import re
import cPickle as pickle
from time import sleep
from argparse import ArgumentParser
from eventlet import GreenPool, listen

try:
    import simplejson as json
except ImportError:
    import json


def errdump(zvm_errcode, nexe_validity, nexe_errcode, nexe_etag,
            nexe_accounting, status_line):
    print '%d\n0\n%d\n%s\n%s\n%s' % (nexe_validity,
                                     nexe_errcode,
                                     nexe_etag,
                                     ' '.join([str(val)
                                               for val in nexe_accounting]),
                                     status_line)
    exit(zvm_errcode)


def eval_as_function(code, local_vars=None, global_vars=None):
    if not global_vars:
        global_vars = globals()
    if not local_vars:
        local_vars = {}
    context = {}
    code = re.sub(r"(?m)^", "    ", code)
    code = "def anon(" + ','.join(local_vars.keys()) + "):\n" + code
    exec code in global_vars, context
    retval = context['anon'](*(local_vars.values()))
    return retval


parser = ArgumentParser()
parser.add_argument(dest='manifest')
parser.add_argument('-s', action='store_true', dest='skip')
parser.add_argument('-F', action='store_true', dest='validate')
args = parser.parse_args()

valid = 0
if args.skip:
    valid = 2
accounting = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
manifest = args.manifest
if not manifest:
    errdump(1, valid, 0, '', accounting, 'Manifest file required')
try:
    inputmnfst = file(manifest, 'r').read().splitlines()
except IOError:
    errdump(1, valid, 0, '', accounting, 'Cannot open manifest file: %s'
                                         % manifest)


def parse_manifest(inputmnfst):
    dl = re.compile("\s*=\s*")
    result = dict()
    for line in inputmnfst:
        (attr, val) = re.split(dl, line, 1)
        if attr and attr in result:
            result[attr] += ',' + val
        else:
            result[attr] = val
    return result

mnfst_dict = parse_manifest(inputmnfst)


class ZerovmDaemon:

    def __init__(self, socket_name):
        self.server_address = socket_name
        self.zerovm_exename = ['zerovm']
        self.pool = GreenPool()
        self.jobs = set()
        self.stats_dir = '/tmp'

    def parse_command(self, fd):
        try:
            size = int(fd.read(8), 0)
            data = fd.read(size)
            return data
        except IOError:
            return None

    def handle(self, fd):
        data = self.parse_command(fd)
        manifest = data
        report = self.execute(manifest)
        self.send_response(fd, report)

    def serve(self):
        try:
            os.remove(self.server_address)
        except OSError:
            pass
        server = listen(self.server_address, family=socket.AF_UNIX)
        while True:
            try:
                new_sock, address = server.accept()
                self.pool.spawn_n(self.handle, new_sock.makefile('rw'))
            except (SystemExit, KeyboardInterrupt):
                break

    def send_response(self, fd, report):
        data = '0x%06x%s' % (len(report), report)
        try:
            fd.write(data)
        except IOError:
            pass

    def execute(self, manifest):
        pass


class Mnfst:
    pass


mnfst = Mnfst()
index = 0
status = 'nexe did not run'
retcode = 0


def retrieve_mnfst_field(n, eq=None, min=None, max=None,
                         isint=False, optional=False):
    if n not in mnfst_dict:
        if optional:
            return
        errdump(1, valid, 0, '', accounting, 'Manifest key missing "%s"' % n)
    v = mnfst_dict[n]
    if isint:
        v = int(v)
        if min and v < min:
            errdump(1, valid, 0, '', accounting,
                    '%s = %d is less than expected: %d' % (n, v, min))
        if max and v > max:
            errdump(1, valid, 0, '', accounting,
                    '%s = %d is more than expected: %d' % (n, v, max))
    if eq and v != eq:
        errdump(1, valid, 0, '', accounting,
                '%s = %s and expected %s' % (n, v, eq))
    setattr(mnfst, n.strip(), v)


retrieve_mnfst_field('Version', '20130611')
retrieve_mnfst_field('Program')
retrieve_mnfst_field('Etag', optional=True)
retrieve_mnfst_field('Timeout', min=1, isint=True)
retrieve_mnfst_field('Memory')
retrieve_mnfst_field('Channel')
retrieve_mnfst_field('Node', optional=True, isint=True)
retrieve_mnfst_field('NameServer', optional=True)
retrieve_mnfst_field('Job', optional=True)
exe = file(mnfst.Program, 'r').read()
if 'INVALID' == exe:
    valid = 1
    retcode = 0
    errdump(8, valid, retcode, '', accounting, 'nexe is invalid')
if args.validate:
    errdump(0, valid, retcode, '', accounting, 'nexe is valid')
if not getattr(mnfst, 'Etag', None):
    mnfst.Etag = 'DISABLED'

channel_list = re.split('\s*,\s*', mnfst.Channel)
if len(channel_list) % 8 != 0:
    errdump(1, valid, 0, mnfst.Etag, accounting,
            'wrong channel config: %s' % mnfst.Channel)
dev_list = channel_list[1::8]
bind_data = ''
bind_count = 0
connect_data = ''
connect_count = 0
con_list = []
bind_map = {}
alias = int(mnfst.Node)
mnfst.channels = {}
stddev = {'/dev/stdin': 0, '/dev/stdout': 0, '/dev/stderr': 0}
for fname, device, type, tag, rd, rd_byte, wr, wr_byte \
        in zip(*[iter(channel_list)]*8):
    net_device = False
    if fname.startswith('tcp:'):
        net_device = True
        if ';' in fname:
            socks = fname.split(';')
        else:
            socks = [fname]
        for name in socks:
            proto, host, port = name.split(':')
            host = int(host)
            if int(rd) > 0:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.bind(('', 0))
                s.listen(1)
                port = s.getsockname()[1]
                bind_map[host] = {
                    'name': device,
                    'port': port,
                    'proto': proto,
                    'sock': s}
                bind_data += struct.pack('!IH', host, int(port))
                bind_count += 1
            else:
                connect_data += struct.pack('!IH', host, 0)
                connect_count += 1
                con_list.append(device)
    elif fname.startswith('opaque:'):
        net_device = True
        con_list.append([fname, device])
    mnfst.channels[device] = {
        'device': device,
        'path': fname,
        'type': type,
        'etag': tag,
        'read': rd,
        'read_bytes': rd_byte,
        'write': wr,
        'write_bytes': wr_byte
    }
    if net_device:
        mnfst.channels[device]['path'] = '/dev/null'
    stddev.pop(device, 0)
    if device == '/dev/stdin' or device == '/dev/input':
        mnfst.input = mnfst.channels[device]
    elif device == '/dev/stdout' or device == '/dev/output':
        mnfst.output = mnfst.channels[device]
    elif device == '/dev/stderr':
        mnfst.err = mnfst.channels[device]
    elif device == '/dev/image':
        mnfst.image = mnfst.channels[device]
    elif device == '/dev/nvram':
        mnfst.nvram = mnfst.channels[device]

if len(stddev) > 0:
    errdump(1, valid, 0, mnfst.Etag, accounting,
            'all standard channels must be present')
request = \
    struct.pack('!I', alias) + \
    struct.pack('!I', bind_count) + \
    struct.pack('!I', connect_count) + \
    bind_data + \
    connect_data
if getattr(mnfst, 'NameServer', None):
    ns_proto, ns_host, ns_port = mnfst.NameServer.split(':')
    ns = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ns.connect((ns_host, int(ns_port)))
    ns.sendto(request, (ns_host, int(ns_port)))
    ns_host = ns.getpeername()[0]
    ns_port = ns.getpeername()[1]
    while 1:
        reply, addr = ns.recvfrom(65535)
        if addr[0] == ns_host and addr[1] == ns_port:
            offset = 8
            connect_count = struct.unpack_from('!I', reply, offset)[0]
            offset += 4 + len(bind_data)
            for i in range(connect_count):
                host, port = struct.unpack_from('!4sH', reply, offset)[0:2]
                offset += 6
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((socket.inet_ntop(socket.AF_INET, host), port))
                con_list[i] = [con_list[i],
                               'tcp://%s:%d' % (
                                   socket.inet_ntop(socket.AF_INET, host),
                                   port)]
            break
    if bind_map:
        sleep(0.5)
try:
    inf = file(mnfst.input['path'], 'r')
    ouf = file(mnfst.output['path'], 'w')
    if mnfst.output['etag']:
        mnfst.output['etag'] = md5()
    err = file(mnfst.err['path'], 'w')
    if mnfst.err['etag']:
        mnfst.err['etag'] = md5()
    in_str = inf.read()
    accounting[2] += 1
    accounting[3] += len(in_str)
    id = pickle.loads(in_str)
except EOFError:
    id = []
except Exception:
    errdump(1, valid, 0, mnfst.Etag, accounting, 'Std files I/O error')

od = ''
try:
    od = str(eval_as_function(exe))
except Exception, e:
    msg = e.message+'\n'
    err.write(msg)
    if mnfst.err['etag']:
        mnfst.err['etag'].update(msg)
    accounting[4] += 1
    accounting[5] += len(msg)
ouf.write(od)
if mnfst.output['etag']:
    mnfst.output['etag'].update(od)
accounting[4] += 1
accounting[5] += len(od)
for t in con_list:
    msg = '%s, %s\n' % (t[1], t[0])
    err.write(msg)
    if mnfst.err['etag']:
        mnfst.err['etag'].update(msg)
    accounting[4] += 1
    accounting[5] += len(msg)
inf.close()
ouf.close()
if mnfst.output['etag']:
    mnfst.output['etag'] = mnfst.output['etag'].hexdigest()
    mnfst.Etag = '%s %s' % (mnfst.output['device'], mnfst.output['etag'])
msg = '\nfinished\n'
err.write(msg)
if mnfst.err['etag']:
    mnfst.err['etag'].update(msg)
accounting[4] += 1
accounting[5] += len(msg)
err.close()
if mnfst.err['etag']:
    mnfst.err['etag'] = mnfst.err['etag'].hexdigest()
    mnfst.Etag += ' %s %s' % (mnfst.err['device'], mnfst.err['etag'])
errdump(0, valid, retcode, mnfst.Etag, accounting, 'ok.')
