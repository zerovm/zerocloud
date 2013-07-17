from hashlib import md5
import socket
import struct
from sys import argv, exit
import re
import logging
import cPickle as pickle
from time import sleep
from argparse import ArgumentParser
try:
    import simplejson as json
except ImportError:
    import json


def errdump(zvm_errcode, nexe_validity, nexe_errcode, nexe_etag, nexe_accounting, status_line):
    print '%d\n%d\n%s\n%s\n%s' % (nexe_validity, nexe_errcode, nexe_etag,
                                  ' '.join([str(val) for val in nexe_accounting]), status_line)
    exit(zvm_errcode)


def eval_as_function(code, local_vars={}, global_vars=None):
    if not global_vars:
        global_vars = globals()
    context = {}
    code = re.sub(r"(?m)^", "    ", code)
    code = "def anon(" + ','.join(local_vars.keys()) + "):\n" + code
    exec code in global_vars, context
    retval = context['anon'](*(local_vars.values()))
    return retval


parser = ArgumentParser()
parser.add_argument('-M', dest='manifest')
parser.add_argument('-s', action='store_true', dest='skip')
parser.add_argument('-F', action='store_true', dest='validate')
args = parser.parse_args()

valid = 1
if args.skip:
    valid = 0
accounting = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
manifest = args.manifest
if not manifest:
    errdump(1, valid, 0, '', accounting, 'Manifest file required')
try:
    inputmnfst = file(manifest, 'r').read().splitlines()
except IOError:
    errdump(1, valid, 0, '', accounting, 'Cannot open manifest file: %s' % manifest)
dl = re.compile("\s*=\s*")
mnfst_dict = dict()
for line in inputmnfst:
    (attr, val) = re.split(dl, line, 1)
    if attr and attr in mnfst_dict:
        mnfst_dict[attr] += ',' + val
    else:
        mnfst_dict[attr] = val


class Mnfst:
    pass


mnfst = Mnfst()
index = 0
status = 'nexe did not run'
retcode = 0


def retrieve_mnfst_field(n, eq=None, min=None, max=None, isint=False, optional=False):
    if n not in mnfst_dict:
        if optional:
            return
        errdump(1, valid, 0, '', accounting, 'Manifest key missing "%s"' % n)
    v = mnfst_dict[n]
    if isint:
        v = int(v)
        if min and v < min:
            errdump(1, valid, 0, '', accounting, '%s = %d is less than expected: %d' % (n, v, min))
        if max and v > max:
            errdump(1, valid, 0, '', accounting, '%s = %d is more than expected: %d' % (n, v, max))
    if eq and v != eq:
        errdump(1, valid, 0, '', accounting, '%s = %s and expected %s' % (n, v, eq))
    setattr(mnfst, n.strip(), v)


retrieve_mnfst_field('Version', '20130611')
retrieve_mnfst_field('Program')
retrieve_mnfst_field('Etag', optional=True)
retrieve_mnfst_field('Timeout', min=1, isint=True)
retrieve_mnfst_field('Memory')
retrieve_mnfst_field('Channel')
retrieve_mnfst_field('Node', optional=True, isint=True)
retrieve_mnfst_field('NameServer', optional=True)
exe = file(mnfst.Program, 'r').read()
if 'INVALID' == exe:
    valid = 2
    retcode = 0
    errdump(8, valid, retcode, '', accounting, 'nexe is invalid')
if args.validate:
    errdump(0, valid, retcode, '', accounting, 'nexe is valid')
if not getattr(mnfst, 'Etag', None):
    mnfst.Etag = 'DISABLED'

channel_list = re.split('\s*,\s*', mnfst.Channel)
if len(channel_list) % 8 != 0:
    errdump(1, valid, 0, mnfst.Etag, accounting, 'wrong channel config: %s' % mnfst.Channel)
dev_list = channel_list[1::8]
bind_data = ''
bind_count = 0
connect_data = ''
connect_count = 0
con_list = []
bind_map = {}
alias = int(mnfst.Node)
mnfst.channels = {}
for fname, device, type, tag, rd, rd_byte, wr, wr_byte in zip(*[iter(channel_list)]*8):
    if fname.startswith('tcp:'):
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
                bind_map[host] = {'name': device, 'port': port, 'proto': proto, 'sock': s}
                bind_data += struct.pack('!IIH', host, 0, int(port))
                bind_count += 1
            else:
                connect_data += struct.pack('!IIH', host, 0, 0)
                connect_count += 1
                con_list.append(device)
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

request = \
    struct.pack('!I', alias) + \
    struct.pack('!I', bind_count) + \
    bind_data + \
    struct.pack('!I', connect_count) + \
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
            offset = 0
            count = struct.unpack_from('!I', reply, offset)[0]
            offset += 4
            for i in range(count):
                host, port = struct.unpack_from('!4sH', reply, offset+4)[0:2]
                offset += 10
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
    accounting[4] += 1
    accounting[5] += len(in_str)
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
    accounting[6] += 1
    accounting[7] += len(msg)
ouf.write(od)
if mnfst.output['etag']:
    mnfst.output['etag'].update(od)
accounting[6] += 1
accounting[7] += len(od)
for t in con_list:
    msg = '%s, %s\n' % (t[1], t[0])
    err.write(msg)
    if mnfst.err['etag']:
        mnfst.err['etag'].update(msg)
    accounting[6] += 1
    accounting[7] += len(msg)
inf.close()
ouf.close()
if mnfst.output['etag']:
    mnfst.output['etag'] = mnfst.output['etag'].hexdigest()
    mnfst.Etag = '%s %s' % (mnfst.output['device'], mnfst.output['etag'])
msg = '\nfinished\n'
err.write(msg)
if mnfst.err['etag']:
    mnfst.err['etag'].update(msg)
accounting[6] += 1
accounting[7] += len(msg)
err.close()
if mnfst.err['etag']:
    mnfst.err['etag'] = mnfst.err['etag'].hexdigest()
    mnfst.Etag += ' %s %s' % (mnfst.err['device'], mnfst.err['etag'])
status = 'ok.'
errdump(0, valid, retcode, mnfst.Etag, accounting, status)
