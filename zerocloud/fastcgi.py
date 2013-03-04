from StringIO import StringIO
from eventlet.green import os
from eventlet.green.httplib import HTTPResponse
from os import SEEK_CUR
import struct
import webob

# Constants from the spec.
from swift.common.swob import Response

FCGI_LISTENSOCK_FILENO = 0

FCGI_HEADER_LEN = 8

FCGI_VERSION_1 = 1

FCGI_BEGIN_REQUEST = 1
FCGI_ABORT_REQUEST = 2
FCGI_END_REQUEST = 3
FCGI_PARAMS = 4
FCGI_STDIN = 5
FCGI_STDOUT = 6
FCGI_STDERR = 7
FCGI_DATA = 8
FCGI_GET_VALUES = 9
FCGI_GET_VALUES_RESULT = 10
FCGI_UNKNOWN_TYPE = 11
FCGI_MAXTYPE = FCGI_UNKNOWN_TYPE

FCGI_NULL_REQUEST_ID = 0

FCGI_KEEP_CONN = 1

FCGI_RESPONDER = 1
FCGI_AUTHORIZER = 2
FCGI_FILTER = 3

FCGI_REQUEST_COMPLETE = 0
FCGI_CANT_MPX_CONN = 1
FCGI_OVERLOADED = 2
FCGI_UNKNOWN_ROLE = 3

FCGI_MAX_CONNS = 'FCGI_MAX_CONNS'
FCGI_MAX_REQS = 'FCGI_MAX_REQS'
FCGI_MPXS_CONNS = 'FCGI_MPXS_CONNS'

FCGI_Header = '!BBHHBx'
FCGI_BeginRequestBody = '!HB5x'
FCGI_EndRequestBody = '!LB3x'
FCGI_UnknownTypeBody = '!B7x'

FCGI_BeginRequestBody_LEN = struct.calcsize(FCGI_BeginRequestBody)
FCGI_EndRequestBody_LEN = struct.calcsize(FCGI_EndRequestBody)
FCGI_UnknownTypeBody_LEN = struct.calcsize(FCGI_UnknownTypeBody)


def decode_pair(s, pos=0):
    """
    Decodes a name/value pair.

    The number of bytes decoded as well as the name/value pair
    are returned.
    """
    nameLength = ord(s[pos])
    if nameLength & 128:
        nameLength = struct.unpack('!L', s[pos:pos + 4])[0] & 0x7fffffff
        pos += 4
    else:
        pos += 1

    valueLength = ord(s[pos])
    if valueLength & 128:
        valueLength = struct.unpack('!L', s[pos:pos + 4])[0] & 0x7fffffff
        pos += 4
    else:
        pos += 1

    name = s[pos:pos + nameLength]
    pos += nameLength
    value = s[pos:pos + valueLength]
    pos += valueLength

    return (pos, (name, value))


def encode_pair(name, value):
    """
    Encodes a name/value pair.

    The encoded string is returned.
    """
    nameLength = len(name)
    if nameLength < 128:
        s = chr(nameLength)
    else:
        s = struct.pack('!L', nameLength | 0x80000000L)

    valueLength = len(value)
    if valueLength < 128:
        s += chr(valueLength)
    else:
        s += struct.pack('!L', valueLength | 0x80000000L)

    return s + name + value


class PseudoSocket():

    def __init__(self, file):
        self.file = file

    def makefile(self, mode, buffering):
        return self.file

class PseudoFile():

    def __init__(self, file):
        self.file = file
        self.record = Record()
        self.type = self.record.type
        self._read_next_record()
        self.buf = StringIO(self.record.contentData)

    def __getattr__(self, attr):
        return getattr(self.file, attr)

    def read(self, amt=None):
        data = ''
        try:
            data = self.buf.read(amt)
            if amt and len(data) < amt:
                if self._read_next_record():
                    self.buf = StringIO(self.record.contentData)
                    return data + self.read(amt - len(data))
            if not amt:
                if self._read_next_record():
                    self.buf = StringIO(self.record.contentData)
            return data
        except EOFError:
            return data

    def _read_next_record(self):
        self.record.read(self.file)
        if self.record.type != self.type:
            self.type = self.record.type
            return False
        if self.record.contentLength == 0:
            return self._read_next_record()
        return True

    def readline(self, size=None):
        line = ''
        try:
            line = self.buf.readline(length=size)
            if size and size == len(line):
                return line
            if line.find('\n') == -1:
                if self._read_next_record():
                    self.buf = StringIO(line + self.record.contentData)
                    return self.readline(size)
            return line
        except EOFError:
            return line

    def readlines(self, size=None):
        lines = []
        try:
            lines = self.buf.readlines(sizehint=size)
            if not lines:
                if self._read_next_record():
                    self.buf = StringIO(self.record.contentData)
                    return self.readlines(size)
            if lines and lines[-1].find('\n') == -1:
                if self._read_next_record():
                    self.buf = StringIO(lines.pop() + self.record.contentData)
            return lines
        except EOFError:
            return lines

    def close(self):
        if not self.file:
            return
        self.file.close()
        os.unlink(self.file.name)
#        try:
#            self._read_next_record()
#            self.buf = StringIO(self.record.contentData)
#        except EOFError:
#            self.file.close()
#            self.file = None


#class FcgiHTTPResponse(HTTPResponse):
#
#    def __init__(self, fp, debuglevel=0, strict=0, method=None, buffering=False):
#        HTTPResponse.__init__(self, PseudoSocket(fp), debuglevel, strict, method, buffering)

class Record(object):
    """
    A FastCGI Record.

    Used for encoding/decoding records.
    """
    def __init__(self, type=FCGI_UNKNOWN_TYPE, requestId=FCGI_NULL_REQUEST_ID,
                 content_iter=None, chunk_size=65536):
        self.version = FCGI_VERSION_1
        self.type = type
        self.requestId = requestId
        self.contentLength = 0
        self.paddingLength = 0
        self.contentData = content_iter
        self.chunk_size = chunk_size

    def read(self, file):
        header = file.read(FCGI_HEADER_LEN)
        if len(header) < FCGI_HEADER_LEN:
            raise EOFError

        self.version, self.type, self.requestId, self.contentLength,\
        self.paddingLength = struct.unpack(FCGI_Header, header)

        if self.contentLength:
            try:
                self.contentData = file.read(self.contentLength)
            except:
                raise EOFError
        else:
            self.contentData = ''
        if len(self.contentData) < self.contentLength:
            raise EOFError

        if self.paddingLength:
            try:
                file.seek(self.paddingLength, SEEK_CUR)
            except:
                raise EOFError

    def write(self, file):
        count = 0
        for chunk in self.contentData:
            count += 1
            content_length = len(chunk)
            padding_length = -content_length & 7
            header = struct.pack(FCGI_Header, self.version, self.type,
                self.requestId, content_length,
                padding_length)
            file.write(header)
            if content_length:
                file.write(chunk)
            if padding_length:
                file.write('\x00' * padding_length)
        if count:
            header = struct.pack(FCGI_Header, self.version, self.type,
                self.requestId, 0,0)
            file.write(header)


if __name__ == '__main__':
    file_name = '/tmp/socket'
    out = open(file_name, 'wb')
    num = 16
    chunk_size = 64 * 1024 - 1
    data = ['HTTP/1.0 200 OK\r\n'
            'Date: Fri, 31 Dec 1999 23:59:59 GMT\r\n'
            'Content-Type: text/html\r\n'
            'Content-Length: %d\r\n\r\n' % (num * chunk_size)]
    #data = []
    #total_size = len(data[0]) + num * chunk_size
    for i in range(0, 16):
        data.append('d' * (64 * 1024 - 1))
    r = Record(type=FCGI_STDOUT, requestId=1, content_iter=iter(data))
    r.write(out)
    err = []
    for i in range(0, 2):
        err.append('e' * (64 * 1024 - 1))
    r = Record(type=FCGI_STDERR, requestId=1, content_iter=iter(err))
    r.write(out)
    out.close()
    input = open(file_name, 'rb')
    pf = PseudoFile(input)
#    resp = FcgiHTTPResponse(pf)
#    resp.begin()
#    rr = Response(status='%d %s' %
#                           (resp.status,
#                            resp.reason),
#        app_iter=iter(lambda: resp.read(65536),''),
#        headers = dict(resp.getheaders()))
#    str(rr.body)
#    print os.path.getsize(file_name)
#    data = pf.read()
#    sum = len(data)
#    while data:
#        data = pf.read()
#        sum += len(data)
#    print sum
    if pf.type == FCGI_STDOUT:
        resp = HTTPResponse(PseudoSocket(pf))
        resp.begin()
        rr = Response(status='%d %s' %
                           (resp.status,
                            resp.reason),
        app_iter=iter(lambda: resp.read(65536),''),
        headers = dict(resp.getheaders()))
        print rr.status
        print rr.headers
        #print resp.__dict__
        #print resp.getheaders()
        #print len(resp.read())
#    data = pf.read()
#    sum = len(data)
#    while data:
#        #print data
#        data = pf.read()
#        sum += len(data)
#    print sum
#    #pf.close()
#    print pf.type
#    data = pf.read()
#    sum = len(data)
#    while data:
#        #print data
#        data = pf.read()
#        sum += len(data)
#    print sum
    #print rr.body