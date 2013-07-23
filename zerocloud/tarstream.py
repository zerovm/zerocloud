#---------
# Imports
#---------
import sys
import os
import shutil
import stat
import errno
import time
import struct
import copy
import re
import operator

try:
    import grp, pwd
except ImportError:
    grp = pwd = None

#---------------------------------------------------------
# tar constants
#---------------------------------------------------------
NUL = "\0"                      # the null character
BLOCKSIZE = 512                 # length of processing blocks
RECORDSIZE = BLOCKSIZE * 20     # length of records
GNU_MAGIC = "ustar  \0"         # magic gnu tar string
POSIX_MAGIC = "ustar\x0000"     # magic posix tar string

LENGTH_NAME = 100               # maximum length of a filename
LENGTH_LINK = 100               # maximum length of a linkname
LENGTH_PREFIX = 155             # maximum length of the prefix field

REGTYPE = "0"                   # regular file
AREGTYPE = "\0"                 # regular file
LNKTYPE = "1"                   # link (inside tarfile)
SYMTYPE = "2"                   # symbolic link
CHRTYPE = "3"                   # character special device
BLKTYPE = "4"                   # block special device
DIRTYPE = "5"                   # directory
FIFOTYPE = "6"                  # fifo special device
CONTTYPE = "7"                  # contiguous file

GNUTYPE_LONGNAME = "L"          # GNU tar longname
GNUTYPE_LONGLINK = "K"          # GNU tar longlink
GNUTYPE_SPARSE = "S"            # GNU tar sparse file

XHDTYPE = "x"                   # POSIX.1-2001 extended header
XGLTYPE = "g"                   # POSIX.1-2001 global header
SOLARIS_XHDTYPE = "X"           # Solaris extended header

USTAR_FORMAT = 0                # POSIX.1-1988 (ustar) format
GNU_FORMAT = 1                  # GNU tar format
PAX_FORMAT = 2                  # POSIX.1-2001 (pax) format
DEFAULT_FORMAT = GNU_FORMAT

#---------------------------------------------------------
# tarfile constants
#---------------------------------------------------------
# File types that tarfile supports:
SUPPORTED_TYPES = (REGTYPE, AREGTYPE, LNKTYPE,
                   SYMTYPE, DIRTYPE, FIFOTYPE,
                   CONTTYPE, CHRTYPE, BLKTYPE,
                   GNUTYPE_LONGNAME, GNUTYPE_LONGLINK,
                   GNUTYPE_SPARSE)

# File types that will be treated as a regular file.
REGULAR_TYPES = (REGTYPE, AREGTYPE,
                 CONTTYPE, GNUTYPE_SPARSE)

# File types that are part of the GNU tar format.
GNU_TYPES = (GNUTYPE_LONGNAME, GNUTYPE_LONGLINK,
             GNUTYPE_SPARSE)

# Fields from a pax header that override a TarInfo attribute.
PAX_FIELDS = ("path", "linkpath", "size", "mtime",
              "uid", "gid", "uname", "gname")

# Fields in a pax header that are numbers, all other fields
# are treated as strings.
PAX_NUMBER_FIELDS = {
    "atime": float,
    "ctime": float,
    "mtime": float,
    "uid": int,
    "gid": int,
    "size": int
}

#---------------------------------------------------------
# Bits used in the mode field, values in octal.
#---------------------------------------------------------
S_IFLNK = 0120000        # symbolic link
S_IFREG = 0100000        # regular file
S_IFBLK = 0060000        # block device
S_IFDIR = 0040000        # directory
S_IFCHR = 0020000        # character device
S_IFIFO = 0010000        # fifo

TSUID   = 04000          # set UID on execution
TSGID   = 02000          # set GID on execution
TSVTX   = 01000          # reserved

TUREAD  = 0400           # read by owner
TUWRITE = 0200           # write by owner
TUEXEC  = 0100           # execute/search by owner
TGREAD  = 0040           # read by group
TGWRITE = 0020           # write by group
TGEXEC  = 0010           # execute/search by group
TOREAD  = 0004           # read by other
TOWRITE = 0002           # write by other
TOEXEC  = 0001           # execute/search by other

#---------------------------------------------------------
# initialization
#---------------------------------------------------------
ENCODING = sys.getfilesystemencoding()
if ENCODING is None:
    ENCODING = sys.getdefaultencoding()

#---------------------------------------------------------
# Some useful functions
#---------------------------------------------------------

def stn(s, length):
    """Convert a python string to a null-terminated string buffer.
    """
    return s[:length] + (length - len(s)) * NUL

def nts(s):
    """Convert a null-terminated string field to a python string.
    """
    # Use the string up to the first null char.
    p = s.find("\0")
    if p == -1:
        return s
    return s[:p]

def nti(s):
    """Convert a number field to a python number.
    """
    # There are two possible encodings for a number field, see
    # itn() below.
    if s[0] != chr(0200):
        try:
            n = int(nts(s) or "0", 8)
        except ValueError:
            raise InvalidHeaderError("invalid header")
    else:
        n = 0L
        for i in xrange(len(s) - 1):
            n <<= 8
            n += ord(s[i + 1])
    return n

def itn(n, digits=8, format=DEFAULT_FORMAT):
    """Convert a python number to a number field.
    """
    # POSIX 1003.1-1988 requires numbers to be encoded as a string of
    # octal digits followed by a null-byte, this allows values up to
    # (8**(digits-1))-1. GNU tar allows storing numbers greater than
    # that if necessary. A leading 0200 byte indicates this particular
    # encoding, the following digits-1 bytes are a big-endian
    # representation. This allows values up to (256**(digits-1))-1.
    if 0 <= n < 8 ** (digits - 1):
        s = "%0*o" % (digits - 1, n) + NUL
    else:
        if format != GNU_FORMAT or n >= 256 ** (digits - 1):
            raise ValueError("overflow in number field")

        if n < 0:
            # XXX We mimic GNU tar's behaviour with negative numbers,
            # this could raise OverflowError.
            n = struct.unpack("L", struct.pack("l", n))[0]

        s = ""
        for i in xrange(digits - 1):
            s = chr(n & 0377) + s
            n >>= 8
        s = chr(0200) + s
    return s

def uts(s, encoding, errors):
    """Convert a unicode object to a string.
    """
    if errors == "utf-8":
        # An extra error handler similar to the -o invalid=UTF-8 option
        # in POSIX.1-2001. Replace untranslatable characters with their
        # UTF-8 representation.
        try:
            return s.encode(encoding, "strict")
        except UnicodeEncodeError:
            x = []
            for c in s:
                try:
                    x.append(c.encode(encoding, "strict"))
                except UnicodeEncodeError:
                    x.append(c.encode("utf8"))
            return "".join(x)
    else:
        return s.encode(encoding, errors)

def calc_chksums(buf):
    """Calculate the checksum for a member's header by summing up all
       characters except for the chksum field which is treated as if
       it was filled with spaces. According to the GNU tar sources,
       some tars (Sun and NeXT) calculate chksum with signed char,
       which will be different if there are chars in the buffer with
       the high bit set. So we calculate two checksums, unsigned and
       signed.
    """
    unsigned_chksum = 256 + sum(struct.unpack("148B", buf[:148]) + struct.unpack("356B", buf[156:512]))
    signed_chksum = 256 + sum(struct.unpack("148b", buf[:148]) + struct.unpack("356b", buf[156:512]))
    return unsigned_chksum, signed_chksum

class TarInfo(object):
    """Informational class which holds the details about an
       archive member given by a tar header block.
       TarInfo objects are returned by TarFile.getmember(),
       TarFile.getmembers() and TarFile.gettarinfo() and are
       usually created internally.
    """

    def __init__(self, name=""):
        """Construct a TarInfo object. name is the optional name
           of the member.
        """
        self.name = name        # member name
        self.mode = 0644        # file permissions
        self.uid = 0            # user id
        self.gid = 0            # group id
        self.size = 0           # file size
        self.mtime = 0          # modification time
        self.chksum = 0         # header checksum
        self.type = REGTYPE     # member type
        self.linkname = ""      # link name
        self.uname = ""         # user name
        self.gname = ""         # group name
        self.devmajor = 0       # device major number
        self.devminor = 0       # device minor number

        self.offset = 0         # the tar header starts here
        self.offset_data = 0    # the file's data starts here

        self.pax_headers = {}   # pax header information

    # In pax headers the "name" and "linkname" field are called
    # "path" and "linkpath".
    def _getpath(self):
        return self.name
    def _setpath(self, name):
        self.name = name
    path = property(_getpath, _setpath)

    def _getlinkpath(self):
        return self.linkname
    def _setlinkpath(self, linkname):
        self.linkname = linkname
    linkpath = property(_getlinkpath, _setlinkpath)

    def __repr__(self):
        return "<%s %r at %#x>" % (self.__class__.__name__,self.name,id(self))

    def get_info(self, encoding, errors):
        """Return the TarInfo's attributes as a dictionary.
        """
        info = {
            "name":     self.name,
            "mode":     self.mode & 07777,
            "uid":      self.uid,
            "gid":      self.gid,
            "size":     self.size,
            "mtime":    self.mtime,
            "chksum":   self.chksum,
            "type":     self.type,
            "linkname": self.linkname,
            "uname":    self.uname,
            "gname":    self.gname,
            "devmajor": self.devmajor,
            "devminor": self.devminor
        }

        if info["type"] == DIRTYPE and not info["name"].endswith("/"):
            info["name"] += "/"

        for key in ("name", "linkname", "uname", "gname"):
            if type(info[key]) is unicode:
                info[key] = info[key].encode(encoding, errors)

        return info

    def tobuf(self, format=DEFAULT_FORMAT, encoding=ENCODING, errors="strict"):
        """Return a tar header as a string of 512 byte blocks.
        """
        info = self.get_info(encoding, errors)

        if format == USTAR_FORMAT:
            return self.create_ustar_header(info)
        elif format == GNU_FORMAT:
            return self.create_gnu_header(info)
        elif format == PAX_FORMAT:
            return self.create_pax_header(info, encoding, errors)
        else:
            raise ValueError("invalid format")

    def create_ustar_header(self, info):
        """Return the object as a ustar header block.
        """
        info["magic"] = POSIX_MAGIC

        if len(info["linkname"]) > LENGTH_LINK:
            raise ValueError("linkname is too long")

        if len(info["name"]) > LENGTH_NAME:
            info["prefix"], info["name"] = self._posix_split_name(info["name"])

        return self._create_header(info, USTAR_FORMAT)

    def create_gnu_header(self, info):
        """Return the object as a GNU header block sequence.
        """
        info["magic"] = GNU_MAGIC

        buf = ""
        if len(info["linkname"]) > LENGTH_LINK:
            buf += self._create_gnu_long_header(info["linkname"], GNUTYPE_LONGLINK)

        if len(info["name"]) > LENGTH_NAME:
            buf += self._create_gnu_long_header(info["name"], GNUTYPE_LONGNAME)

        return buf + self._create_header(info, GNU_FORMAT)

    def create_pax_header(self, info, encoding, errors):
        """Return the object as a ustar header block. If it cannot be
           represented this way, prepend a pax extended header sequence
           with supplement information.
        """
        info["magic"] = POSIX_MAGIC
        pax_headers = self.pax_headers.copy()

        # Test string fields for values that exceed the field length or cannot
        # be represented in ASCII encoding.
        for name, hname, length in (
            ("name", "path", LENGTH_NAME), ("linkname", "linkpath", LENGTH_LINK),
            ("uname", "uname", 32), ("gname", "gname", 32)):

            if hname in pax_headers:
                # The pax header has priority.
                continue

            val = info[name].decode(encoding, errors)

            # Try to encode the string as ASCII.
            try:
                val.encode("ascii")
            except UnicodeEncodeError:
                pax_headers[hname] = val
                continue

            if len(info[name]) > length:
                pax_headers[hname] = val

        # Test number fields for values that exceed the field limit or values
        # that like to be stored as float.
        for name, digits in (("uid", 8), ("gid", 8), ("size", 12), ("mtime", 12)):
            if name in pax_headers:
                # The pax header has priority. Avoid overflow.
                info[name] = 0
                continue

            val = info[name]
            if not 0 <= val < 8 ** (digits - 1) or isinstance(val, float):
                pax_headers[name] = unicode(val)
                info[name] = 0

        # Create a pax extended header if necessary.
        if pax_headers:
            buf = self._create_pax_generic_header(pax_headers)
        else:
            buf = ""

        return buf + self._create_header(info, USTAR_FORMAT)

    @classmethod
    def create_pax_global_header(cls, pax_headers):
        """Return the object as a pax global header block sequence.
        """
        return cls._create_pax_generic_header(pax_headers, type=XGLTYPE)

    def _posix_split_name(self, name):
        """Split a name longer than 100 chars into a prefix
           and a name part.
        """
        prefix = name[:LENGTH_PREFIX + 1]
        while prefix and prefix[-1] != "/":
            prefix = prefix[:-1]

        name = name[len(prefix):]
        prefix = prefix[:-1]

        if not prefix or len(name) > LENGTH_NAME:
            raise ValueError("name is too long")
        return prefix, name

    @staticmethod
    def _create_header(info, format):
        """Return a header block. info is a dictionary with file
           information, format must be one of the *_FORMAT constants.
        """
        parts = [
            stn(info.get("name", ""), 100),
            itn(info.get("mode", 0) & 07777, 8, format),
            itn(info.get("uid", 0), 8, format),
            itn(info.get("gid", 0), 8, format),
            itn(info.get("size", 0), 12, format),
            itn(info.get("mtime", 0), 12, format),
            "        ", # checksum field
            info.get("type", REGTYPE),
            stn(info.get("linkname", ""), 100),
            stn(info.get("magic", POSIX_MAGIC), 8),
            stn(info.get("uname", ""), 32),
            stn(info.get("gname", ""), 32),
            itn(info.get("devmajor", 0), 8, format),
            itn(info.get("devminor", 0), 8, format),
            stn(info.get("prefix", ""), 155)
        ]

        buf = struct.pack("%ds" % BLOCKSIZE, "".join(parts))
        chksum = calc_chksums(buf[-BLOCKSIZE:])[0]
        buf = buf[:-364] + "%06o\0" % chksum + buf[-357:]
        return buf

    @staticmethod
    def _create_payload(payload):
        """Return the string payload filled with zero bytes
           up to the next 512 byte border.
        """
        blocks, remainder = divmod(len(payload), BLOCKSIZE)
        if remainder > 0:
            payload += (BLOCKSIZE - remainder) * NUL
        return payload

    @classmethod
    def _create_gnu_long_header(cls, name, type):
        """Return a GNUTYPE_LONGNAME or GNUTYPE_LONGLINK sequence
           for name.
        """
        name += NUL

        info = {}
        info["name"] = "././@LongLink"
        info["type"] = type
        info["size"] = len(name)
        info["magic"] = GNU_MAGIC

        # create extended header + name blocks.
        return cls._create_header(info, USTAR_FORMAT) +\
               cls._create_payload(name)

    @classmethod
    def _create_pax_generic_header(cls, pax_headers, type=XHDTYPE):
        """Return a POSIX.1-2001 extended or global header sequence
           that contains a list of keyword, value pairs. The values
           must be unicode objects.
        """
        records = []
        for keyword, value in pax_headers.iteritems():
            keyword = keyword.encode("utf8")
            value = value.encode("utf8")
            l = len(keyword) + len(value) + 3   # ' ' + '=' + '\n'
            n = p = 0
            while True:
                n = l + len(str(p))
                if n == p:
                    break
                p = n
            records.append("%d %s=%s\n" % (p, keyword, value))
        records = "".join(records)

        # We use a hardcoded "././@PaxHeader" name like star does
        # instead of the one that POSIX recommends.
        info = {}
        info["name"] = "././@PaxHeader"
        info["type"] = type
        info["size"] = len(records)
        info["magic"] = POSIX_MAGIC

        # Create pax header + record blocks.
        return cls._create_header(info, USTAR_FORMAT) +\
               cls._create_payload(records)

    @classmethod
    def frombuf(cls, buf):
        """Construct a TarInfo object from a 512 byte string buffer.
        """
        if len(buf) == 0:
            raise EmptyHeaderError("empty header")
        if len(buf) != BLOCKSIZE:
            raise TruncatedHeaderError("truncated header")
        if buf.count(NUL) == BLOCKSIZE:
            raise EOFHeaderError("end of file header")

        chksum = nti(buf[148:156])
        if chksum not in calc_chksums(buf):
            raise InvalidHeaderError("bad checksum")

        obj = cls()
        obj.buf = buf
        obj.name = nts(buf[0:100])
        obj.mode = nti(buf[100:108])
        obj.uid = nti(buf[108:116])
        obj.gid = nti(buf[116:124])
        obj.size = nti(buf[124:136])
        obj.mtime = nti(buf[136:148])
        obj.chksum = chksum
        obj.type = buf[156:157]
        obj.linkname = nts(buf[157:257])
        obj.magic = buf[257:265]
        obj.uname = nts(buf[265:297])
        obj.gname = nts(buf[297:329])
        obj.devmajor = nti(buf[329:337])
        obj.devminor = nti(buf[337:345])
        prefix = nts(buf[345:500])

        # Old V7 tar format represents a directory as a regular
        # file with a trailing slash.
        if obj.type == AREGTYPE and obj.name.endswith("/"):
            obj.type = DIRTYPE

        # Remove redundant slashes from directories.
        if obj.isdir():
            obj.name = obj.name.rstrip("/")

        # Reconstruct a ustar longname.
        if prefix and obj.type not in GNU_TYPES:
            obj.name = prefix + "/" + obj.name
        return obj

#    @classmethod
#    def fromtarfile(cls, tarfile):
#        """Return the next TarInfo object from TarFile object
#           tarfile.
#        """
#        buf = tarfile.fileobj.read(BLOCKSIZE)
#        obj = cls.frombuf(buf)
#        obj.offset = tarfile.fileobj.tell() - BLOCKSIZE
#        return obj._proc_member(tarfile)

    #--------------------------------------------------------------------------
    # The following are methods that are called depending on the type of a
    # member. The entry point is _proc_member() which can be overridden in a
    # subclass to add custom _proc_*() methods. A _proc_*() method MUST
    # implement the following
    # operations:
    # 1. Set self.offset_data to the position where the data blocks begin,
    #    if there is data that follows.
    # 2. Set tarfile.offset to the position where the next member's header will
    #    begin.
    # 3. Return self or another valid TarInfo object.
#    def _proc_member(self, tarfile):
#        """Choose the right processing method depending on
#           the type and call it.
#        """
#        if self.type in (GNUTYPE_LONGNAME, GNUTYPE_LONGLINK):
#            return self._proc_gnulong(tarfile)
#        elif self.type == GNUTYPE_SPARSE:
#            return self._proc_sparse(tarfile)
#        elif self.type in (XHDTYPE, XGLTYPE, SOLARIS_XHDTYPE):
#            return self._proc_pax(tarfile)
#        else:
#            return self._proc_builtin(tarfile)

    def _proc_builtin(self, untar_stream):
        """Process a builtin type or an unknown type which
           will be treated as a regular file.
        """
        self.offset_data = untar_stream.offset
        offset = self.offset_data
        if self.isreg() or self.type not in SUPPORTED_TYPES:
            # Skip the following data blocks.
            offset += self._block(self.size)
        untar_stream.offset = offset

        # Patch the TarInfo object with saved global
        # header information.
        self._apply_pax_info(untar_stream.pax_headers, untar_stream.encoding, untar_stream.errors)

        return self

    def _proc_gnulong(self, untar_stream):
        """Process the blocks that hold a GNU longname
           or longlink member.
        """
        buf = untar_stream.next_block(size=self._block(self.size))
        if not buf:
            return None
        # Fetch the next header and process it.
        try:
            next = untar_stream.read_tarinfo()
            if not next:
                return None
        except HeaderError:
            raise SubsequentHeaderError("missing or bad subsequent header")

        # Patch the TarInfo object from the next header with
        # the longname information.
        next.offset = self.offset
        if self.type == GNUTYPE_LONGNAME:
            next.name = nts(buf)
        elif self.type == GNUTYPE_LONGLINK:
            next.linkname = nts(buf)

        return next

    def _proc_sparse(self, untar_stream):
        """Process a GNU sparse header plus extra headers.
        """
        buf = self.buf
        sp = _ringbuffer()
        pos = 386
        lastpos = 0L
        realpos = 0L
        # There are 4 possible sparse structs in the
        # first header.
        for i in xrange(4):
            try:
                offset = nti(buf[pos:pos + 12])
                numbytes = nti(buf[pos + 12:pos + 24])
            except ValueError:
                break
            if offset > lastpos:
                sp.append(_hole(lastpos, offset - lastpos))
            sp.append(_data(offset, numbytes, realpos))
            realpos += numbytes
            lastpos = offset + numbytes
            pos += 24

        isextended = ord(buf[482])
        origsize = nti(buf[483:495])

        # If the isextended flag is given,
        # there are extra headers to process.
        while isextended == 1:
            buf = untar_stream.next_block()
            if not buf:
                return None
            pos = 0
            for i in xrange(21):
                try:
                    offset = nti(buf[pos:pos + 12])
                    numbytes = nti(buf[pos + 12:pos + 24])
                except ValueError:
                    break
                if offset > lastpos:
                    sp.append(_hole(lastpos, offset - lastpos))
                sp.append(_data(offset, numbytes, realpos))
                realpos += numbytes
                lastpos = offset + numbytes
                pos += 24
            isextended = ord(buf[504])

        if lastpos < origsize:
            sp.append(_hole(lastpos, origsize - lastpos))

        self.sparse = sp

        self.offset_data = untar_stream.offset
        untar_stream.offset = self.offset_data + self._block(self.size)
        self.size = origsize

        return self

    def _proc_pax(self, untar_stream):
        """Process an extended or global header as described in
           POSIX.1-2001.
        """
        # Read the header information.
        buf = untar_stream.next_block(size=self._block(self.size))
        if not buf:
            return None
        # A pax header stores supplemental information for either
        # the following file (extended) or all following files
        # (global).
        if self.type == XGLTYPE:
            pax_headers = untar_stream.pax_headers
        else:
            pax_headers = untar_stream.pax_headers.copy()

        # Parse pax header information. A record looks like that:
        # "%d %s=%s\n" % (length, keyword, value). length is the size
        # of the complete record including the length field itself and
        # the newline. keyword and value are both UTF-8 encoded strings.
        regex = re.compile(r"(\d+) ([^=]+)=", re.U)
        pos = 0
        while True:
            match = regex.match(buf, pos)
            if not match:
                break

            length, keyword = match.groups()
            length = int(length)
            value = buf[match.end(2) + 1:match.start(1) + length - 1]

            keyword = keyword.decode("utf8")
            value = value.decode("utf8")

            pax_headers[keyword] = value
            pos += length

        # Fetch the next header.
        try:
            next = untar_stream.read_tarinfo()
            if not next:
                return None
        except HeaderError:
            raise SubsequentHeaderError("missing or bad subsequent header")

        if self.type in (XHDTYPE, SOLARIS_XHDTYPE):
            # Patch the TarInfo object with the extended header info.
            next._apply_pax_info(pax_headers, untar_stream.encoding, untar_stream.errors)
            #next.offset = self.offset

            if "size" in pax_headers:
                # If the extended header replaces the size field,
                # we need to recalculate the offset where the next
                # header starts.
                offset = next.offset_data
                if next.isreg() or next.type not in SUPPORTED_TYPES:
                    offset += next._block(next.size)
                untar_stream.offset = offset

        return next

    def _apply_pax_info(self, pax_headers, encoding, errors):
        """Replace fields with supplemental information from a previous
           pax extended or global header.
        """
        for keyword, value in pax_headers.iteritems():
            if keyword not in PAX_FIELDS:
                continue

            if keyword == "path":
                value = value.rstrip("/")

            if keyword in PAX_NUMBER_FIELDS:
                try:
                    value = PAX_NUMBER_FIELDS[keyword](value)
                except ValueError:
                    value = 0
            else:
                value = uts(value, encoding, errors)

            setattr(self, keyword, value)

        self.pax_headers = pax_headers.copy()

    def _block(self, count):
        """Round up a byte count by BLOCKSIZE and return it,
           e.g. _block(834) => 1024.
        """
        blocks, remainder = divmod(count, BLOCKSIZE)
        if remainder:
            blocks += 1
        return blocks * BLOCKSIZE

    def isreg(self):
        return self.type in REGULAR_TYPES
    def isfile(self):
        return self.isreg()
    def isdir(self):
        return self.type == DIRTYPE
    def issym(self):
        return self.type == SYMTYPE
    def islnk(self):
        return self.type == LNKTYPE
    def ischr(self):
        return self.type == CHRTYPE
    def isblk(self):
        return self.type == BLKTYPE
    def isfifo(self):
        return self.type == FIFOTYPE
    def issparse(self):
        return self.type == GNUTYPE_SPARSE
    def isdev(self):
        return self.type in (CHRTYPE, BLKTYPE, FIFOTYPE)
    # class TarInfo

class TarError(Exception):
    """Base exception."""
    pass
class ExtractError(TarError):
    """General exception for extract errors."""
    pass
class ReadError(TarError):
    """Exception for unreadble tar archives."""
    pass
class CompressionError(TarError):
    """Exception for unavailable compression methods."""
    pass
class StreamError(TarError):
    """Exception for unsupported operations on stream-like TarFiles."""
    pass
class HeaderError(TarError):
    """Base exception for header errors."""
    pass
class EmptyHeaderError(HeaderError):
    """Exception for empty headers."""
    pass
class TruncatedHeaderError(HeaderError):
    """Exception for truncated headers."""
    pass
class EOFHeaderError(HeaderError):
    """Exception for end of file headers."""
    pass
class InvalidHeaderError(HeaderError):
    """Exception for invalid headers."""
    pass
class SubsequentHeaderError(HeaderError):
    """Exception for missing and invalid extended headers."""
    pass

# Helper classes for sparse file support
class _section:
    """Base class for _data and _hole.
    """
    def __init__(self, offset, size):
        self.offset = offset
        self.size = size
    def __contains__(self, offset):
        return self.offset <= offset < self.offset + self.size

class _data(_section):
    """Represent a data section in a sparse file.
    """
    def __init__(self, offset, size, realpos):
        _section.__init__(self, offset, size)
        self.realpos = realpos

class _hole(_section):
    """Represent a hole section in a sparse file.
    """
    pass

class _ringbuffer(list):
    """Ringbuffer class which increases performance
       over a regular list.
    """
    def __init__(self):
        self.idx = 0
    def find(self, offset):
        idx = self.idx
        while True:
            item = self[idx]
            if offset in item:
                break
            idx += 1
            if idx == len(self):
                idx = 0
            if idx == self.idx:
                # End of File
                return None
        self.idx = idx
        return item


class Path:

    def __init__(self, type, file_name, size, data):
        self.type = type
        self.file_name = file_name
        self.size = size
        self.data = data

    def __iter__(self):
        for chunk in self.data:
            yield chunk


class RegFile:

    def __init__(self, file_name, chunk_size=65536):
        self.file_name = file_name
        self.fp = None
        self.chunk_size = chunk_size
        self.size = 0L
        self.type = DIRTYPE
        if hasattr(os, "lstat"):
            statres = os.lstat(file_name)
        else:
            statres = os.stat(file_name)
        if stat.S_ISREG(statres.st_mode):
            self.size = statres.st_size
            self.type = REGTYPE

    def __iter__(self):
        self.fp = open(self.file_name, 'rb')
        return self

    def next(self):
        chunk = self.fp.read(self.chunk_size)
        if chunk:
            return chunk
        else:
            if self.fp:
                self.fp.close()
                self.fp = None
                raise StopIteration

class StringBuffer:

    def __init__(self, name, body=''):
        self.name = name
        self.file_name = name
        self.size = len(body)
        self.body = body
        self.is_closed = False
        self.type = REGTYPE

    def write(self, data):
        if not self.is_closed:
            self.body += data

    def close(self):
        self.is_closed = True

class TarStream(object):

    errors = None

    def __init__(self, tar_iter=None, path_list=None, chunk_size=65536,
                 format=DEFAULT_FORMAT, encoding=ENCODING, append=False):
        self.tar_iter = tar_iter
        self.path_list = path_list
        self.chunk_size = chunk_size
        self.format = format
        self.encoding = encoding
        self.to_write = self.chunk_size
        self.data = ''
        self.file_len = 0
        self.append = append

    def _serve_chunk(self, buf):
        self.to_write -= len(buf)
        if self.to_write < 0:
            self.data += buf[:self.to_write]
            self.file_len += self.chunk_size
            yield self.data
            self.data = buf[self.to_write:]
            self.to_write += self.chunk_size
        else:
            self.data += buf

    def create_tarinfo(self, path=None, ftype=None, name=None, size=None):
        tarinfo = TarInfo()
        tarinfo.tarfile = None
        if path:
            tarinfo.type = path.type
            tarinfo.name = path.file_name
            tarinfo.size = path.size
        else:
            tarinfo.type = ftype
            tarinfo.name = name
            tarinfo.size = size
        tarinfo.mtime = time.time()
        buf = tarinfo.tobuf(self.format, self.encoding, self.errors)
        return buf

    def get_archive_size(self, file_size):
        size = file_size + BLOCKSIZE - 1
        return (size / BLOCKSIZE) * BLOCKSIZE

    def get_total_stream_length(self):
        size = 0
        for path in self.path_list:
            size += self.get_archive_size(path.size)
            size += len(self.create_tarinfo(path=path))
        return size

    def __iter__(self):
        if self.append:
            if self.tar_iter:
                for data in self.tar_iter:
                    for chunk in self._serve_chunk(data):
                        yield chunk
        for path in self.path_list:
            buf = self.create_tarinfo(path=path)
            for chunk in self._serve_chunk(buf):
                yield chunk
            for file_data in path:
                for chunk in self._serve_chunk(file_data):
                    yield chunk
            self.file_len += len(self.data)
            blocks, remainder = divmod(self.file_len, BLOCKSIZE)
            if remainder > 0:
                nulls = NUL * (BLOCKSIZE - remainder)
                for chunk in self._serve_chunk(nulls):
                    yield chunk
            self.file_len = 0
        if not self.append:
            if self.tar_iter:
                for data in self.tar_iter:
                    for chunk in self._serve_chunk(data):
                        yield chunk
            else:
                for chunk in self._serve_chunk(NUL * (BLOCKSIZE * 2)):
                    yield chunk
        if self.data:
            yield self.data


class ExtractedFile(object):

    def __init__(self, untar_stream):
        self.untar_stream = untar_stream
        self.data = ''

    def read(self, size=None):
        if size is None:
            size = self.untar_stream.to_write

        if size:
            if self.untar_stream.to_write:
                while len(self.data) < size:
                    chunk = self.untar_stream.get_file_chunk()
                    if not chunk:
                        result = self.data[:]
                        self.data = ''
                        return result
                    self.data += chunk
                    if self.untar_stream.to_write:
                        self.untar_stream.block = ''
                        try:
                            data = next(self.untar_stream.tar_iter)
                        except StopIteration:
                            result = self.data[:]
                            self.data = ''
                            return result
                        self.untar_stream.update_buffer(data)
            else:
                result = self.data[:]
                self.data = ''
                return result
            result = self.data[:size]
            self.data = self.data[size:]
            return result
        return ''


class UntarStream(object):

    def __init__(self, tar_iter, path_list=[], encoding=ENCODING,
                 errors=None):
        self.tar_iter = iter(tar_iter)
        self.path_list = path_list
        self.block = ''
        self.encoding = encoding
        self.errors = errors
        self.pax_headers = {}
        self.offset = 0
        self.offset_data = 0
        self.to_write = 0
        self.fp = None
        self.format = None

    def update_buffer(self, data):
        if self.block:
            self.block += data
        else:
            self.block = data

    def __iter__(self):
        while True:
            try:
                data = next(self.tar_iter)
            except StopIteration:
                break
            self.update_buffer(data)
            info = self.get_next_tarinfo()
            while info:
                if info.offset_data:
                    for f in self.path_list:
                        if info.name == f.name:
                            self.fp = f
                            break
                    self.to_write = info.size
                    self.offset_data = info.offset_data
                    while self.to_write:
                        if self.fp:
                            self.fp.write(self.get_file_chunk())
                            if not self.to_write:
                                self.fp.close()
                                self.fp = None
                        else:
                            self.skip_file_chunk()
                        if self.to_write:
                            self.block = ''
                            yield data
                            try:
                                data = next(self.tar_iter)
                            except StopIteration:
                                break
                            self.update_buffer(data)
                info = self.get_next_tarinfo()
            yield data

    def next_block(self, size=BLOCKSIZE):
        if size > len(self.block):
            return None
        stop = self.offset + size
        if stop > len(self.block):
            self.block = self.block[self.offset:]
            self.offset = 0
            return None
        start = self.offset
        self.offset = stop
        return self.block[start:stop]

    def read_tarinfo(self):
        buf = self.next_block()
        if not buf:
            return None
        tarinfo = TarInfo.frombuf(buf)
        tarinfo.offset = self.offset - BLOCKSIZE
        if tarinfo.type in (GNUTYPE_LONGNAME, GNUTYPE_LONGLINK):
            return tarinfo._proc_gnulong(self)
        elif tarinfo.type == GNUTYPE_SPARSE:
            return tarinfo._proc_sparse(self)
        elif tarinfo.type in (XHDTYPE, XGLTYPE, SOLARIS_XHDTYPE):
            return tarinfo._proc_pax(self)
        else:
            return tarinfo._proc_builtin(self)

    def write_file(self):
        chunk = self.get_file_chunk()
        if self.fp:
            self.fp.write(chunk)
            if not self.to_write:
                self.fp.close()
                self.fp = None

    def get_file_chunk(self):
        buf_size = len(self.block)
        eof = self.offset_data + self.to_write
        if eof <= buf_size:
            self.to_write = 0
            return self.block[self.offset_data:eof]
        start = self.offset_data
        self.offset_data = 0
        self.offset -= buf_size
        self.to_write = eof - buf_size
        return self.block[start:]

    def skip_file_chunk(self):
        buf_size = len(self.block)
        eof = self.offset_data + self.to_write
        if eof < buf_size:
            self.to_write = 0
            return
        self.offset_data = 0
        self.offset -= buf_size
        self.to_write = eof - buf_size

    def get_next_tarinfo(self):
        info = None
        while True:
            try:
                info = self.read_tarinfo()
            except EOFHeaderError:
                self.offset += BLOCKSIZE
                continue
            except InvalidHeaderError, e:
                if self.offset == 0:
                    raise ReadError(str(e))
                self.offset += BLOCKSIZE
                continue
            break
        if info:
            if info.magic == GNU_MAGIC:
                self.format = GNU_FORMAT
            elif info.magic == POSIX_MAGIC:
                self.format = USTAR_FORMAT
        return info

    def untar_file_iter(self):
        while self.to_write:
            yield self.get_file_chunk()
            if self.to_write:
                self.block = ''
                try:
                    data = next(self.tar_iter)
                except StopIteration:
                    break
                self.update_buffer(data)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print 'Usage: tarstream.py cf|xf <tar source> <tar dest> <filtered files>'
        exit()
    op = sys.argv.pop(1)
    src = sys.argv.pop(1)
    dst = sys.argv.pop(1)
    path_list = sys.argv[1:]
    chunk_size=65536

    if op not in ['cf', 'xf']:
        print 'Usage: tarstream.py cf|xf <tar source> <tar dest> <filtered files>'
    src_iter = None
    if src not in '-':
        src_iter = RegFile(src, chunk_size)
    dst_fp = open(dst, 'wb')
    if op in 'cf':
        path_list = [RegFile(path, chunk_size) for path in path_list]
        for data in TarStream(src_iter, path_list, chunk_size):
            dst_fp.write(data)
    elif op in 'xf':
        path_list = [open(path, 'wb') for path in path_list]
        for data in UntarStream(src_iter, path_list):
            dst_fp.write(data)
    dst_fp.close()
