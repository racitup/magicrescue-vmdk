#!/usr/bin/python3
# python3 script to read and verify vmware vmdk files
# only supports hosted product vmdks and not ESXi COW vmdks
# info taken from vmdk_50_technote.pdf from vmware.com
# Supports only vmdk version 1 files
#
# NOTES: Header capacity field and descriptor geometry (cyl*heads*sectors)
# should equate to the same (huge) number of sectors (typically 1GB or 100GB)
# and should match the sum of the extents
# magicrescue pipes data in from stdin, passes output filename as $1
# mr expects two functions: extract and then an optional rename
# the rename expects the new filename as stdout: RENAME file.ext
#
# Licensed under GPL-3.0
# Copyright (c) 2017 Richard Case

from struct import Struct, pack
from collections import OrderedDict
from contextlib import contextmanager
import sys, io, re, string, math, array

NUMGTESPERGTv1 = 512
# sizes in bytes
SECTOR_SIZE = 512
GTE_SIZE = GDE_SIZE = 4
# size in sectors
GRAINSIZEv1 = 128
DESCRIPTORSIZE = 20

# Helper class
class Peeker:
    """Wrapper for stdin that implements proper peeking"""
    def __init__(self, fileobj):
        self.fileobj = fileobj
        self.buf = io.BytesIO()

    def _append_to_buf(self, contents):
        oldpos = self.buf.tell()
        self.buf.seek(0, io.SEEK_END)
        self.buf.write(contents)
        self.buf.seek(oldpos)

    def _buffered(self):
        oldpos = self.buf.tell()
        data = self.buf.read()
        self.buf.seek(oldpos)
        return data

    def peek(self, size):
        buf = self._buffered()[:size]
        if len(buf) < size:
            contents = self.fileobj.read(size - len(buf))
            self._append_to_buf(contents)
            return self._buffered()
        return buf

    def read(self, size=None):
        if size is None:
            contents = self.buf.read() + self.fileobj.read()
            self.buf = io.BytesIO()
            return contents
        contents = self.buf.read(size)
        if len(contents) < size:
            contents += self.fileobj.read(size - len(contents))
            self.buf = io.BytesIO()
        return contents

    def readline(self):
        line = self.buf.readline()
        if not line.endswith(b'\n'):
            line += self.fileobj.readline()
            self.buf = io.BytesIO()
        return line

    def close(self):
        self.buf = None
        self.fileobj = None

class SparseExtentHeader:
    """Reads/creates/checks typical vmdk binary header"""
    _structfmt = (
        'I'     #uint32       magicNumber
        'I'     #uint32       version
        'I'     #uint32       flags
        'I'     #SectorType   capacity;
        'I'     #SectorType   grainSize
        'I'     #SectorType   descriptorOffset
        'I'     #SectorType   descriptorSize
        'I'     #uint32       numGTEsPerGT
        'I'     #SectorType   rgdOffset
        'I'     #SectorType   gdOffset
        'I'     #SectorType   overHead
        '?'     #Bool         uncleanShutdown
        'c'     #char         singleEndLineChar
        'c'     #char         nonEndLineChar
        'c'     #char         doubleEndLineChar1
        'c'     #char         doubleEndLineChar2
        'H'     #uint16       compressAlgorithm
        '433s'  #uint8        pad[433]
    )
    _structle = '<'     # little-endian
    _structbe = '>'     # big-endian
    # typical defaults
    #SPARSE_MAGICNUMBER = 0x564d444b
    magicNumber = 0x564d444b
    version = 1
    # valid newline test & redundant grain table:
    _flags = 3
    grainSize = 0
    # typically 128 but you need to create the descriptor:
    descriptorOffset = 0
    descriptorSize = 0
    rgdOffset = 0
    # if gdOffset = 20, numGTEsPerGT = 1
    gdOffset = 0
    numGTEsPerGT = 0
    overHead = 0
    uncleanShutdown = False
    # typical values differ from document, see flags bit0:
    #singleEndLineChar = b'\n'
    #nonEndLineChar = b' '
    #doubleEndLineChar1 = b'\r'
    #doubleEndLineChar2 = b'\n'
    singleEndLineChar = b'\x02'
    nonEndLineChar = b'\x00'
    doubleEndLineChar1 = b'\x00'
    # can also be \x01:
    doubleEndLineChar2 = b'\x15'
    compressAlgorithm = 0
    pad = [0] * 433

    def __init__(self, reader=None):
        """Create from file stream or create manually"""
        # try both little endian and big endian
        for self.endian in [self._structle, self._structbe]:
            self.hstruct = Struct(self.endian + self._structfmt)
            if isinstance(reader, Peeker):
                hdata = reader.peek(self.hstruct.size)
            elif reader is None:
                # copy defaults to self
                for tup in vars(SparseExtentHeader).items():
                    if not callable(tup[1]) and tup[0][0] != '_':
                        setattr(self, tup[0], tup[1])
                return
            else:
                raise TypeError("SparseHeader: Input is not a Peeker")

            (self.magicNumber,
            self.version,
            self._flags,
            self.capacity,
            self.grainSize,
            self.descriptorOffset,
            self.descriptorSize,
            self.numGTEsPerGT,
            self.rgdOffset,
            self.gdOffset,
            self.overHead,
            self.uncleanShutdown,
            self.singleEndLineChar,
            self.nonEndLineChar,
            self.doubleEndLineChar1,
            self.doubleEndLineChar2,
            self.compressAlgorithm,
            self.pad) = self.hstruct.unpack(hdata[:self.hstruct.size])

            try:
                self.check()
            except ValueError:
                if self.endian == self._structbe:
                    raise
            else:
                break

    def check(self):
        """Checks the validity of the data"""
        if self.magicNumber != SparseExtentHeader.magicNumber:
            magicstring = pack(self.endian + 'I', self.magicNumber).decode('utf8')
            raise ValueError("SparseHeader: Wrong MAGIC number: {}".format(magicstring))
        if self.version in [1, 2, 3]:
            if self.version != 1:
                raise NotImplementedError("SparseHeader: This library only supports vmdk v1, {} found".format(self.version))
        else:
            raise ValueError("SparseHeader: Wrong VERSION number: {}".format(self.version))
        if (self.singleEndLineChar != SparseExtentHeader.singleEndLineChar or
            self.nonEndLineChar != SparseExtentHeader.nonEndLineChar or
            self.doubleEndLineChar1 != SparseExtentHeader.doubleEndLineChar1):
            raise UserWarning("SparseHeader: Endline character comparison failed")

    def info(self):
        """Return a dict describing the header sorted by type and key name"""
        desc = OrderedDict(sorted(vars(self).items(), key=lambda t: str(type(t[1])) + t[0]))
        del desc['hstruct']
        del desc['pad']
        del desc['singleEndLineChar']
        del desc['nonEndLineChar']
        del desc['doubleEndLineChar1']
        del desc['doubleEndLineChar2']
        desc['flags'] = self.flags
        return desc

    def pack(self):
        """Pack the data back into a byte string"""
        return self.hstruct.pack(
            self.magicNumber,
            self.version,
            self._flags,
            self.capacity,
            self.grainSize,
            self.descriptorOffset,
            self.descriptorSize,
            self.numGTEsPerGT,
            self.rgdOffset,
            self.gdOffset,
            self.overHead,
            self.uncleanShutdown,
            self.singleEndLineChar,
            self.nonEndLineChar,
            self.doubleEndLineChar1,
            self.doubleEndLineChar2,
            self.compressAlgorithm,
            self.pad)

    @property
    def flags(self):
        """Read the flags integer as bool list"""
        s = '{:032b}'.format(self._flags)
        return [bool(int(c)) for c in reversed(s)]

printable_chars = bytes(string.printable, 'ascii')
def isascii(b):
    """Check whether the passed byte is an ascii character"""
    return b in printable_chars

def istext(data, forward=True):
    """
    Check whether the passed byte string is text
    Returns a tuple of:
        (True, None) if all bytes are ascii
        (False, The index of the first found non-ascii byte)
    Can be run forward or backward, if backward the index will be negative
    """
    start = 0 if forward else -1
    step = 1 if forward else -1
    stop = len(data) if forward else -len(data)
    for i in range(start, stop, step):
        if not isascii(data[i]):
            return (False, i)
    return (True, None)

def findtext(data, minsize=256, searchsects=2, sectsize=SECTOR_SIZE):
    """
    finds the start and end of a block of text embedded within binary bytes
    text must start on a sector boundary and be at least minsize
    returns a tuple of the start and end character indexes. If the end is
    not followed by a non-ascii byte, the second value will be None
    If insufficient text is found the first value will also be None
    """
    # search for start
    for start in range(0, searchsects * sectsize, sectsize):
        (isalltext, index) = istext(data[start:start + minsize])
        if isalltext:
            break
    else:
        return (None, None)

    # search for end
    (isalltext, index) = istext(data[start:])
    if isalltext:
        return (start, None)
    else:
        return (start, start + index)

class VMDKDescriptor:
    """Reads the descriptor"""
    # newline \n 0x0A is at the end of a line
    # run not case-sensitive: (?i)
    _regex_values = r"(?i)([a-z.]+) *= *(([\"']?)[\w -]+\3)\n".encode('utf8')
    _regex_extent = (r"(?i)(RW|RDONLY|NOACCESS) +"
                     r"(\d+) +"
                     r"(\w+) +"
                     r"(([\"]?)[\w \\/.'()~`\[\]{}=+&^%$#@!-]+\5) *"
                     r"(\d*)\n").encode('utf8')
    _extent_keys = ['access', 'size', 'type', 'filepath', 'offset']
    _searchsects = 2

    def __init__(self, reader):
        """Read descriptor from reader trying multiple sector positions"""
        if isinstance(reader, Peeker):
            ddata = reader.peek((DESCRIPTORSIZE + 1) * SECTOR_SIZE)
            start, end = findtext(ddata, searchsects=self._searchsects, sectsize=SECTOR_SIZE)
            self.offset = start
            self.size = len(ddata)
            self.textonly = False

            if start is None:
                raise ValueError("Descriptor: Insufficient text found")
            elif start == 0:
                self.textonly = True

            if end:
                self.size = end - start

            #print(ddata)
            self.values = self._values(ddata)
            self.extents = self._extents(ddata)
        else:
            raise TypeError("Descriptor: Input is not a Peeker")

    def _values(self, data):
        """Find all values"""
        if not getattr(self, '_valre', None):
            self._valre = re.compile(self._regex_values)
        results = self._valre.findall(data)
        if results:
            vals = OrderedDict()
            for tup in results:
                key = tup[0].decode('utf8')
                value = tup[1].decode('utf8').strip("'\"")
                for base in [10, 16]:
                    try:
                        value = int(value, base)
                    except ValueError:
                        continue
                    else:
                        break
                vals[key] = value
            return vals
        else:
            raise ValueError("Descriptor: No VALUES found")

    def _extents(self, data):
        """Find all extents"""
        if not getattr(self, '_extre', None):
            self._extre = re.compile(self._regex_extent)
        results = self._extre.findall(data)
        if results:
            vals = []
            for tup in results:
                vals += [(  tup[0].decode('utf8'),
                            int(tup[1].decode('utf8')),
                            tup[2].decode('utf8'),
                            tup[3].decode('utf8').strip("'\""),
                            int(tup[5].decode('utf8') if tup[5] else 0)
                    )]
            return vals
        else:
            raise ValueError("Descriptor: No EXTENTS found")

    def info(self):
        """returns the 'public' variables"""
        return dict(tup for tup in vars(self).items() if not tup[0].startswith('_'))

    def get_extentdict(self, index=0):
        """return a dict describing the extent, defaults to first"""
        if self.extents:
            return dict(zip(self._extent_keys, self.extents[index]))
        else:
            return None

def vmdk_lastoffset(reader, start, size):
    """
    scans the sparse grain table for the greatest offset
    input parameters are in sectors
    offset is in sectors from the beginning of the file
    """
    end = (start + size) * SECTOR_SIZE
    alldata = reader.peek(end)
    gtdata = alldata[start * SECTOR_SIZE:end]
    # uint32
    gtarray = array.array('I')
    gtarray.frombytes(gtdata)
    return max(gtarray)

def vmdk_print(header, descriptor):
    """prints the header and descriptor info"""
    if header:
        print("Header: {}".format(header.info()))
    if descriptor:
        print("Descriptor: {}".format(descriptor.info()))

def vmdk_info(reader, verbose=False):
    """returns header and descriptor if found"""
    # descriptor
    try:
        descriptor = VMDKDescriptor(reader)
    except ValueError as e:
        descriptor = None
        if verbose:
            print(e, file=sys.stderr)
    else:
        if descriptor.textonly:
            return (None, descriptor)

    # header - input is not valid if header is not detected
    try:
        header = SparseExtentHeader(reader)
    except Exception as e:
        header = None
        if verbose:
            print(e, file=sys.stderr)

    return (header, descriptor)

def vmdk_size(reader, header, descriptor, verbose=False):
    """finds the size of the vmdk in bytes"""
    data_sectors = None
    extent = None

    if descriptor:
        if descriptor.textonly:
            return descriptor.size, None
        elif descriptor.extents:
            extent = descriptor.get_extentdict()
            data_sectors = extent['size']
        else:
            cyls = int(descriptor.values['ddb.geometry.cylinders'])
            heads = int(descriptor.values['ddb.geometry.heads'])
            sects = int(descriptor.values['ddb.geometry.sectors'])
            data_sectors = cyls * heads * sects

    if not data_sectors:
        data_sectors = header.capacity

    # Calculate metadata sectors (grain directories and grain tables)
    if extent:
        if 'SPARSE' in extent['type']:
            pass
        elif 'FLAT' in extent['type']:
            raise NotImplementedError("Flat extent type with a header is undefined")
        else:
            raise NotImplementedError("Extent type not supported: {}".format(extent['type']))

    # if file has a SparseExtentHeader, it is by definition sparse
    # flat files don't have a header

    grainsects = GRAINSIZEv1 if header.grainSize == 0 else header.grainSize
    numgtespergt = NUMGTESPERGTv1 if header.numGTEsPerGT in [0, 1] else header.numGTEsPerGT
    # bit 1: redundant grain table will be used
    metadata_copies = 2 if header.flags[1] else 1
    descsize = DESCRIPTORSIZE if descriptor else 0

    # number of grain table entries, GTEs e.g. 209715200 / 128 = 1638400
    GTEs_grains = data_sectors // grainsects
    # number of grain directory entries, GDEs e.g. 1638400 / 512 = 3200
    GTs_GDEs = math.ceil(GTEs_grains / numgtespergt)
    # Grain Table size in sectors e.g. ceil((512 * 4) / SECTOR_SIZE) = 4
    GTsize = math.ceil((numgtespergt * GTE_SIZE) / SECTOR_SIZE)
    # Grain Directory size in sectors e.g. ceil((3200 * 4) / 512) = 25
    GDsize = math.ceil((GTs_GDEs * GDE_SIZE) / SECTOR_SIZE)

    # metadata size in sectors e.g. (4 * 3200) + 25 = 12825
    metasize = (GTsize * GTs_GDEs) + GDsize
    # total header size in sectors e.g. 1 + 20 + 12825 * 2 = 25671
    headersize = 1 + descsize + (metasize * metadata_copies)
    # data starts on grainsize boundary e.g. ceil(25671 / 128) * 128 = 201 * 128 = 25728
    headersects = math.ceil(headersize / grainsects) * grainsects

    # working grain table start
    GTstart = 1 + descsize + metasize + GDsize

    if verbose:
        print("Offsets: header: {:#010x}, descriptor: {:#010x}, "
                "RGD: {:#010x}, RGTs: {:#010x}, "
                "GD: {:#010x}, GTs: {:#010x}, Data: {:#010x}".format(
                    0, 1*SECTOR_SIZE,
                    (1+descsize)*SECTOR_SIZE, (1+descsize+GDsize)*SECTOR_SIZE,
                    (1+descsize+metasize)*SECTOR_SIZE, GTstart*SECTOR_SIZE,
                    headersects*SECTOR_SIZE
                ))

    # Get last grain offset from working grain table
    offset = vmdk_lastoffset(reader, GTstart, GTsize * GTs_GDEs)

    # final offset calculation:
    if offset:
        # offset + grainsize
        size = offset + grainsects
    else:
        size = headersects

    return size * SECTOR_SIZE, grainsects * SECTOR_SIZE

def vmdk_name(descriptor):
    """return the vmdk filename, or return None"""
    if descriptor:
        extent = descriptor.get_extentdict()
        diskname = extent['filepath']
        if descriptor.textonly:
            tup = diskname.rpartition('-')
            return tup[0] + '.vmdk'
        else:
            return diskname
    return None

@contextmanager
def stdin():
    """returns a stdin reader with proper peek"""
    reader = Peeker(sys.stdin.buffer)
    try:
        yield reader
    finally:
        reader.close()

def vmdk_extract():
    """extract the vmdk to arg1, if vmdk data found"""
    with stdin() as reader:
        header, descriptor = vmdk_info(reader, verbose=True)
        if header or descriptor:
            size, grainsize = vmdk_size(reader, header, descriptor)
            with open(sys.argv[1], mode='wb') as writer:
                if grainsize:
                    for i in range(0, size, grainsize):
                        grain = reader.read(grainsize)
                        writer.write(grain)
                else:
                    writer.write(reader.read(size))

def vmdk_debug():
    """prints debug information about the vmdk"""
    with stdin() as reader:
        header, descriptor = vmdk_info(reader, verbose=True)
        if header or descriptor:
            vmdk_print(header, descriptor)
            size, grainsize = vmdk_size(reader, header, descriptor, verbose=True)
            name = vmdk_name(descriptor)
            print('Size: {0}/{0:#010x}, name: {1}'.format(size, name))

# magicrescue compatible extract and rename operations
if __name__ == '__main__':
    if len(sys.argv) == 1:
        vmdk_debug()
    else:
        # if $1 file exists, extraction has already been run and must be a rename operation
        try:
            with open(sys.argv[1], mode='rb') as fd:
                reader = Peeker(fd)
                header, descriptor = vmdk_info(reader)
                name = vmdk_name(descriptor)
            # may not retrieve name if descriptor is not present
            if name:
                print("RENAME {}".format(name))
            sys.exit()
        # otherwise extract the file from stdin
        except FileNotFoundError:
            pass
        vmdk_extract()

