#===============================================================================
# Copyright 2014 NetApp, Inc. All Rights Reserved,
# contribution by Jorge Mora <mora@netapp.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#===============================================================================
"""
File I/O module

Provides an interface to create and manipulate files of different types.
The arguments allow running for a specified period of time as well as running
multiple processes. Each process modifies a single file at a time and the
file name space is different for each process so there are no collisions
between two different processes modifying the same file.

File types:
  - Regular file
  - Hard link
  - Symbolic link

File operations:
  - Open (create or re-open)
  - Open downgrade
    This is done by opening the file for read and write, then the file is
    opened again as read only and finally closing the read and write file
    descriptor
  - Read (sequential or random access)
  - Write (sequential or random access)
  - Remove
  - Rename
  - Truncate (path or file descriptor)
  - Readdir
  - Lock
  - Unlock
  - Tlock
"""
import os
import re
import sys
import time
import errno
import fcntl
import ctypes
import signal
import struct
import formatstr
import traceback
import subprocess
from random import Random
import nfstest_config as c
from baseobj import BaseObj
from formatstr import str_units, int_units
from multiprocessing import Process,JoinableQueue

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.3"

# Default values
P_SEED       = None
P_NPROCS     = 1
P_RUNTIME    = 0
P_VERBOSE    = "none"
P_CREATELOG  = False
P_CREATELOGS = False
P_CREATE     = 5.0
P_OSYNC      = 10.0
P_FSYNC      = 2.0
P_READ       = 40.0
P_WRITE      = 40.0
P_RDWR       = 20.0
P_ODGRADE    = 5.0
P_RANDIO     = 50.0
P_RDWRONLY   = False
P_DIRECT     = False
P_TMPDIR     = "/tmp"
P_IODELAY    = 0.0

P_RENAME     = 5.0
P_REMOVE     = 5.0
P_TRUNC      = 2.0
P_FTRUNC     = 2.0
P_LINK       = 1.0
P_SLINK      = 0.2
P_READDIR    = 0.5
P_LOCK       = 20.0
P_UNLOCK     = 80.0
P_TLOCK      = 20.0
P_LOCKFULL   = 50.0

P_FILESIZE   = "1m"
P_FSIZEDEV   = "256k"
P_RSIZE      = "64k"
P_WSIZE      = "64k"
P_RSIZEDEV   = "8k"
P_WSIZEDEV   = "8k"
P_SIZEMULT   = "1.0"

# Minimum number of files to create before doing any other
# file operations like remove, rename, etc.
MIN_FILES = 10

# Mapping dictionaries
LOCKMAP = {
    fcntl.F_RDLCK: "RDLCK",
    fcntl.F_WRLCK: "WRLCK",
    fcntl.F_UNLCK: "UNLCK",
}

OPENMAP = {
    os.O_RDONLY: "O_RDONLY",
    os.O_WRONLY: "O_WRONLY",
    os.O_RDWR:   "O_RDWR",
    os.O_CREAT:  "O_CREAT",
    os.O_TRUNC:  "O_TRUNC",
    os.O_SYNC:   "O_SYNC",
}

class NoFilesMatchingCondition(Exception):
    """No files were found to match the given condition"""
    pass


class TermSignal(Exception):
    """Exception to be raised on SIGTERM signal"""
    pass

def stop_handler(signum, frame):
    """Signal handler to catch SIGTERM and allow for graceful termination
       of subprocesses
    """
    raise TermSignal("Terminating process!")

# File object
class FileObj(BaseObj): pass

class FileIO(BaseObj):
    """FileIO object

       Usage:
           from nfstest.file_io import FileIO

           # Instantiate FileIO object given top level directory
           x = FileIO(datadir="/tmp/data")

           # Run workload creating the top level directory if necessary
           x.run()
    """
    def __init__(self, **kwargs):
        """Constructor

           Initialize object's private data

           datadir:
               Top level directory where files will be created,
               it will be created if it does not exist
           seed:
               Seed to initialized the random number generator
               [default: automatically generated]
           nprocs:
               Number of processes to use [default: 1]
           runtime:
               Run time [default: 0 (indefinitely)]
           verbose:
               Verbose level: none|info|debug|dbg1-7|all [default: 'none']
           exiterr:
               Exit on first error [default: False]
           read:
               Read file percentage [default: 40.0]
           write:
               Write file percentage [default: 40.0]
           rdwr:
               Read/write file percentage [default: 20.0]
           randio:
               Random file access percentage [default: 50.0]
           iodelay:
               Seconds to delay I/O operations [default: 0.0]
           direct:
               Use direct I/O [default: False]
           rdwronly:
               Use read and write only, no rename, remove, etc. [default: False]
           create:
               Create file percentage [default: 5.0]
           odgrade:
               Open downgrade percentage [default: 5.0]
           osync:
               Open file with O_SYNC [default: 10.0]
           fsync:
               Percentage of fsync after write [default: 2.0]
           rename:
               Rename file percentage [default: 5.0]
           remove:
               Remove file percentage [default: 5.0]
           trunc:
               Truncate file percentage [default: 2.0]
           ftrunc:
               Truncate opened file percentage [default: 2.0]
           link:
               Create hard link percentage [default: 1.0]
           slink:
               Create symbolic link percentage [default: 0.2]
           readdir:
               List contents of directory percentage [default: 0.5]
           lock:
               Lock file percentage [default: 20.0]
           unlock:
               Unlock file percentage [default: 80.0]
           tlock:
               Lock test percentage [default: 20.0]
           lockfull:
               Lock full file percentage [default: 50.0]
           minfiles:
               Minimum number of files to create before any file operation
               is executed [default: 10]
           fsizeavg:
               File size average [default: 1m]
           fsizedev:
               File size standard deviation [default: 256k]
           rsize:
               Read block size [default: 64k]
           rsizedev:
               Read block size standard deviation [default: 8k]
           wsize:
               Write block size [default: 64k]
           wsizedev:
               Write block size standard deviation [default: 8k]
           sizemult:
               Size multiplier [default: 1.0]
           createlog:
               Create log file [default: False]
           createlogs:
               Create a log file for each process [default: False]
           logdir:
               Log directory [default: '/tmp']
        """
        self.progname   = os.path.basename(sys.argv[0])
        self.datadir    = kwargs.pop("datadir",    None)
        self.seed       = kwargs.pop("seed",       P_SEED)
        self.nprocs     = kwargs.pop("nprocs",     P_NPROCS)
        self.runtime    = kwargs.pop("runtime",    P_RUNTIME)
        self.verbose    = kwargs.pop("verbose",    P_VERBOSE)
        self.createlog  = kwargs.pop("createlog",  P_CREATELOG)
        self.createlogs = kwargs.pop("createlogs", P_CREATELOGS)
        self.create     = kwargs.pop("create",     P_CREATE)
        self.osync      = kwargs.pop("osync",      P_OSYNC)
        self.fsync      = kwargs.pop("fsync",      P_FSYNC)
        self.read       = kwargs.pop("read",       None)
        self.write      = kwargs.pop("write",      None)
        self.rdwr       = kwargs.pop("rdwr",       None)
        self.odgrade    = kwargs.pop("odgrade",    P_ODGRADE)
        self.randio     = kwargs.pop("randio",     P_RANDIO)
        self.rdwronly   = kwargs.pop("rdwronly",   P_RDWRONLY)
        self.iodelay    = kwargs.pop("iodelay",    P_IODELAY)
        self.direct     = kwargs.pop("direct",     P_DIRECT)
        self.logdir     = kwargs.pop("logdir",     P_TMPDIR)
        self.exiterr    = kwargs.pop("exiterr",    False)
        self.minfiles   = kwargs.pop("minfiles",   str(MIN_FILES))

        if self.datadir is None:
            print "Error: datadir is required"
            sys.exit(2)

        data = [int(x) for x in self.minfiles.split(",")]
        if len(data) == 1:
            self.up_minfiles = -1
            self.top_minfiles  = data[0]
            self.bot_minfiles  = data[0]
        elif len(data) > 1:
            self.up_minfiles = 0
            self.top_minfiles  = max(data)
            self.bot_minfiles  = min(data)
        else:
            print "Error: option minfiles must be an integer or two integers separated by a ',': %s" % self.minfiles
            sys.exit(2)
        self.minfiles = self.top_minfiles

        if self.rdwronly:
            # When rdwronly option is given, set all options for manipulating
            # files to zero if not explicitly given
            self.rename   = kwargs.pop("rename",   0)
            self.remove   = kwargs.pop("remove",   0)
            self.trunc    = kwargs.pop("trunc",    0)
            self.ftrunc   = kwargs.pop("ftrunc",   0)
            self.link     = kwargs.pop("link",     0)
            self.slink    = kwargs.pop("slink",    0)
            self.readdir  = kwargs.pop("readdir",  0)
            self.lock     = kwargs.pop("lock",     0)
            self.unlock   = kwargs.pop("unlock",   0)
            self.tlock    = kwargs.pop("tlock",    0)
            self.lockfull = kwargs.pop("lockfull", 0)
        else:
            self.rename   = kwargs.pop("rename",   P_RENAME)
            self.remove   = kwargs.pop("remove",   P_REMOVE)
            self.trunc    = kwargs.pop("trunc",    P_TRUNC)
            self.ftrunc   = kwargs.pop("ftrunc",   P_FTRUNC)
            self.link     = kwargs.pop("link",     P_LINK)
            self.slink    = kwargs.pop("slink",    P_SLINK)
            self.readdir  = kwargs.pop("readdir",  P_READDIR)
            self.lock     = kwargs.pop("lock",     P_LOCK)
            self.unlock   = kwargs.pop("unlock",   P_UNLOCK)
            self.tlock    = kwargs.pop("tlock",    P_TLOCK)
            self.lockfull = kwargs.pop("lockfull", P_LOCKFULL)

        # Get size multiplier
        sizemult = kwargs.pop("sizemult", P_SIZEMULT)
        if re.search("^[\d\.]+$", sizemult):
            self.sizemult = float(sizemult)
        else:
            self.sizemult = float(int_units(sizemult))
        # Convert sizes and apply multiplier
        self.fsizeavg  = int(self.sizemult * int_units(kwargs.pop("fsizeavg", P_FILESIZE)))
        self.fsizedev  = int(self.sizemult * int_units(kwargs.pop("fsizedev", P_FSIZEDEV)))
        self.rsize     = int(self.sizemult * int_units(kwargs.pop("rsize",    P_RSIZE)))
        self.wsize     = int(self.sizemult * int_units(kwargs.pop("wsize",    P_WSIZE)))
        self.rsizedev  = int(self.sizemult * int_units(kwargs.pop("rsizedev", P_RSIZEDEV)))
        self.wsizedev  = int(self.sizemult * int_units(kwargs.pop("wsizedev", P_WSIZEDEV)))

        if self.direct:
            # When using direct I/O, use fixed read/write block sizes
            self.rsizedev = 0
            self.wsizedev = 0

        # Initialize counters
        self.rbytes   = 0
        self.wbytes   = 0
        self.nopen    = 0
        self.nopendgr = 0
        self.nosync   = 0
        self.nclose   = 0
        self.nread    = 0
        self.nwrite   = 0
        self.nfsync   = 0
        self.nrename  = 0
        self.nremove  = 0
        self.ntrunc   = 0
        self.nftrunc  = 0
        self.nlink    = 0
        self.nslink   = 0
        self.nreaddir = 0
        self.nlock    = 0
        self.nunlock  = 0
        self.ntlock   = 0
        self.stime    = 0

        # Set read and write option percentages
        total = 100.0
        if self.rdwr is None:
            if self.read is None and self.write is None:
                # None of the read and write options are given, use defaults
                self.read  = P_READ
                self.write = P_WRITE
                self.rdwr  = P_RDWR
            elif self.read is None or self.write is None:
                # If only read or write is given, don't use rdwr
                self.rdwr = 0.0
            else:
                # If both read and write are given, set rdwr to add up to 100
                self.rdwr = max(0.0, total - self.read - self.write)
        else:
            # Option rdwr is given, calculate remainder left for read and write
            total -= self.rdwr

        if self.read is None and self.write is None:
            # Only rdwr is given, distribute remainder equally
            # between read and write
            self.read = total/2.0
            self.write = total - self.read
        elif self.read is None and self.write is not None:
            # Option rdwr and write are given, set read percentage
            self.read = total - self.write
        elif self.read is not None and self.write is None:
            # Option rdwr and read are given, set write percentage
            self.write = total - self.read

        # Verify read and write options add up to 100 percent
        total = abs(self.read) + abs(self.write) + abs(self.rdwr)
        if total != 100.0:
            print "Total for read, write and rdwr must be == 100"
            sys.exit(2)

        # Set verbose level mask
        self.debug_level(self.verbose)

        # Set timestamp format to include the date and time
        self.tstamp(fmt="{0:date:%Y-%m-%d %H:%M:%S.%q}  ")

        self.logbase = None
        if self.createlog or self.createlogs:
            # Create main log file
            datetimestr = self.timestamp("{0:date:%Y%m%d%H%M%S_%q}")
            logname = "%s_%s" % (self.progname, datetimestr)
            self.logbase = os.path.join(self.logdir, logname)
            self.logfile = self.logbase + ".log"
            self.open_log(self.logfile)

        # Multiprocessing
        self.tid   = 0
        self.queue = None

        # Memory buffers
        self.fbuffers = []
        self.PAGESIZE = os.sysconf(os.sysconf_names['SC_PAGESIZE'])

        # Load share library for calling C library functions
        try:
            # Linux
            self.libc = ctypes.CDLL('libc.so.6', use_errno=True)
        except:
            # MacOS
            self.libc = ctypes.CDLL('libc.dylib', use_errno=True)
        self.libc.malloc.argtypes = [ctypes.c_long]
        self.libc.malloc.restype = ctypes.c_void_p
        self.libc.posix_memalign.argtypes = [ctypes.POINTER(ctypes.c_void_p), ctypes.c_long, ctypes.c_long]
        self.libc.posix_memalign.restype = ctypes.c_int
        self.libc.read.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_long]
        self.libc.read.restype = ctypes.c_int
        self.libc.write.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_long]
        self.libc.write.restype = ctypes.c_int
        self.libc.lseek.argtypes = [ctypes.c_int, ctypes.c_long, ctypes.c_int]
        self.libc.lseek.restype = ctypes.c_long
        self.libc.memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_long]
        self.libc.memcpy.restype = ctypes.c_void_p

    def __del__(self):
        """Destructor"""
        if getattr(self, 'logfile', None):
            print "\nLogfile: %s" % self.logfile

    def _dprint(self, level, msg):
        """Local dprint function, if called from a subprocess send the
           message to the main process, otherwise use dprint on message
        """
        if self.queue and not self.createlogs:
            # Send message to main process
            self.queue.put([level,msg])
        else:
            # Display message and send it to the log file
            self.dprint(level, msg)

    def _get_tree(self):
        """Read top level directory for existing files to populate database
           This is used so it can be run in the same top level directory
           multiple times
        """
        for entry in os.listdir(self.datadir):
            # Must match file names given by _newname
            if not re.search(r'^f[\dA-F]+$', entry):
                continue
            # Get tid from file name
            tid = int(entry[1:self.bidx], 16)
            if self.tid != tid:
                continue
            # Get index from file name and set it
            index = int(entry[self.bidx:], 16)
            if self.n_index <= index:
                self.n_index = index + 1

            # Get file size and append it to database
            absfile = os.path.join(self.datadir, entry)
            try:
                fst = os.stat(absfile)
                size = fst.st_size
            except:
                size = 0
            fileobj = FileObj(name=entry, size=size)
            fileobj.debug_repr(1)
            if os.path.islink(absfile):
                fileobj.srcname = os.path.basename(os.readlink(absfile))
            self.n_files.append(fileobj)

    def _newname(self):
        """Create new file name"""
        name = "%s%06X" % (self.basename, self.n_index)
        self.n_index += 1
        return name

    def _percent(self, pvalue):
        """Test percent value"""
        if pvalue >= 100:
            return True
        elif pvalue <= 0:
            return False
        return self.random.randint(0,9999) < 100*pvalue

    def _get_fileobj(self, condition=None):
        """Get a random file object that fulfills condition"""
        files_matching_condition = [file_obj for file_obj in self.n_files if condition(file_obj)] if condition else self.n_files
        if len(files_matching_condition) == 0:
            raise NoFilesMatchingCondition()
        return self.random.choice(files_matching_condition)

    def _getiolist(self, size, iswrite):
        """Return list of I/O blocks to read/write"""
        iolist = []
        if iswrite:
            bsize = self.wsize
            bdev  = self.wsizedev
        else:
            bsize = self.rsize
            bdev  = self.rsizedev

        tsize = 0
        offset = 0
        while tsize < size:
            block = {}
            if self.direct:
                # Direct I/O uses same block size for all blocks
                blocksize = bsize
            else:
                # Buffered I/O uses different block sizes
                blocksize = int(abs(self.random.gauss(bsize, bdev)))
            if tsize + blocksize > size:
                # Use remaining bytes for last block
                blocksize = size - tsize
            iolist.append({'offset':offset, 'write':iswrite, 'size':blocksize})
            offset += blocksize
            tsize += blocksize

        return iolist

    def _mem_alloc(self, size, aligned=False):
        """Allocate memory for use in C library functions"""
        dbuffer = None
        if aligned:
            # Allocate aligned buffer
            dbuffer = ctypes.c_void_p()
            self.libc.posix_memalign(ctypes.byref(dbuffer), self.PAGESIZE, size)
        else:
            # Allocate regular buffer
            dbuffer = self.libc.malloc(size)
        # Add allocated buffer so it can be freed
        self.fbuffers.append(dbuffer)
        return dbuffer

    def _getlock(self, name, fd, lock_type=None, offset=0, length=0, lock=None, tlock=False):
        """Get byte range lock on file given by file descriptor"""
        rn = self.random.randint(0,9999)
        stype = fcntl.F_SETLK
        if lock_type == fcntl.F_UNLCK:
            lstr = "UNLOCK"
            if not lock or rn >= 100*self.unlock:
                # Do not unlock file
                return
            self.nunlock += 1
        else:
            if tlock:
                # Just do TLOCK
                lstr = "TLOCK "
                stype = fcntl.F_GETLK
                if rn >= 100*self.tlock:
                    # No lock, so no tlock
                    return
                self.ntlock += 1
            else:
                lstr = "LOCK  "
                if rn >= 100*self.lock:
                    # No lock
                    return
                self.nlock += 1
            if lock_type is None:
                # Choose lock: read or write
                if self._percent(50):
                    lock_type = fcntl.F_RDLCK
                else:
                    lock_type = fcntl.F_WRLCK
            if not tlock:
                # LOCK is requested, but do TLOCK before actual lock
                self._getlock(name, fd, lock_type=lock_type, offset=offset, length=length, lock=lock, tlock=True)
        fstr = ""
        if offset == 0 and length == 0 and lstr == "LOCK  ":
            fstr = " full file"
        self._dprint("DBG4", "%s  %s %d @ %d (%s)%s" % (lstr, name, length, offset, LOCKMAP[lock_type], fstr))
        lockdata = struct.pack('hhllhh', lock_type, 0, offset, length, 0, 0)
        return fcntl.fcntl(fd, stype, lockdata)

    def _do_io(self, **kwargs):
        """Read or write to the given file descriptor"""
        fd       = kwargs.pop("fd", None)
        write    = kwargs.pop("write", False)
        offset   = kwargs.pop("offset", 0)
        size     = kwargs.pop("size", 0)
        fileobj  = kwargs.pop("fileobj", None)
        lockfull = kwargs.pop("lockfull", True)
        lockout  = None

        if self.iodelay > 0.0:
            time.sleep(self.iodelay)

        # Set file offset to read/write
        os.lseek(fd, offset, os.SEEK_SET)

        if write:
            if self.random and not lockfull:
                # Lock file segment
                lockout = self._getlock(fileobj.name, fd, lock_type=fcntl.F_WRLCK, offset=offset, length=size)
            data = 'x' * size
            self._dprint("DBG5", "WRITE   %s %d @ %d" % (fileobj.name, size, offset))

            if self.direct:
                # Direct I/O -- use native write function
                count = self.libc.write(fd, self.wbuffer, size)
            else:
                # Buffered I/O
                count = os.write(fd, data)
                if self._percent(self.fsync):
                    self._dprint("DBG4", "FSYNC   %s" % fileobj.name)
                    self.nfsync += 1
                    os.fsync(fd)

            self.nwrite += 1
            self.wbytes += count
            fsize = offset + count
            if fileobj.size < fsize:
                fileobj.size = fsize
        else:
            if self.random and not lockfull:
                # Lock file segment
                lockout = self._getlock(fileobj.name, fd, lock_type=fcntl.F_RDLCK, offset=offset, length=size)
            self._dprint("DBG5", "READ    %s %d @ %d" % (fileobj.name, size, offset))

            if self.direct:
                # Direct I/O -- use native read function
                count = self.libc.read(fd, self.rbuffer, size)
            else:
                # Buffered I/O
                data = os.read(fd, size)
                count = len(data)
            self.rbytes += count
            self.nread += 1

        if self.random and not lockfull:
            # Unlock file segment
            self._getlock(fileobj.name, fd, lock_type=fcntl.F_UNLCK, offset=offset, length=size, lock=lockout)
        return count

    def _do_file(self):
        """Operate on a file, create, read, truncate, etc."""
        self.absfile = ""
        # Number of files available
        nlen = len(self.n_files)
        if self.up_minfiles == 0 and nlen > self.minfiles:
            self.minfiles = self.bot_minfiles
            self.up_minfiles = 1
        if self.up_minfiles > 0 and nlen < self.minfiles:
            self.minfiles = self.top_minfiles
            self.up_minfiles = 0

        if nlen > self.minfiles and self._percent(self.trunc):
            # Truncate file using the file name
            fileobj = self._get_fileobj()
            self.absfile = os.path.join(self.datadir, fileobj.name)
            # Choose new size at random
            nsize = self.random.randint(0, fileobj.size + self.wsizedev)
            self._dprint("DBG2", "TRUNC   %s %d -> %d" % (fileobj.name, fileobj.size, nsize))
            out = self.libc.truncate(self.absfile, nsize)
            if out == -1:
                err = ctypes.get_errno()
                if hasattr(fileobj, 'srcname') and err == errno.ENOENT:
                    # Make sure not to fail if it is a broken symbolic link
                    self._dprint("DBG2", "TRUNC   %s: broken symbolic link" % fileobj.name)
                    return
                raise OSError(err, os.strerror(err), fileobj.name)
            else:
                self.ntrunc += 1
                fileobj.size = nsize
            return

        if nlen > self.minfiles and self._percent(self.rename):
            # Rename file
            fileobj = self._get_fileobj()
            name = self._newname()
            self.absfile = os.path.join(self.datadir, fileobj.name)
            newfile = os.path.join(self.datadir, name)
            self._dprint("DBG2", "RENAME  %s -> %s" % (fileobj.name, name))
            os.rename(self.absfile, newfile)
            self.nrename += 1
            fileobj.name = name
            return

        if nlen > self.minfiles and self._percent(self.remove):
            # Remove file
            fileobj = self._get_fileobj()
            self.absfile = os.path.join(self.datadir, fileobj.name)
            self._dprint("DBG2", "REMOVE  %s" % fileobj.name)
            os.unlink(self.absfile)
            self.nremove += 1
            self.n_files.remove(fileobj)
            return

        if nlen > self.minfiles and self._percent(self.link):
            # Create hard link
            name = self._newname()
            self.absfile = os.path.join(self.datadir, name)
            try:
                fileobj = self._get_fileobj(condition=lambda f: not hasattr(f, 'srcname'))
            except NoFilesMatchingCondition:
                raise Exception("Unable to find a valid source file for hard link")
            srcfile = os.path.join(self.datadir, fileobj.name)
            self._dprint("DBG2", "LINK    %s -> %s" % (name, fileobj.name))
            os.link(srcfile, self.absfile)
            self.nlink += 1
            linkobj = FileObj(name=name, size=fileobj.size)
            self.n_files.append(linkobj)
            return

        if nlen > self.minfiles and self._percent(self.slink):
            # Create symbolic link
            name = self._newname()
            self.absfile = os.path.join(self.datadir, name)
            try:
                fileobj = self._get_fileobj(condition=lambda f: not hasattr(f, 'srcname'))
            except NoFilesMatchingCondition:
                raise Exception("Unable to find a valid source file for symbolic link")
            self._dprint("DBG2", "SLINK   %s -> %s" % (name, fileobj.name))
            os.symlink(fileobj.name, self.absfile)
            self.nslink += 1
            slinkobj = FileObj(name=name, size=fileobj.size, srcname=fileobj.name)
            self.n_files.append(slinkobj)
            return

        if nlen > self.minfiles and self._percent(self.readdir):
            # Read directory
            count = self.random.randint(1,99)
            self._dprint("DBG2", "READDIR %s maxentries: %d" % (self.datadir, count))
            self.absfile = self.datadir
            fd = self.libc.opendir(self.datadir)
            index = 0
            while True:
                dirent = self.libc.readdir(fd)
                if dirent == 0 or index >= count:
                    break
                index += 1
            out = self.libc.closedir(fd)
            self.nreaddir += 1
            return

        # Select type of open: read, write or rdwr
        total = self.read + self.write
        rn = self.random.randint(0,9999)
        if rn < 100*self.read:
            oflags = os.O_RDONLY
            oflist = ["O_RDONLY"]
        elif rn < 100*total:
            oflags = os.O_WRONLY
            oflist = ["O_WRONLY"]
        else:
            oflags = os.O_RDWR
            oflist = ["O_RDWR"]

        # Set create file flag
        if nlen < self.minfiles:
            # Create at least self.minfiles before any other operation
            cflag = True
        else:
            cflag = self._percent(self.create)

        if cflag:
            # Create new name
            name = self._newname()
            fileobj = FileObj(name=name, size=0)
            self.n_files.append(fileobj)
            if oflags == os.O_RDONLY:
                # Creating file, must be able to write
                oflags = os.O_WRONLY
                oflist = ["O_WRONLY"]
            oflags |= os.O_CREAT
            oflist.append("O_CREAT")
        else:
            # Use name chosen at random
            fileobj = self._get_fileobj()

        if "O_RDONLY" not in oflist and self._percent(self.osync):
            # Add O_SYNC flag when opening file for writing
            oflags |= os.O_SYNC
            oflist.append("O_SYNC")
            self.nosync += 1

        if self.direct:
            # Open file for direct I/O
            oflags |= os.O_DIRECT
            oflist.append("O_DIRECT")

        # Select random or sequential I/O
        sstr = "sequen"
        if self._percent(self.randio):
            sstr = "random"

        ostr = "|".join(oflist)

        fd = None
        index = 0
        is_symlink = False
        while fd is None:
            try:
                index += 1
                if hasattr(fileobj, 'srcname'):
                    is_symlink = True
                self.absfile = os.path.join(self.datadir, fileobj.name)
                self._dprint("DBG2", "OPEN    %s %s %s" % (fileobj.name, sstr, ostr))
                fd = os.open(self.absfile, oflags)
                st = os.fstat(fd)
                if is_symlink:
                    self._dprint("DBG6", "OPEN    %s inode:%d symlink" % (fileobj.name, st.st_ino))
                    absfile = os.path.join(self.datadir, fileobj.srcname)
                    st = os.stat(absfile)
                    self._dprint("DBG6", "OPEN    %s inode:%d src:%s" % (fileobj.name, st.st_ino, fileobj.srcname))
                else:
                    self._dprint("DBG6", "OPEN    %s inode:%d" % (fileobj.name, st.st_ino))
            except OSError as openerr:
                if is_symlink and openerr.errno == errno.ENOENT:
                    self._dprint("DBG2", "OPEN    %s: broken symbolic link" % fileobj.name)
                    if index >= 10:
                        # Do not exit execution, just return to select another operation
                        return
                    # Choose a new name at random
                    fileobj = self._get_fileobj()
                    is_symlink = False
                else:
                    # Unknown error
                    raise
        self.nopen += 1

        # Get file size for writing
        size = int(abs(self.random.gauss(self.fsizeavg, self.fsizedev)))

        odgrade = False
        if oflags & os.O_WRONLY == os.O_WRONLY:
            lock_type = fcntl.F_WRLCK
            iolist = self._getiolist(size, True)
        elif oflags & os.O_RDWR == os.O_RDWR:
            lock_type = None
            iolist  = self._getiolist(size, True)
            iolist += self._getiolist(size, False)
            if self._percent(self.odgrade):
                odgrade = True
        else:
            lock_type = fcntl.F_RDLCK
            size = fileobj.size
            if size == 0:
                # File does not have any data, at least try to read one block
                size = self.rsize
            iolist = self._getiolist(size, False)

        if sstr == "random":
            # Shuffle I/O list for random access
            self.random.shuffle(iolist)

        # Lock full file if necessary
        lockfull = False
        if self._percent(self.lockfull):
            lockfull = True
            lockfout = self._getlock(fileobj.name, fd, lock_type=lock_type, offset=0, length=0)

        if nlen > self.minfiles and "O_RDONLY" not in oflist and self._percent(self.ftrunc):
            # Truncate file using the file descriptor
            # Choose new size at random
            nsize = self.random.randint(0, fileobj.size + self.wsizedev)
            self._dprint("DBG2", "FTRUNC  %s %d -> %d" % (fileobj.name, fileobj.size, nsize))
            os.ftruncate(fd, nsize)
            self.nftrunc += 1
            fileobj.size = nsize

        # Read or write the file
        for item in iolist:
            if self.runtime > 0 and time.time() >= self.s_time + self.runtime:
                # Runtime has been reached
                break
            self._do_io(**dict(fd=fd, fileobj=fileobj, lockfull=lockfull, **item))

        if lockfull:
            # Unlock full file
            self._getlock(fileobj.name, fd, lock_type=fcntl.F_UNLCK, offset=0, length=0, lock=lockfout)

        fdr = None
        fdroffset = 0
        if odgrade:
            # Need for open downgrade:
            # First, the file has been opened for read and write
            # Second, open file again for reading
            # Then close read and write file descriptor
            self._dprint("DBG2", "OPENDGR %s" % fileobj.name)
            fdr = os.open(self.absfile, os.O_RDONLY)
            self.nopendgr += 1
            count = self._do_io(fd=fdr, offset=fdroffset, size=self.rsize, fileobj=fileobj)
            fdroffset += count

        # Close main file descriptor
        self._dprint("DBG3", "CLOSE   %s" % fileobj.name)
        os.close(fd)
        self.nclose += 1

        if odgrade:
            for i in xrange(10):
                count = self._do_io(fd=fdr, offset=fdroffset, size=self.rsize, fileobj=fileobj)
                fdroffset += count
            self._dprint("DBG3", "CLOSE   %s" % fileobj.name)
            os.close(fdr)
            self.nclose += 1

        return

    def get_mountpoint(self):
        """Get mount point from data directory"""
        path = self.datadir
        st1 = os.stat(path)
        while path != os.sep:
            # Get parent directory
            parpath = os.path.realpath(os.path.join(path, os.pardir))
            st2 = os.stat(parpath)
            # Compare device ids from current and parent directories
            if st1.st_dev != st2.st_dev:
                break;
            path = parpath
        return path

    def run_process(self, tid=0):
        """Main loop for each process"""
        ret = 0
        stime = time.time()
        self.tid = tid
        self.n_index = 1
        self.n_files = []
        self.s_time  = stime

        # Setup signal handler to gracefully terminate process
        signal.signal(signal.SIGTERM, stop_handler)

        # Set file base name according to the number processes
        self.bidx = 1 + max(2, len("{0:x}".format(max(0,self.nprocs-1))))
        self.basename = "f{0:0{width}X}".format(self.tid, width=self.bidx-1)

        if self.createlogs:
            # Open a log file for each process
            if self.nprocs <= 10:
                self.logfile = self.logbase + "_%d.log" % self.tid
            elif self.nprocs <= 100:
                self.logfile = self.logbase + "_%02d.log" % self.tid
            elif self.nprocs <= 1000:
                self.logfile = self.logbase + "_%03d.log" % self.tid
            else:
                self.logfile = self.logbase + "_%04d.log" % self.tid
            self.open_log(self.logfile)

        # Read top level directory and populate file database when
        # a previous instance was ran on the same top level directory
        self._get_tree()

        # Create random object and initialized seed for process
        self.random = Random()
        self.random.seed(self.seed + tid)

        if self.direct:
            # Round up to nearest PAGESIZE boundary
            rsize = self.rsize + (self.PAGESIZE - self.rsize)%self.PAGESIZE
            wsize = self.wsize + (self.PAGESIZE - self.wsize)%self.PAGESIZE
            self._dprint("DBG7", "Allocating aligned read buffer of size %d" % rsize)
            self.rbuffer = self._mem_alloc(rsize, aligned=True)
            self._dprint("DBG7", "Allocating aligned write buffer of size %d" % wsize)
            self.wbuffer = self._mem_alloc(wsize, aligned=True)
            pdata = ctypes.create_string_buffer('x' * wsize)
            self.libc.memcpy(self.wbuffer, pdata, wsize);

        count = 0
        while True:
            try:
                self._do_file()
            except TermSignal:
                # SIGTERM has been raised, so stop running and send stats
                break
            except Exception:
                errstr = "ERROR on file object %s (process #%d)\n" % (self.absfile, self.tid)
                errstr += "Directory i-node: %d\n" % self.datadir_st.st_ino
                ioerror = traceback.format_exc()
                self._dprint("INFO", errstr+ioerror)
                ret = 1
                break
            ctime = time.time()
            if self.runtime > 0 and ctime >= stime + self.runtime:
                # Runtime has been reached
                break
            count += 1
        if self.queue:
            # Send all counts to main process
            self.queue.put(["RBYTES",   self.rbytes])
            self.queue.put(["WBYTES",   self.wbytes])
            self.queue.put(["NOPEN",    self.nopen])
            self.queue.put(["NOPENDGR", self.nopendgr])
            self.queue.put(["NOSYNC",   self.nosync])
            self.queue.put(["NCLOSE",   self.nclose])
            self.queue.put(["NREAD",    self.nread])
            self.queue.put(["NWRITE",   self.nwrite])
            self.queue.put(["NFSYNC",   self.nfsync])
            self.queue.put(["NRENAME",  self.nrename])
            self.queue.put(["NREMOVE",  self.nremove])
            self.queue.put(["NTRUNC",   self.ntrunc])
            self.queue.put(["NFTRUNC",  self.nftrunc])
            self.queue.put(["NLINK",    self.nlink])
            self.queue.put(["NSLINK",   self.nslink])
            self.queue.put(["NREADDIR", self.nreaddir])
            self.queue.put(["NLOCK",    self.nlock])
            self.queue.put(["NTLOCK",   self.ntlock])
            self.queue.put(["NUNLOCK",  self.nunlock])
            self.queue.put(["RETVALUE", ret])

        if self.direct:
            self._dprint("DBG7", "Free data buffers")
            for dbuffer in self.fbuffers:
                self.libc.free(dbuffer)
        self.close_log()
        return ret

    def run(self):
        """Main function where all processes are started"""
        errors = 0
        if self.seed is None:
            # Create random seed
            self.seed = int(1000.0*time.time())

        self.dprint("INFO", "System:  %s" % " ".join(os.uname()))
        self.dprint("INFO", "Command: %s" % " ".join(sys.argv))

        # Main seed so run can be reproduced
        self.dprint("INFO", "SEED = %d" % self.seed)
        # Flush log file descriptor to make sure above info is not written
        # to all log files when using multiple logs for each subprocess
        self.flush_log()
        stime = time.time()

        if not os.path.exists(self.datadir):
            # Create top level directory if it does not exist
            os.mkdir(self.datadir, 0777)
        self.datadir_st = os.stat(self.datadir)

        # Get mount stats for mount point
        mtpoint = self.get_mountpoint()
        cmd = "mountstats %s" % mtpoint
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)
        pstdout, pstderr = process.communicate()
        for line in pstdout.split("\n"):
            regex = re.search("Stats for\s+(.*):", line)
            if regex:
                self.dprint("INFO", regex.group(1))
            else:
                regex = re.search("NFS mount options:.*", line)
                if regex:
                    self.dprint("INFO", regex.group(0))

        if self.nprocs > 1:
            # setup interprocess queue
            self.queue = JoinableQueue()
            processes = []
            for i in xrange(self.nprocs):
                # Run each subprocess with its own process id (tid)
                # The process id is used to set the random number generator
                # and also to have each process work with different files
                process = Process(target=self.run_process, kwargs={'tid':self.tid})
                processes.append(process)
                process.start()
                self.tid += 1
            done = False
            while not done:
                # Wait for a short time so main process does not hog the CPU
                # by checking the queue continuously
                time.sleep(0.1)
                while not self.queue.empty():
                    # Get any pending messages from any of the processes
                    level, msg = self.queue.get()
                    # Check if message is a valid count first
                    if level == "RBYTES":
                        self.rbytes += msg
                    elif level == "WBYTES":
                        self.wbytes += msg
                    elif level == "NOPEN":
                        self.nopen += msg
                    elif level == "NOPENDGR":
                        self.nopendgr += msg
                    elif level == "NOSYNC":
                        self.nosync += msg
                    elif level == "NCLOSE":
                        self.nclose += msg
                    elif level == "NREAD":
                        self.nread += msg
                    elif level == "NWRITE":
                        self.nwrite += msg
                    elif level == "NFSYNC":
                        self.nfsync += msg
                    elif level == "NRENAME":
                        self.nrename += msg
                    elif level == "NREMOVE":
                        self.nremove += msg
                    elif level == "NTRUNC":
                        self.ntrunc += msg
                    elif level == "NFTRUNC":
                        self.nftrunc += msg
                    elif level == "NLINK":
                        self.nlink += msg
                    elif level == "NSLINK":
                        self.nslink += msg
                    elif level == "NREADDIR":
                        self.nreaddir += msg
                    elif level == "NLOCK":
                        self.nlock += msg
                    elif level == "NTLOCK":
                        self.ntlock += msg
                    elif level == "NUNLOCK":
                        self.nunlock += msg
                    elif level == "RETVALUE":
                        if msg != 0:
                            errors += 1
                            if self.exiterr:
                                # Exit on first error
                                for process in list(processes):
                                    process.terminate()
                                break
                    else:
                        # Message is not any of the valid counts,
                        # so treat it as a debug message
                        self.dprint(level, msg)
                # Check if any process has finished
                for process in list(processes):
                    if not process.is_alive():
                        process.join()
                        if not self.exiterr and abs(process.exitcode):
                            errors += 1
                        processes.remove(process)
                        if len(processes) == 0:
                            done = True
                            break
        else:
            # Only one process to run, just run the function
            out = self.run_process(tid=self.tid)
            if out != 0:
                errors += 1
        # Set seed to make sure if this function is called again a different
        # set of operations will be called
        self.seed += self.nprocs
        delta = time.time() - stime

        # Display stats
        formatstr.UNIT_SEP = " "
        readbytes  = str_units(self.rbytes)
        readbps    = str_units(self.rbytes/delta)
        writebytes = str_units(self.wbytes)
        writebps   = str_units(self.wbytes/delta)
        self.dprint("INFO", "==================STATS===================")
        self.dprint("INFO", "OPEN:    % 7d" % self.nopen)
        self.dprint("INFO", "OPENDGR: % 7d" % self.nopendgr)
        self.dprint("INFO", "CLOSE:   % 7d" % self.nclose)
        self.dprint("INFO", "OSYNC:   % 7d" % self.nosync)
        self.dprint("INFO", "READ:    % 7d, % 10s, % 10s/s" % (self.nread, readbytes, readbps))
        self.dprint("INFO", "WRITE:   % 7d, % 10s, % 10s/s" % (self.nwrite, writebytes, writebps))
        self.dprint("INFO", "FSYNC:   % 7d" % self.nfsync)
        self.dprint("INFO", "RENAME:  % 7d" % self.nrename)
        self.dprint("INFO", "REMOVE:  % 7d" % self.nremove)
        self.dprint("INFO", "TRUNC:   % 7d" % self.ntrunc)
        self.dprint("INFO", "FTRUNC:  % 7d" % self.nftrunc)
        self.dprint("INFO", "LINK:    % 7d" % self.nlink)
        self.dprint("INFO", "SLINK:   % 7d" % self.nslink)
        self.dprint("INFO", "READDIR: % 7d" % self.nreaddir)
        self.dprint("INFO", "LOCK:    % 7d" % self.nlock)
        self.dprint("INFO", "TLOCK:   % 7d" % self.ntlock)
        self.dprint("INFO", "UNLOCK:  % 7d" % self.nunlock)
        if errors > 0:
            self.dprint("INFO", "ERRORS:  % 7d" % errors)
        self.dprint("INFO", "TIME:    % 7d secs" % delta)
