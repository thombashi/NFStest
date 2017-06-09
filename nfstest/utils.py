#===============================================================================
# Copyright 2015 NetApp, Inc. All Rights Reserved,
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
Utilities module

Definition for common classes and constants
"""
import os
import nfstest_config as c
from baseobj import BaseObj

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2015 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

# Constants for file type
FTYPE_FILE       = 0 # Regular file
FTYPE_SP_OFFSET  = 1 # Sparse file (write data to offset only)
FTYPE_SP_ZERO    = 2 # Sparse file (write zeros on hole)
FTYPE_SP_DEALLOC = 3 # Sparse file (use deallocate to create holes)

# Space reservation constants
SR_ALLOCATE   = 0 # Allocate
SR_DEALLOCATE = 3 # FALLOC_FL_KEEP_SIZE|FALLOC_FL_PUNCH_HOLE

# Sparse file constants
SP_HOLE = 0 # Hole segment
SP_DATA = 1 # Data segment

SEEK_DATA = 3 # Seek for the next data segment with lseek()
SEEK_HOLE = 4 # Seek for the next hole with lseek()

SEEKmap = {
    SEEK_DATA: "SEEK_DATA",
    SEEK_HOLE: "SEEK_HOLE",
}

def split_path(path):
    """Return list of components in path"""
    ret = os.path.normpath(path).split(os.sep)
    # Remove leading empty component and "." entry
    while len(ret) and ret[0] in ("", "."):
        ret.pop(0)
    return ret

class SparseFile(BaseObj):
    """SparseFile object

       SparseFile() -> New sparse file object

       Usage:
           # Create definition for a sparse file of size 10000 having
           # two holes of size 1000 at offsets 3000 and 6000
           x = SparseFile("/mnt/t/file1", 10000, [3000, 6000], 1000)

           # Object attributes defined after creation using the above
           # sample data:

           # endhole: set to True if the file ends with a hole
           # Above example ends with data so,
           # x.endhole = False

           # data_offsets: list of data segment offsets
           # x.data_offsets = [0, 4000, 7000]

           # hole_offsets: list of hole segment offsets including the
           #   implicit hole at the end of the file
           # x.hole_offsets = [3000, 6000, 10000]

           # sparse_data: list of data/hole segments, each item in the list
           #   has the following format [offset, size, type]
           # x.sparse_data = [[0, 3000, 1], [3000, 1000, 0], [4000, 2000, 1],
           #                  [6000, 1000, 0], [7000, 3000, 1]]
    """
    def __init__(self, absfile, file_size, hole_list, hole_size):
        """Create sparse file object definition, the file is not created
           just the object. Object attributes are defined which makes it
           easy to create the actual file.

           absfile:
               Absolute path name of file
           file_size:
               Total size of sparse file
           hole_list:
               List of hole offsets
           hole_size:
               Size for each hole
        """
        self.filename  = os.path.basename(absfile)
        self.absfile   = absfile
        self.filesize  = file_size
        self.hole_list = hole_list
        self.hole_size = hole_size

        if hole_list[-1] < file_size and hole_list[-1] + hole_size >= file_size:
            # File ends with a hole
            self.endhole = True
        else:
            # File ends with data
            self.endhole = False

        # List of hole offsets
        self.hole_offsets = list(hole_list)

        if not self.endhole:
            # Include the implicit hole at the end of the file
            self.hole_offsets += [file_size]

        # List of data offsets
        self.data_offsets = []
        # List of data and hole segments
        self.sparse_data = []
        if hole_list[0] > 0:
            # There is data at the beginning of the file
            self.data_offsets.append(0)
            self.sparse_data.append([0, hole_list[0], SP_DATA])
        idx = 0
        for offset in hole_list:
            # Append hole segment
            self.sparse_data.append([offset, hole_size, SP_HOLE])
            endhole_offset = offset + hole_size
            if endhole_offset < file_size:
                self.data_offsets.append(endhole_offset)
                if idx == len(hole_list) - 1:
                    # Data segment is up to the end of the file
                    size = file_size - endhole_offset
                else:
                    # Data segment is up to the start of next hole
                    size = hole_list[idx+1] - endhole_offset
                # Append data segment
                self.sparse_data.append([endhole_offset, size, SP_DATA])
            idx += 1
