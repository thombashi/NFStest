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
# Generated by process_xdr.py from nfs4.x on Wed Aug 19 13:23:07 2015
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "4.0"

# Enum nfs_bool
FALSE = 0
TRUE  = 1

nfs_bool = {
    0 : "FALSE",
    1 : "TRUE",
}

# Sizes
NFS4_FHSIZE        = 128
NFS4_VERIFIER_SIZE = 8
NFS4_OPAQUE_LIMIT  = 1024
NFS4_OTHER_SIZE    = 12

# Enum nfs_ftype4
NF4REG       = 1  # Regular File
NF4DIR       = 2  # Directory
NF4BLK       = 3  # Special File - block device
NF4CHR       = 4  # Special File - character device
NF4LNK       = 5  # Symbolic Link
NF4SOCK      = 6  # Special File - socket
NF4FIFO      = 7  # Special File - fifo
NF4ATTRDIR   = 8  # Attribute Directory
NF4NAMEDATTR = 9  # Named Attribute

nfs_ftype4 = {
    1 : "NF4REG",
    2 : "NF4DIR",
    3 : "NF4BLK",
    4 : "NF4CHR",
    5 : "NF4LNK",
    6 : "NF4SOCK",
    7 : "NF4FIFO",
    8 : "NF4ATTRDIR",
    9 : "NF4NAMEDATTR",
}

# Enum nfsstat4
NFS4_OK                     = 0      # everything is okay
NFS4ERR_PERM                = 1      # caller not privileged
NFS4ERR_NOENT               = 2      # no such file/directory
NFS4ERR_IO                  = 5      # hard I/O error
NFS4ERR_NXIO                = 6      # no such device
NFS4ERR_ACCESS              = 13     # access denied
NFS4ERR_EXIST               = 17     # file already exists
NFS4ERR_XDEV                = 18     # different filesystems
# Unused/reserved                   19
NFS4ERR_NOTDIR              = 20     # should be a directory
NFS4ERR_ISDIR               = 21     # should not be directory
NFS4ERR_INVAL               = 22     # invalid argument
NFS4ERR_FBIG                = 27     # file exceeds server max
NFS4ERR_NOSPC               = 28     # no space on filesystem
NFS4ERR_ROFS                = 30     # read-only filesystem
NFS4ERR_MLINK               = 31     # too many hard links
NFS4ERR_NAMETOOLONG         = 63     # name exceeds server max
NFS4ERR_NOTEMPTY            = 66     # directory not empty
NFS4ERR_DQUOT               = 69     # hard quota limit reached
NFS4ERR_STALE               = 70     # file no longer exists
NFS4ERR_BADHANDLE           = 10001  # Illegal filehandle
NFS4ERR_BAD_COOKIE          = 10003  # READDIR cookie is stale
NFS4ERR_NOTSUPP             = 10004  # operation not supported
NFS4ERR_TOOSMALL            = 10005  # response limit exceeded
NFS4ERR_SERVERFAULT         = 10006  # undefined server error
NFS4ERR_BADTYPE             = 10007  # type invalid for CREATE
NFS4ERR_DELAY               = 10008  # file "busy" - retry
NFS4ERR_SAME                = 10009  # nverify says attrs same
NFS4ERR_DENIED              = 10010  # lock unavailable
NFS4ERR_EXPIRED             = 10011  # lock lease expired
NFS4ERR_LOCKED              = 10012  # I/O failed due to lock
NFS4ERR_GRACE               = 10013  # in grace period
NFS4ERR_FHEXPIRED           = 10014  # filehandle expired
NFS4ERR_SHARE_DENIED        = 10015  # share reserve denied
NFS4ERR_WRONGSEC            = 10016  # wrong security flavor
NFS4ERR_CLID_INUSE          = 10017  # clientid in use
NFS4ERR_RESOURCE            = 10018  # resource exhaustion
NFS4ERR_MOVED               = 10019  # filesystem relocated
NFS4ERR_NOFILEHANDLE        = 10020  # current FH is not set
NFS4ERR_MINOR_VERS_MISMATCH = 10021  # minor vers not supp
NFS4ERR_STALE_CLIENTID      = 10022  # server has rebooted
NFS4ERR_STALE_STATEID       = 10023  # server has rebooted
NFS4ERR_OLD_STATEID         = 10024  # state is out of sync
NFS4ERR_BAD_STATEID         = 10025  # incorrect stateid
NFS4ERR_BAD_SEQID           = 10026  # request is out of seq.
NFS4ERR_NOT_SAME            = 10027  # verify - attrs not same
NFS4ERR_LOCK_RANGE          = 10028  # overlapping lock range
NFS4ERR_SYMLINK             = 10029  # should be file/directory
NFS4ERR_RESTOREFH           = 10030  # no saved filehandle
NFS4ERR_LEASE_MOVED         = 10031  # some filesystem moved
NFS4ERR_ATTRNOTSUPP         = 10032  # recommended attr not sup
NFS4ERR_NO_GRACE            = 10033  # reclaim outside of grace
NFS4ERR_RECLAIM_BAD         = 10034  # reclaim error at server
NFS4ERR_RECLAIM_CONFLICT    = 10035  # conflict on reclaim
NFS4ERR_BADXDR              = 10036  # XDR decode failed
NFS4ERR_LOCKS_HELD          = 10037  # file locks held at CLOSE
NFS4ERR_OPENMODE            = 10038  # conflict in OPEN and I/O
NFS4ERR_BADOWNER            = 10039  # owner translation bad
NFS4ERR_BADCHAR             = 10040  # utf-8 char not supported
NFS4ERR_BADNAME             = 10041  # name not supported
NFS4ERR_BAD_RANGE           = 10042  # lock range not supported
NFS4ERR_LOCK_NOTSUPP        = 10043  # no atomic up/downgrade
NFS4ERR_OP_ILLEGAL          = 10044  # undefined operation
NFS4ERR_DEADLOCK            = 10045  # file locking deadlock
NFS4ERR_FILE_OPEN           = 10046  # open file blocks op.
NFS4ERR_ADMIN_REVOKED       = 10047  # lockowner state revoked
NFS4ERR_CB_PATH_DOWN        = 10048  # callback path down

nfsstat4 = {
        0 : "NFS4_OK",
        1 : "NFS4ERR_PERM",
        2 : "NFS4ERR_NOENT",
        5 : "NFS4ERR_IO",
        6 : "NFS4ERR_NXIO",
       13 : "NFS4ERR_ACCESS",
       17 : "NFS4ERR_EXIST",
       18 : "NFS4ERR_XDEV",
       20 : "NFS4ERR_NOTDIR",
       21 : "NFS4ERR_ISDIR",
       22 : "NFS4ERR_INVAL",
       27 : "NFS4ERR_FBIG",
       28 : "NFS4ERR_NOSPC",
       30 : "NFS4ERR_ROFS",
       31 : "NFS4ERR_MLINK",
       63 : "NFS4ERR_NAMETOOLONG",
       66 : "NFS4ERR_NOTEMPTY",
       69 : "NFS4ERR_DQUOT",
       70 : "NFS4ERR_STALE",
    10001 : "NFS4ERR_BADHANDLE",
    10003 : "NFS4ERR_BAD_COOKIE",
    10004 : "NFS4ERR_NOTSUPP",
    10005 : "NFS4ERR_TOOSMALL",
    10006 : "NFS4ERR_SERVERFAULT",
    10007 : "NFS4ERR_BADTYPE",
    10008 : "NFS4ERR_DELAY",
    10009 : "NFS4ERR_SAME",
    10010 : "NFS4ERR_DENIED",
    10011 : "NFS4ERR_EXPIRED",
    10012 : "NFS4ERR_LOCKED",
    10013 : "NFS4ERR_GRACE",
    10014 : "NFS4ERR_FHEXPIRED",
    10015 : "NFS4ERR_SHARE_DENIED",
    10016 : "NFS4ERR_WRONGSEC",
    10017 : "NFS4ERR_CLID_INUSE",
    10018 : "NFS4ERR_RESOURCE",
    10019 : "NFS4ERR_MOVED",
    10020 : "NFS4ERR_NOFILEHANDLE",
    10021 : "NFS4ERR_MINOR_VERS_MISMATCH",
    10022 : "NFS4ERR_STALE_CLIENTID",
    10023 : "NFS4ERR_STALE_STATEID",
    10024 : "NFS4ERR_OLD_STATEID",
    10025 : "NFS4ERR_BAD_STATEID",
    10026 : "NFS4ERR_BAD_SEQID",
    10027 : "NFS4ERR_NOT_SAME",
    10028 : "NFS4ERR_LOCK_RANGE",
    10029 : "NFS4ERR_SYMLINK",
    10030 : "NFS4ERR_RESTOREFH",
    10031 : "NFS4ERR_LEASE_MOVED",
    10032 : "NFS4ERR_ATTRNOTSUPP",
    10033 : "NFS4ERR_NO_GRACE",
    10034 : "NFS4ERR_RECLAIM_BAD",
    10035 : "NFS4ERR_RECLAIM_CONFLICT",
    10036 : "NFS4ERR_BADXDR",
    10037 : "NFS4ERR_LOCKS_HELD",
    10038 : "NFS4ERR_OPENMODE",
    10039 : "NFS4ERR_BADOWNER",
    10040 : "NFS4ERR_BADCHAR",
    10041 : "NFS4ERR_BADNAME",
    10042 : "NFS4ERR_BAD_RANGE",
    10043 : "NFS4ERR_LOCK_NOTSUPP",
    10044 : "NFS4ERR_OP_ILLEGAL",
    10045 : "NFS4ERR_DEADLOCK",
    10046 : "NFS4ERR_FILE_OPEN",
    10047 : "NFS4ERR_ADMIN_REVOKED",
    10048 : "NFS4ERR_CB_PATH_DOWN",
}

# Enum time_how4
SET_TO_SERVER_TIME4 = 0
SET_TO_CLIENT_TIME4 = 1

time_how4 = {
    0 : "SET_TO_SERVER_TIME4",
    1 : "SET_TO_CLIENT_TIME4",
}

# Various Access Control Entry definitions
#
# Mask that indicates which Access Control Entries are supported.
# Values for the fattr4_aclsupport attribute.
ACL4_SUPPORT_ALLOW_ACL          = 0x00000001
ACL4_SUPPORT_DENY_ACL           = 0x00000002
ACL4_SUPPORT_AUDIT_ACL          = 0x00000004
ACL4_SUPPORT_ALARM_ACL          = 0x00000008

# acetype4 values, others can be added as needed.
ACE4_ACCESS_ALLOWED_ACE_TYPE    = 0x00000000
ACE4_ACCESS_DENIED_ACE_TYPE     = 0x00000001
ACE4_SYSTEM_AUDIT_ACE_TYPE      = 0x00000002
ACE4_SYSTEM_ALARM_ACE_TYPE      = 0x00000003

# ACE flag values
ACE4_FILE_INHERIT_ACE           = 0x00000001
ACE4_DIRECTORY_INHERIT_ACE      = 0x00000002
ACE4_NO_PROPAGATE_INHERIT_ACE   = 0x00000004
ACE4_INHERIT_ONLY_ACE           = 0x00000008
ACE4_SUCCESSFUL_ACCESS_ACE_FLAG = 0x00000010
ACE4_FAILED_ACCESS_ACE_FLAG     = 0x00000020
ACE4_IDENTIFIER_GROUP           = 0x00000040

# ACE mask values
ACE4_READ_DATA                  = 0x00000001
ACE4_LIST_DIRECTORY             = 0x00000001
ACE4_WRITE_DATA                 = 0x00000002
ACE4_ADD_FILE                   = 0x00000002
ACE4_APPEND_DATA                = 0x00000004
ACE4_ADD_SUBDIRECTORY           = 0x00000004
ACE4_READ_NAMED_ATTRS           = 0x00000008
ACE4_WRITE_NAMED_ATTRS          = 0x00000010
ACE4_EXECUTE                    = 0x00000020
ACE4_DELETE_CHILD               = 0x00000040
ACE4_READ_ATTRIBUTES            = 0x00000080
ACE4_WRITE_ATTRIBUTES           = 0x00000100
ACE4_DELETE                     = 0x00010000
ACE4_READ_ACL                   = 0x00020000
ACE4_WRITE_ACL                  = 0x00040000
ACE4_WRITE_OWNER                = 0x00080000
ACE4_SYNCHRONIZE                = 0x00100000

# ACE4_GENERIC_READ -- defined as combination of
#      ACE4_READ_ACL |
#      ACE4_READ_DATA |
#      ACE4_READ_ATTRIBUTES |
#      ACE4_SYNCHRONIZE
ACE4_GENERIC_READ               = 0x00120081

# ACE4_GENERIC_WRITE -- defined as combination of
#      ACE4_READ_ACL |
#      ACE4_WRITE_DATA |
#      ACE4_WRITE_ATTRIBUTES |
#      ACE4_WRITE_ACL |
#      ACE4_APPEND_DATA |
#      ACE4_SYNCHRONIZE
ACE4_GENERIC_WRITE              = 0x00160106

# ACE4_GENERIC_EXECUTE -- defined as combination of
#      ACE4_READ_ACL
#      ACE4_READ_ATTRIBUTES
#      ACE4_EXECUTE
#      ACE4_SYNCHRONIZE
ACE4_GENERIC_EXECUTE            = 0x001200A0

# Field definitions for the fattr4_mode attribute
MODE4_SUID = 0x800  # set user id on execution
MODE4_SGID = 0x400  # set group id on execution
MODE4_SVTX = 0x200  # save text even after use
MODE4_RUSR = 0x100  # read permission: owner
MODE4_WUSR = 0x080  # write permission: owner
MODE4_XUSR = 0x040  # execute permission: owner
MODE4_RGRP = 0x020  # read permission: group
MODE4_WGRP = 0x010  # write permission: group
MODE4_XGRP = 0x008  # execute permission: group
MODE4_ROTH = 0x004  # read permission: other
MODE4_WOTH = 0x002  # write permission: other
MODE4_XOTH = 0x001  # execute permission: other

# Enum stable_how4
UNSTABLE4  = 0
DATA_SYNC4 = 1
FILE_SYNC4 = 2

stable_how4 = {
    0 : "UNSTABLE4",
    1 : "DATA_SYNC4",
    2 : "FILE_SYNC4",
}

# Values for fattr4_fh_expire_type
FH4_PERSISTENT         = 0x00000000
FH4_NOEXPIRE_WITH_OPEN = 0x00000001
FH4_VOLATILE_ANY       = 0x00000002
FH4_VOL_MIGRATION      = 0x00000004
FH4_VOL_RENAME         = 0x00000008

# Enum nfs_fattr4

# Mandatory Attributes
FATTR4_SUPPORTED_ATTRS   = 0
FATTR4_TYPE              = 1
FATTR4_FH_EXPIRE_TYPE    = 2
FATTR4_CHANGE            = 3
FATTR4_SIZE              = 4
FATTR4_LINK_SUPPORT      = 5
FATTR4_SYMLINK_SUPPORT   = 6
FATTR4_NAMED_ATTR        = 7
FATTR4_FSID              = 8
FATTR4_UNIQUE_HANDLES    = 9
FATTR4_LEASE_TIME        = 10
FATTR4_RDATTR_ERROR      = 11
FATTR4_FILEHANDLE        = 19

# Recommended Attributes
FATTR4_ACL               = 12
FATTR4_ACLSUPPORT        = 13
FATTR4_ARCHIVE           = 14
FATTR4_CANSETTIME        = 15
FATTR4_CASE_INSENSITIVE  = 16
FATTR4_CASE_PRESERVING   = 17
FATTR4_CHOWN_RESTRICTED  = 18
FATTR4_FILEID            = 20
FATTR4_FILES_AVAIL       = 21
FATTR4_FILES_FREE        = 22
FATTR4_FILES_TOTAL       = 23
FATTR4_FS_LOCATIONS      = 24
FATTR4_HIDDEN            = 25
FATTR4_HOMOGENEOUS       = 26
FATTR4_MAXFILESIZE       = 27
FATTR4_MAXLINK           = 28
FATTR4_MAXNAME           = 29
FATTR4_MAXREAD           = 30
FATTR4_MAXWRITE          = 31
FATTR4_MIMETYPE          = 32
FATTR4_MODE              = 33
FATTR4_NO_TRUNC          = 34
FATTR4_NUMLINKS          = 35
FATTR4_OWNER             = 36
FATTR4_OWNER_GROUP       = 37
FATTR4_QUOTA_AVAIL_HARD  = 38
FATTR4_QUOTA_AVAIL_SOFT  = 39
FATTR4_QUOTA_USED        = 40
FATTR4_RAWDEV            = 41
FATTR4_SPACE_AVAIL       = 42
FATTR4_SPACE_FREE        = 43
FATTR4_SPACE_TOTAL       = 44
FATTR4_SPACE_USED        = 45
FATTR4_SYSTEM            = 46
FATTR4_TIME_ACCESS       = 47
FATTR4_TIME_ACCESS_SET   = 48
FATTR4_TIME_BACKUP       = 49
FATTR4_TIME_CREATE       = 50
FATTR4_TIME_DELTA        = 51
FATTR4_TIME_METADATA     = 52
FATTR4_TIME_MODIFY       = 53
FATTR4_TIME_MODIFY_SET   = 54
FATTR4_MOUNTED_ON_FILEID = 55

nfs_fattr4 = {
     0 : "FATTR4_SUPPORTED_ATTRS",
     1 : "FATTR4_TYPE",
     2 : "FATTR4_FH_EXPIRE_TYPE",
     3 : "FATTR4_CHANGE",
     4 : "FATTR4_SIZE",
     5 : "FATTR4_LINK_SUPPORT",
     6 : "FATTR4_SYMLINK_SUPPORT",
     7 : "FATTR4_NAMED_ATTR",
     8 : "FATTR4_FSID",
     9 : "FATTR4_UNIQUE_HANDLES",
    10 : "FATTR4_LEASE_TIME",
    11 : "FATTR4_RDATTR_ERROR",
    19 : "FATTR4_FILEHANDLE",
    12 : "FATTR4_ACL",
    13 : "FATTR4_ACLSUPPORT",
    14 : "FATTR4_ARCHIVE",
    15 : "FATTR4_CANSETTIME",
    16 : "FATTR4_CASE_INSENSITIVE",
    17 : "FATTR4_CASE_PRESERVING",
    18 : "FATTR4_CHOWN_RESTRICTED",
    20 : "FATTR4_FILEID",
    21 : "FATTR4_FILES_AVAIL",
    22 : "FATTR4_FILES_FREE",
    23 : "FATTR4_FILES_TOTAL",
    24 : "FATTR4_FS_LOCATIONS",
    25 : "FATTR4_HIDDEN",
    26 : "FATTR4_HOMOGENEOUS",
    27 : "FATTR4_MAXFILESIZE",
    28 : "FATTR4_MAXLINK",
    29 : "FATTR4_MAXNAME",
    30 : "FATTR4_MAXREAD",
    31 : "FATTR4_MAXWRITE",
    32 : "FATTR4_MIMETYPE",
    33 : "FATTR4_MODE",
    34 : "FATTR4_NO_TRUNC",
    35 : "FATTR4_NUMLINKS",
    36 : "FATTR4_OWNER",
    37 : "FATTR4_OWNER_GROUP",
    38 : "FATTR4_QUOTA_AVAIL_HARD",
    39 : "FATTR4_QUOTA_AVAIL_SOFT",
    40 : "FATTR4_QUOTA_USED",
    41 : "FATTR4_RAWDEV",
    42 : "FATTR4_SPACE_AVAIL",
    43 : "FATTR4_SPACE_FREE",
    44 : "FATTR4_SPACE_TOTAL",
    45 : "FATTR4_SPACE_USED",
    46 : "FATTR4_SYSTEM",
    47 : "FATTR4_TIME_ACCESS",
    48 : "FATTR4_TIME_ACCESS_SET",
    49 : "FATTR4_TIME_BACKUP",
    50 : "FATTR4_TIME_CREATE",
    51 : "FATTR4_TIME_DELTA",
    52 : "FATTR4_TIME_METADATA",
    53 : "FATTR4_TIME_MODIFY",
    54 : "FATTR4_TIME_MODIFY_SET",
    55 : "FATTR4_MOUNTED_ON_FILEID",
}

# Enum nfs_opnum4
OP_ACCESS              = 3
OP_CLOSE               = 4
OP_COMMIT              = 5
OP_CREATE              = 6
OP_DELEGPURGE          = 7
OP_DELEGRETURN         = 8
OP_GETATTR             = 9
OP_GETFH               = 10
OP_LINK                = 11
OP_LOCK                = 12
OP_LOCKT               = 13
OP_LOCKU               = 14
OP_LOOKUP              = 15
OP_LOOKUPP             = 16
OP_NVERIFY             = 17
OP_OPEN                = 18
OP_OPENATTR            = 19
OP_OPEN_CONFIRM        = 20
OP_OPEN_DOWNGRADE      = 21
OP_PUTFH               = 22
OP_PUTPUBFH            = 23
OP_PUTROOTFH           = 24
OP_READ                = 25
OP_READDIR             = 26
OP_READLINK            = 27
OP_REMOVE              = 28
OP_RENAME              = 29
OP_RENEW               = 30
OP_RESTOREFH           = 31
OP_SAVEFH              = 32
OP_SECINFO             = 33
OP_SETATTR             = 34
OP_SETCLIENTID         = 35
OP_SETCLIENTID_CONFIRM = 36
OP_VERIFY              = 37
OP_WRITE               = 38
OP_RELEASE_LOCKOWNER   = 39
# Illegal operation
OP_ILLEGAL             = 10044

nfs_opnum4 = {
        3 : "OP_ACCESS",
        4 : "OP_CLOSE",
        5 : "OP_COMMIT",
        6 : "OP_CREATE",
        7 : "OP_DELEGPURGE",
        8 : "OP_DELEGRETURN",
        9 : "OP_GETATTR",
       10 : "OP_GETFH",
       11 : "OP_LINK",
       12 : "OP_LOCK",
       13 : "OP_LOCKT",
       14 : "OP_LOCKU",
       15 : "OP_LOOKUP",
       16 : "OP_LOOKUPP",
       17 : "OP_NVERIFY",
       18 : "OP_OPEN",
       19 : "OP_OPENATTR",
       20 : "OP_OPEN_CONFIRM",
       21 : "OP_OPEN_DOWNGRADE",
       22 : "OP_PUTFH",
       23 : "OP_PUTPUBFH",
       24 : "OP_PUTROOTFH",
       25 : "OP_READ",
       26 : "OP_READDIR",
       27 : "OP_READLINK",
       28 : "OP_REMOVE",
       29 : "OP_RENAME",
       30 : "OP_RENEW",
       31 : "OP_RESTOREFH",
       32 : "OP_SAVEFH",
       33 : "OP_SECINFO",
       34 : "OP_SETATTR",
       35 : "OP_SETCLIENTID",
       36 : "OP_SETCLIENTID_CONFIRM",
       37 : "OP_VERIFY",
       38 : "OP_WRITE",
       39 : "OP_RELEASE_LOCKOWNER",
    10044 : "OP_ILLEGAL",
}

ACCESS4_READ    = 0x00000001
ACCESS4_LOOKUP  = 0x00000002
ACCESS4_MODIFY  = 0x00000004
ACCESS4_EXTEND  = 0x00000008
ACCESS4_DELETE  = 0x00000010
ACCESS4_EXECUTE = 0x00000020

# Enum nfs_lock_type4
READ_LT   = 1
WRITE_LT  = 2
READW_LT  = 3  # blocking read
WRITEW_LT = 4  # blocking write

nfs_lock_type4 = {
    1 : "READ_LT",
    2 : "WRITE_LT",
    3 : "READW_LT",
    4 : "WRITEW_LT",
}

# Enum createmode4
UNCHECKED4 = 0
GUARDED4   = 1
EXCLUSIVE4 = 2

createmode4 = {
    0 : "UNCHECKED4",
    1 : "GUARDED4",
    2 : "EXCLUSIVE4",
}

# Enum opentype4
OPEN4_NOCREATE = 0
OPEN4_CREATE   = 1

opentype4 = {
    0 : "OPEN4_NOCREATE",
    1 : "OPEN4_CREATE",
}

# Enum limit_by4
NFS_LIMIT_SIZE   = 1
NFS_LIMIT_BLOCKS = 2

limit_by4 = {
    1 : "NFS_LIMIT_SIZE",
    2 : "NFS_LIMIT_BLOCKS",
}

# Share Access and Deny constants for open argument
OPEN4_SHARE_ACCESS_READ                               = 0x00000001
OPEN4_SHARE_ACCESS_WRITE                              = 0x00000002
OPEN4_SHARE_ACCESS_BOTH                               = 0x00000003
OPEN4_SHARE_DENY_NONE                                 = 0x00000000
OPEN4_SHARE_DENY_READ                                 = 0x00000001
OPEN4_SHARE_DENY_WRITE                                = 0x00000002
OPEN4_SHARE_DENY_BOTH                                 = 0x00000003
# New flags for share_access field of OPEN4args
OPEN4_SHARE_ACCESS_WANT_DELEG_MASK                    = 0xFF00
OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE                 = 0x0000
OPEN4_SHARE_ACCESS_WANT_READ_DELEG                    = 0x0100
OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG                   = 0x0200
OPEN4_SHARE_ACCESS_WANT_ANY_DELEG                     = 0x0300
OPEN4_SHARE_ACCESS_WANT_NO_DELEG                      = 0x0400
OPEN4_SHARE_ACCESS_WANT_CANCEL                        = 0x0500
OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL = 0x10000
OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED   = 0x20000

# Enum open_delegation_type4
OPEN_DELEGATE_NONE  = 0
OPEN_DELEGATE_READ  = 1
OPEN_DELEGATE_WRITE = 2

open_delegation_type4 = {
    0 : "OPEN_DELEGATE_NONE",
    1 : "OPEN_DELEGATE_READ",
    2 : "OPEN_DELEGATE_WRITE",
}

# Enum open_claim_type4

# Not a reclaim.
CLAIM_NULL          = 0
CLAIM_PREVIOUS      = 1
CLAIM_DELEGATE_CUR  = 2
CLAIM_DELEGATE_PREV = 3

open_claim_type4 = {
    0 : "CLAIM_NULL",
    1 : "CLAIM_PREVIOUS",
    2 : "CLAIM_DELEGATE_CUR",
    3 : "CLAIM_DELEGATE_PREV",
}
# Result flags
#
# Client must confirm open
OPEN4_RESULT_CONFIRM        = 0x00000002
# Type of file locking behavior at the server
OPEN4_RESULT_LOCKTYPE_POSIX = 0x00000004

# Enum nfs_secflavor4
AUTH_NONE  = 0
AUTH_SYS   = 1
RPCSEC_GSS = 6

nfs_secflavor4 = {
    0 : "AUTH_NONE",
    1 : "AUTH_SYS",
    6 : "RPCSEC_GSS",
}

# Enum rpc_gss_svc_t
RPC_GSS_SVC_NONE      = 1
RPC_GSS_SVC_INTEGRITY = 2
RPC_GSS_SVC_PRIVACY   = 3

rpc_gss_svc_t = {
    1 : "RPC_GSS_SVC_NONE",
    2 : "RPC_GSS_SVC_INTEGRITY",
    3 : "RPC_GSS_SVC_PRIVACY",
}

# Enum nfs_cb_opnum4
OP_CB_GETATTR = 3
OP_CB_RECALL  = 4
# Illegal callback operation
OP_CB_ILLEGAL = 10044

nfs_cb_opnum4 = {
        3 : "OP_CB_GETATTR",
        4 : "OP_CB_RECALL",
    10044 : "OP_CB_ILLEGAL",
}
