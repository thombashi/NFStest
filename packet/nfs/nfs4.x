/*
 * Copyright (c) 2016 IETF Trust and the persons identified
 * as the authors.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the
 * following conditions are met:
 *
 * - Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 * - Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *
 * - Neither the name of Internet Society, IETF or IETF
 *   Trust, nor the names of specific contributors, may be
 *   used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
 *   AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO
 *   EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 *   LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 *   NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *   SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 *   INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 *   OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
 *   IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *   ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This code was derived from RFC 7863.
 *
 *  Copyright (C) The IETF Trust (2007-2014)
 *  All Rights Reserved.
 *
 *  Copyright (C) The Internet Society (1998-2006).
 *  All Rights Reserved.
 *
 *=====================================================================
 * This Document was changed to add directives for converting
 * it to python code. Also the name of some variables were
 * changed to be consistent throughout this document and to
 * have a similar interface with earlier versions of NFS.
 *=====================================================================
 */

/* COPYRIGHT: 2014 */
/* VERSION: "4.2" */

/*
 * Constants
 */
enum bool {
    FALSE = 0,
    TRUE  = 1
};

/*
 * Sizes
 */
const NFS4_FHSIZE               = 128;
const NFS4_VERIFIER_SIZE        = 8;
const NFS4_OPAQUE_LIMIT         = 1024;
const NFS4_OTHER_SIZE           = 12;

/* Sizes new to NFSv4.1 */
const NFS4_SESSIONID_SIZE       = 16;
const NFS4_DEVICEID4_SIZE       = 16;
const NFS4_INT64_MAX            = 0x7fffffffffffffff;
const NFS4_UINT64_MAX           = 0xffffffffffffffff;
const NFS4_INT32_MAX            = 0x7fffffff;
const NFS4_UINT32_MAX           = 0xffffffff;

/*
 * File types
 */
enum nfs_ftype4 {
    NF4REG         = 1,    /* Regular File */
    NF4DIR         = 2,    /* Directory */
    NF4BLK         = 3,    /* Special File - block device */
    NF4CHR         = 4,    /* Special File - character device */
    NF4LNK         = 5,    /* Symbolic Link */
    NF4SOCK        = 6,    /* Special File - socket */
    NF4FIFO        = 7,    /* Special File - fifo */
    NF4ATTRDIR     = 8,    /* Attribute Directory */
    NF4NAMEDATTR   = 9     /* Named Attribute */
};

/*
 * Error status
 */
enum nfsstat4 {
    NFS4_OK                            = 0,    /* everything is okay      */
    NFS4ERR_PERM                       = 1,    /* caller not privileged   */
    NFS4ERR_NOENT                      = 2,    /* no such file/directory  */
    NFS4ERR_IO                         = 5,    /* hard I/O error          */
    NFS4ERR_NXIO                       = 6,    /* no such device          */
    NFS4ERR_ACCESS                     = 13,   /* access denied           */
    NFS4ERR_EXIST                      = 17,   /* file already exists     */
    NFS4ERR_XDEV                       = 18,   /* different filesystems   */
    /* Unused/reserved                   19 */
    NFS4ERR_NOTDIR                     = 20,   /* should be a directory   */
    NFS4ERR_ISDIR                      = 21,   /* should not be directory */
    NFS4ERR_INVAL                      = 22,   /* invalid argument        */
    NFS4ERR_FBIG                       = 27,   /* file exceeds server max */
    NFS4ERR_NOSPC                      = 28,   /* no space on filesystem  */
    NFS4ERR_ROFS                       = 30,   /* read-only filesystem    */
    NFS4ERR_MLINK                      = 31,   /* too many hard links     */
    NFS4ERR_NAMETOOLONG                = 63,   /* name exceeds server max */
    NFS4ERR_NOTEMPTY                   = 66,   /* directory not empty     */
    NFS4ERR_DQUOT                      = 69,   /* hard quota limit reached*/
    NFS4ERR_STALE                      = 70,   /* file no longer exists   */
    NFS4ERR_BADHANDLE                  = 10001,/* Illegal filehandle      */
    NFS4ERR_BAD_COOKIE                 = 10003,/* READDIR cookie is stale */
    NFS4ERR_NOTSUPP                    = 10004,/* operation not supported */
    NFS4ERR_TOOSMALL                   = 10005,/* response limit exceeded */
    NFS4ERR_SERVERFAULT                = 10006,/* undefined server error  */
    NFS4ERR_BADTYPE                    = 10007,/* type invalid for CREATE */
    NFS4ERR_DELAY                      = 10008,/* file "busy" - retry     */
    NFS4ERR_SAME                       = 10009,/* nverify says attrs same */
    NFS4ERR_DENIED                     = 10010,/* lock unavailable        */
    NFS4ERR_EXPIRED                    = 10011,/* lock lease expired      */
    NFS4ERR_LOCKED                     = 10012,/* I/O failed due to lock  */
    NFS4ERR_GRACE                      = 10013,/* in grace period         */
    NFS4ERR_FHEXPIRED                  = 10014,/* filehandle expired      */
    NFS4ERR_SHARE_DENIED               = 10015,/* share reserve denied    */
    NFS4ERR_WRONGSEC                   = 10016,/* wrong security flavor   */
    NFS4ERR_CLID_INUSE                 = 10017,/* clientid in use         */

    /* NFS4ERR_RESOURCE is not a valid error in NFSv4.1 */
    NFS4ERR_RESOURCE                   = 10018,/* resource exhaustion     */

    NFS4ERR_MOVED                      = 10019,/* filesystem relocated    */
    NFS4ERR_NOFILEHANDLE               = 10020,/* current FH is not set   */
    NFS4ERR_MINOR_VERS_MISMATCH        = 10021,/* minor vers not supp     */
    NFS4ERR_STALE_CLIENTID             = 10022,/* server has rebooted     */
    NFS4ERR_STALE_STATEID              = 10023,/* server has rebooted     */
    NFS4ERR_OLD_STATEID                = 10024,/* state is out of sync    */
    NFS4ERR_BAD_STATEID                = 10025,/* incorrect stateid       */
    NFS4ERR_BAD_SEQID                  = 10026,/* request is out of seq.  */
    NFS4ERR_NOT_SAME                   = 10027,/* verify - attrs not same */
    NFS4ERR_LOCK_RANGE                 = 10028,/* overlapping lock range  */
    NFS4ERR_SYMLINK                    = 10029,/* should be file/directory*/
    NFS4ERR_RESTOREFH                  = 10030,/* no saved filehandle     */
    NFS4ERR_LEASE_MOVED                = 10031,/* some filesystem moved   */
    NFS4ERR_ATTRNOTSUPP                = 10032,/* recommended attr not sup*/
    NFS4ERR_NO_GRACE                   = 10033,/* reclaim outside of grace*/
    NFS4ERR_RECLAIM_BAD                = 10034,/* reclaim error at server */
    NFS4ERR_RECLAIM_CONFLICT           = 10035,/* conflict on reclaim     */
    NFS4ERR_BADXDR                     = 10036,/* XDR decode failed       */
    NFS4ERR_LOCKS_HELD                 = 10037,/* file locks held at CLOSE*/
    NFS4ERR_OPENMODE                   = 10038,/* conflict in OPEN and I/O*/
    NFS4ERR_BADOWNER                   = 10039,/* owner translation bad   */
    NFS4ERR_BADCHAR                    = 10040,/* utf-8 char not supported*/
    NFS4ERR_BADNAME                    = 10041,/* name not supported      */
    NFS4ERR_BAD_RANGE                  = 10042,/* lock range not supported*/
    NFS4ERR_LOCK_NOTSUPP               = 10043,/* no atomic up/downgrade  */
    NFS4ERR_OP_ILLEGAL                 = 10044,/* undefined operation     */
    NFS4ERR_DEADLOCK                   = 10045,/* file locking deadlock   */
    NFS4ERR_FILE_OPEN                  = 10046,/* open file blocks op.    */
    NFS4ERR_ADMIN_REVOKED              = 10047,/* lockowner state revoked */
    NFS4ERR_CB_PATH_DOWN               = 10048,/* callback path down      */

    /*
     * NFSv4.1 errors start here
     */
    NFS4ERR_BADIOMODE                  = 10049,
    NFS4ERR_BADLAYOUT                  = 10050,
    NFS4ERR_BAD_SESSION_DIGEST         = 10051,
    NFS4ERR_BADSESSION                 = 10052,
    NFS4ERR_BADSLOT                    = 10053,
    NFS4ERR_COMPLETE_ALREADY           = 10054,
    NFS4ERR_CONN_NOT_BOUND_TO_SESSION  = 10055,
    NFS4ERR_DELEG_ALREADY_WANTED       = 10056,
    NFS4ERR_BACK_CHAN_BUSY             = 10057,/*backchan reqs outstanding*/
    NFS4ERR_LAYOUTTRYLATER             = 10058,
    NFS4ERR_LAYOUTUNAVAILABLE          = 10059,
    NFS4ERR_NOMATCHING_LAYOUT          = 10060,
    NFS4ERR_RECALLCONFLICT             = 10061,
    NFS4ERR_UNKNOWN_LAYOUTTYPE         = 10062,
    NFS4ERR_SEQ_MISORDERED             = 10063,/* unexpected seq.id in req*/
    NFS4ERR_SEQUENCE_POS               = 10064,/* [CB_]SEQ. op not 1st op */
    NFS4ERR_REQ_TOO_BIG                = 10065,/* request too big         */
    NFS4ERR_REP_TOO_BIG                = 10066,/* reply too big           */
    NFS4ERR_REP_TOO_BIG_TO_CACHE       = 10067,/* rep. not all cached     */
    NFS4ERR_RETRY_UNCACHED_REP         = 10068,/* retry & rep. uncached   */
    NFS4ERR_UNSAFE_COMPOUND            = 10069,/* retry/recovery too hard */
    NFS4ERR_TOO_MANY_OPS               = 10070,/*too many ops in [CB_]COMP*/
    NFS4ERR_OP_NOT_IN_SESSION          = 10071,/* op needs [CB_]SEQ. op   */
    NFS4ERR_HASH_ALG_UNSUPP            = 10072, /* hash alg. not supp.    */
    /* Unused/reserved                   10073 */
    NFS4ERR_CLIENTID_BUSY              = 10074,/* clientid has state      */
    NFS4ERR_PNFS_IO_HOLE               = 10075,/* IO to _SPARSE file hole */
    NFS4ERR_SEQ_FALSE_RETRY            = 10076,/* Retry != original req.  */
    NFS4ERR_BAD_HIGH_SLOT              = 10077,/* req has bad highest_slot*/
    NFS4ERR_DEADSESSION                = 10078,/*new req sent to dead sess*/
    NFS4ERR_ENCR_ALG_UNSUPP            = 10079,/* encr alg. not supp.     */
    NFS4ERR_PNFS_NO_LAYOUT             = 10080,/* I/O without a layout    */
    NFS4ERR_NOT_ONLY_OP                = 10081,/* addl ops not allowed    */
    NFS4ERR_WRONG_CRED                 = 10082,/* op done by wrong cred   */
    NFS4ERR_WRONG_TYPE                 = 10083,/* op on wrong type object */
    NFS4ERR_DIRDELEG_UNAVAIL           = 10084,/* delegation not avail.   */
    NFS4ERR_REJECT_DELEG               = 10085,/* cb rejected delegation  */
    NFS4ERR_RETURNCONFLICT             = 10086,/* layout get before return*/
    NFS4ERR_DELEG_REVOKED              = 10087,/* no return-state revoked */

    /*
     * NFSv4.2 errors start here
     */
    NFS4ERR_PARTNER_NOTSUPP            = 10088,/* s2s not supported       */
    NFS4ERR_PARTNER_NO_AUTH            = 10089,/* s2s not authorized      */
    NFS4ERR_UNION_NOTSUPP              = 10090,/* Arm of union not supp   */
    NFS4ERR_OFFLOAD_DENIED             = 10091,/* dest not allowing copy  */
    NFS4ERR_WRONG_LFS                  = 10092,/* LFS not supported       */
    NFS4ERR_BADLABEL                   = 10093,/* incorrect label         */
    NFS4ERR_OFFLOAD_NO_REQS            = 10094 /* dest not meeting reqs   */
};

/*
 * Basic typedefs for RFC 1832 data type definitions
 */
typedef int             int32_t;
typedef unsigned int    uint32_t;
typedef hyper           int64_t;
typedef unsigned hyper  uint64_t;

/*
 * Basic data types
 */
typedef opaque                  attrlist4<>;
/* BITMAP:1 */
typedef uint32_t                bitmap4<>; /* STRHEX:1 */
typedef uint64_t                changeid4; /* STRHEX:1 */
typedef uint64_t                clientid4; /* STRHEX:1 */
typedef uint64_t                offset4;
typedef uint32_t                count4;
typedef uint64_t                length4;
typedef uint32_t                mode4;
typedef uint64_t                nfs_cookie4;
typedef opaque                  nfs_fh4<NFS4_FHSIZE>; /* STRHEX:1 */
typedef uint32_t                nfs_lease4;
typedef uint32_t                qop4;
typedef opaque                  sec_oid4<>; /* STRHEX:1 */
typedef uint32_t                seqid4;
typedef opaque                  utf8string<>;
typedef utf8string              utf8str_cis;
typedef utf8string              utf8str_cs;
typedef utf8string              utf8str_mixed;
typedef utf8str_cs              component4;
typedef utf8str_cs              linktext4;
typedef utf8string              ascii_REQUIRED4;
typedef component4              pathname4<>;
typedef opaque                  verifier4[NFS4_VERIFIER_SIZE]; /* STRHEX:1 */
typedef uint32_t                acetype4; /* STRHEX:1 */
typedef uint32_t                aceflag4; /* STRHEX:1 */
typedef uint32_t                acemask4; /* STRHEX:1 */
typedef uint32_t                access4;

/*
 * New to NFSv4.1
 */
typedef uint32_t                sequenceid4;
typedef opaque                  sessionid4[NFS4_SESSIONID_SIZE]; /* STRHEX:1 */
typedef uint32_t                slotid4;
typedef uint32_t                aclflag4; /* STRHEX:1 */
typedef opaque                  deviceid4[NFS4_DEVICEID4_SIZE]; /* STRHEX:1 */
typedef uint32_t                fs_charset_cap4;
typedef uint32_t                nfl_util4; /* STRHEX:1 */
typedef opaque                  gsshandle4_t<>; /* STRHEX:1 */

/*
 * New to NFSv4.2
 */
typedef string                  secret4<>;
typedef uint32_t                policy4;

/*
 * Timeval
 */
/* STRFMT1: {0}.{1:09} */
struct nfstime4 {
    int64_t   seconds;
    uint32_t  nseconds;
};

enum time_how4 {
    SET_TO_SERVER_TIME4 = 0,
    SET_TO_CLIENT_TIME4 = 1
};

union settime4 switch (time_how4 set_it) {
    case SET_TO_CLIENT_TIME4:
        nfstime4  time;
    default:
        void;
};

/*
 * File attribute definitions
 */

/*
 * FSID structure for major/minor
 */
/* STRFMT1: {0},{1} */
struct fsid4 {
    uint64_t  major;
    uint64_t  minor;
};

/*
 * Filesystem locations attribute for relocation/migration
 */
/* STRFMT1: server:{0} rootpath:{1:/:} */
struct fs_location4 {
    utf8str_cis  server<>;
    pathname4    root;
};

/* STRFMT1: root:{1:/:} */
struct fs_locations4 {
    pathname4     root;
    fs_location4  locations<>;
};

/*
 * Various Access Control Entry definitions
 */

/*
 * Mask that indicates which Access Control Entries are supported.
 * Values for the fattr4_aclsupport attribute.
 */
const ACL4_SUPPORT_ALLOW_ACL    = 0x00000001;
const ACL4_SUPPORT_DENY_ACL     = 0x00000002;
const ACL4_SUPPORT_AUDIT_ACL    = 0x00000004;
const ACL4_SUPPORT_ALARM_ACL    = 0x00000008;

/*
 * acetype4 values, others can be added as needed.
 */
const ACE4_ACCESS_ALLOWED_ACE_TYPE      = 0x00000000;
const ACE4_ACCESS_DENIED_ACE_TYPE       = 0x00000001;
const ACE4_SYSTEM_AUDIT_ACE_TYPE        = 0x00000002;
const ACE4_SYSTEM_ALARM_ACE_TYPE        = 0x00000003;

/*
 * ACE flag values
 */
const ACE4_FILE_INHERIT_ACE             = 0x00000001;
const ACE4_DIRECTORY_INHERIT_ACE        = 0x00000002;
const ACE4_NO_PROPAGATE_INHERIT_ACE     = 0x00000004;
const ACE4_INHERIT_ONLY_ACE             = 0x00000008;
const ACE4_SUCCESSFUL_ACCESS_ACE_FLAG   = 0x00000010;
const ACE4_FAILED_ACCESS_ACE_FLAG       = 0x00000020;
const ACE4_IDENTIFIER_GROUP             = 0x00000040;
const ACE4_INHERITED_ACE                = 0x00000080; /* New to NFSv4.1 */

/*
 * ACE mask values
 */
const ACE4_READ_DATA            = 0x00000001;
const ACE4_LIST_DIRECTORY       = 0x00000001;
const ACE4_WRITE_DATA           = 0x00000002;
const ACE4_ADD_FILE             = 0x00000002;
const ACE4_APPEND_DATA          = 0x00000004;
const ACE4_ADD_SUBDIRECTORY     = 0x00000004;
const ACE4_READ_NAMED_ATTRS     = 0x00000008;
const ACE4_WRITE_NAMED_ATTRS    = 0x00000010;
const ACE4_EXECUTE              = 0x00000020;
const ACE4_DELETE_CHILD         = 0x00000040;
const ACE4_READ_ATTRIBUTES      = 0x00000080;
const ACE4_WRITE_ATTRIBUTES     = 0x00000100;
const ACE4_WRITE_RETENTION      = 0x00000200; /* New to NFSv4.1 */
const ACE4_WRITE_RETENTION_HOLD = 0x00000400; /* New to NFSv4.1 */

const ACE4_DELETE               = 0x00010000;
const ACE4_READ_ACL             = 0x00020000;
const ACE4_WRITE_ACL            = 0x00040000;
const ACE4_WRITE_OWNER          = 0x00080000;
const ACE4_SYNCHRONIZE          = 0x00100000;

/*
 * ACE4_GENERIC_READ -- defined as combination of
 *      ACE4_READ_ACL |
 *      ACE4_READ_DATA |
 *      ACE4_READ_ATTRIBUTES |
 *      ACE4_SYNCHRONIZE
 */
const ACE4_GENERIC_READ = 0x00120081;

/*
 * ACE4_GENERIC_WRITE -- defined as combination of
 *      ACE4_READ_ACL |
 *      ACE4_WRITE_DATA |
 *      ACE4_WRITE_ATTRIBUTES |
 *      ACE4_WRITE_ACL |
 *      ACE4_APPEND_DATA |
 *      ACE4_SYNCHRONIZE
 */
const ACE4_GENERIC_WRITE = 0x00160106;

/*
 * ACE4_GENERIC_EXECUTE -- defined as combination of
 *      ACE4_READ_ACL
 *      ACE4_READ_ATTRIBUTES
 *      ACE4_EXECUTE
 *      ACE4_SYNCHRONIZE
 */
const ACE4_GENERIC_EXECUTE = 0x001200A0;

/*
 * Access Control Entry definition
 */
struct nfsace4 {
    acetype4       type;
    aceflag4       flag;
    acemask4       mask;
    utf8str_mixed  who;
};

/*
 * ACL flag values new to NFSv4.1
 */
const ACL4_AUTO_INHERIT         = 0x00000001;
const ACL4_PROTECTED            = 0x00000002;
const ACL4_DEFAULTED            = 0x00000004;

/*
 * Access Control List definition new to NFSv4.1
 */
struct nfsacl41 {
    aclflag4  flag;
    nfsace4   aces<>;
};

/*
 * Field definitions for the fattr4_mode attribute
 * and fattr4_mode_set_masked attributes.
 */
const MODE4_SUID = 0x800;  /* set user id on execution */
const MODE4_SGID = 0x400;  /* set group id on execution */
const MODE4_SVTX = 0x200;  /* save text even after use */
const MODE4_RUSR = 0x100;  /* read permission: owner */
const MODE4_WUSR = 0x080;  /* write permission: owner */
const MODE4_XUSR = 0x040;  /* execute permission: owner */
const MODE4_RGRP = 0x020;  /* read permission: group */
const MODE4_WGRP = 0x010;  /* write permission: group */
const MODE4_XGRP = 0x008;  /* execute permission: group */
const MODE4_ROTH = 0x004;  /* read permission: other */
const MODE4_WOTH = 0x002;  /* write permission: other */
const MODE4_XOTH = 0x001;  /* execute permission: other */

/*
 * Special data/attribute associated with
 * file types NF4BLK and NF4CHR.
 */
/* STRFMT1: major:{0} minor:{1} */
struct specdata4 {
    uint32_t  specdata1; /* major device number */
    uint32_t  specdata2; /* minor device number */
};

/*
 * Stateid
 */
/* EQATTR: other */
/* STRFMT1: {0},{1:crc16} */
struct stateid4 {
    uint32_t  seqid;
    opaque    other[NFS4_OTHER_SIZE]; /* STRHEX:1 */
};

enum stable_how4 {
    UNSTABLE4       = 0,
    DATA_SYNC4      = 1,
    FILE_SYNC4      = 2
};

/* STRFMT1: netid:{0} addr:{1} */
struct clientaddr4 {
    /* See struct rpcb in RFC 1833 */
    string  netid<>;    /* network id */
    string  addr<>;     /* universal address */
};

typedef clientaddr4 netaddr4;

/*
 * Values for fattr4_fh_expire_type
 */
const FH4_PERSISTENT          = 0x00000000;
const FH4_NOEXPIRE_WITH_OPEN  = 0x00000001;
const FH4_VOLATILE_ANY        = 0x00000002;
const FH4_VOL_MIGRATION       = 0x00000004;
const FH4_VOL_RENAME          = 0x00000008;

/*
 * Data structures new to NFSv4.1
 */

/*
 * Filesystem locations attribute
 * for relocation/migration and
 * related attributes.
 */
struct change_policy4 {
    uint64_t  major;
    uint64_t  minor;
};

/*
 * Masked mode for the mode_set_masked attribute.
 */
struct mode_masked4 {
    mode4  values;   /* Values of bits to set or reset in mode. */
    mode4  mask;     /* Mask of bits to set or reset in mode. */
};

enum layouttype4 {
    LAYOUT4_NFSV4_1_FILES   = 0x1,
    LAYOUT4_OSD2_OBJECTS    = 0x2,
    LAYOUT4_BLOCK_VOLUME    = 0x3,
    LAYOUT4_FLEX_FILES      = 0x4
};

const NFL4_UFLG_MASK                  = 0x0000003F;
const NFL4_UFLG_DENSE                 = 0x00000001;
const NFL4_UFLG_COMMIT_THRU_MDS       = 0x00000002;
const NFL42_UFLG_IO_ADVISE_THRU_MDS   = 0x00000004;
const NFL4_UFLG_STRIPE_UNIT_SIZE_MASK = 0xFFFFFFC0;

enum filelayout_hint_care4 {
    NFLH4_CARE_DENSE              = NFL4_UFLG_DENSE,
    NFLH4_CARE_COMMIT_THRU_MDS    = NFL4_UFLG_COMMIT_THRU_MDS,
    NFL42_CARE_IO_ADVISE_THRU_MDS = NFL42_UFLG_IO_ADVISE_THRU_MDS,
    NFLH4_CARE_STRIPE_UNIT_SIZE   = 0x00000040,
    NFLH4_CARE_STRIPE_COUNT       = 0x00000080
};

/* Encoded in the body field of type layouthint4: */
struct nfsv4_1_file_layouthint4 {
    uint32_t        size;  /* opaque size from layouthint4 */
    uint32_t        care;
    nfl_util4       nfl_util;
    count4          stripe_count;
};

typedef netaddr4 multipath_list4<>;

/* Encoded in the addr_body field of type device_addr4: */
/* STRFMT1: {2} */
struct nfsv4_1_file_layout_ds_addr4 {
    uint32_t        size;  /* opaque size from device_addr4 */
    uint32_t        stripe_indices<>;
    multipath_list4 multipath_ds_list<>;
};

/* Encoded in the body field of type layout_content4: */
/* STRFMT1: {5:crc32} */
struct nfsv4_1_file_layout4 {
    uint32_t       size;  /* opaque size from layout_content4 */
    deviceid4      deviceid;
    nfl_util4      nfl_util;
    uint32_t       first_stripe_index;
    offset4        pattern_offset;
    nfs_fh4        fh_list<>;
};

/* COMMENT: NFSv4.x flex files layout definitions (BEGIN) ================================ */
/* INCLUDE: nfs4flex.x */
/* COMMENT: NFSv4.x flex files layout definitions (END) ================================== */

/*
 * Original definition
 * struct layout_content4 {
 *     layouttype4  type;
 *     opaque       body<>;
 * };
*/
/* STRFMT1: {1} */
union layout_content4 switch (layouttype4 type) {
    case LAYOUT4_NFSV4_1_FILES:
        nfsv4_1_file_layout4 body;
    case LAYOUT4_FLEX_FILES:
        ff_layout4 body;
    default:
        /* All other types are not supported yet */
        /* STRFMT1: "" */
        opaque body<>;
};

/*
 * Original definition
 * struct layouthint4 {
 *     layouttype4  type;
 *     opaque       body<>;
 * };
 */
union layouthint4 switch (layouttype4 type) {
    case LAYOUT4_NFSV4_1_FILES:
        nfsv4_1_file_layouthint4 body;
    case LAYOUT4_FLEX_FILES:
        ff_layouthint4 body;
    default:
        /* All other types are not supported yet */
        opaque body<>;
};

enum layoutiomode4 {
    LAYOUTIOMODE4_READ      = 1,
    LAYOUTIOMODE4_RW        = 2,
    LAYOUTIOMODE4_ANY       = 3
};

/* STRFMT1: {2:@14} off:{0:umax64} len:{1:umax64} {3} */
struct layout4 {
    offset4          offset;
    length4          length;
    layoutiomode4    iomode;
    layout_content4  content;
};

/*
 * Original definition
 * struct device_addr4 {
 *     layouttype4 type;
 *     opaque      addr_body<>;
 * };
 */
/* STRFMT1: {1} */
union device_addr4 switch (layouttype4 type) {
    case LAYOUT4_NFSV4_1_FILES:
        nfsv4_1_file_layout_ds_addr4 body;
    case LAYOUT4_FLEX_FILES:
        ff_device_addr4 body;
    default:
        /* All other types are not supported yet */
        /* STRFMT1: "" */
        opaque body<>;
};

/*
 * For LAYOUT4_NFSV4_1_FILES, the body field MUST have a zero length
 */
struct layoutupdate4 {
    layouttype4  type;
    opaque       body<>;
};

/* Constants used for LAYOUTRETURN and CB_LAYOUTRECALL */
const LAYOUT4_RET_REC_FILE      = 1;
const LAYOUT4_RET_REC_FSID      = 2;
const LAYOUT4_RET_REC_ALL       = 3;

enum layoutreturn_type4 {
    LAYOUTRETURN4_FILE = LAYOUT4_RET_REC_FILE,
    LAYOUTRETURN4_FSID = LAYOUT4_RET_REC_FSID,
    LAYOUTRETURN4_ALL  = LAYOUT4_RET_REC_ALL
};

/* GLOBAL: nfs4_layouttype */
union layoutreturn_file_body4 switch (layouttype4 nfs4_layouttype) {
    case LAYOUT4_FLEX_FILES:
        ff_layoutreturn4 body;
    default:
        /* All other types are not supported yet or not used */
        opaque body<>;
};

/* STRFMT1: off:{0:umax64} len:{1:umax64} stid:{2} */
struct layoutreturn_file4 {
    offset4   offset;
    length4   length;
    stateid4  stateid;
    /* layouttype4 specific data */
    layoutreturn_file_body4 data; /* FLATATTR:1 */
};

/* STRFMT1: {1} */
union layoutreturn4 switch(layoutreturn_type4 returntype) {
    case LAYOUTRETURN4_FILE:
        layoutreturn_file4  layout;
    default:
        void;
};

enum fs4_status_type {
    STATUS4_FIXED = 1,
    STATUS4_UPDATED = 2,
    STATUS4_VERSIONED = 3,
    STATUS4_WRITABLE = 4,
    STATUS4_REFERRAL = 5
};

struct fs4_status {
    bool             absent;
    fs4_status_type  type;   /* STRHEX:1 */
    utf8str_cs       source;
    utf8str_cs       current;
    int32_t          age;
    nfstime4         version;
};

const TH4_READ_SIZE     = 0;
const TH4_WRITE_SIZE    = 1;
const TH4_READ_IOSIZE   = 2;
const TH4_WRITE_IOSIZE  = 3;

struct threshold_item4 {
    layouttype4  type;
    bitmap4      mask;
    opaque       values<>;
};

struct mdsthreshold4 {
    threshold_item4  hints<>;
};

const RET4_DURATION_INFINITE    = 0xffffffffffffffff;

struct retention_get4 {
    uint64_t  duration;
    nfstime4  begin_time<1>;
};

struct retention_set4 {
    bool      enable;
    uint64_t  duration<1>;
};

/*
 * Byte indices of items within
 * fls_info: flag fields, class numbers,
 * bytes indicating ranks and orders.
 */
const FSLI4BX_GFLAGS            = 0;
const FSLI4BX_TFLAGS            = 1;

const FSLI4BX_CLSIMUL           = 2;
const FSLI4BX_CLHANDLE          = 3;
const FSLI4BX_CLFILEID          = 4;
const FSLI4BX_CLWRITEVER        = 5;
const FSLI4BX_CLCHANGE          = 6;
const FSLI4BX_CLREADDIR         = 7;

const FSLI4BX_READRANK          = 8;
const FSLI4BX_WRITERANK         = 9;
const FSLI4BX_READORDER         = 10;
const FSLI4BX_WRITEORDER        = 11;

/*
 * Bits defined within the general flag byte.
 */
const FSLI4GF_WRITABLE          = 0x01;
const FSLI4GF_CUR_REQ           = 0x02;
const FSLI4GF_ABSENT            = 0x04;
const FSLI4GF_GOING             = 0x08;
const FSLI4GF_SPLIT             = 0x10;

/*
 * Bits defined within the transport flag byte.
 */
const FSLI4TF_RDMA              = 0x01;

/*
 * Flag bits in fli_flags.
 */
const FSLI4IF_VAR_SUB           = 0x00000001;

/*
 * Defines an individual server replica
 */
struct fs_locations_server4 {
    int32_t         currency;
    opaque          info<>;
    utf8str_cis     server;
};

/*
 * Defines a set of replicas sharing
 * a common value of the root path
 * with in the corresponding
 * single-server namespaces.
 */
struct fs_locations_item4 {
    fs_locations_server4    entries<>;
    pathname4               root;
};

/*
 * Defines the overall structure of
 * the fs_locations_info attribute.
 */
struct fs_locations_info4 {
    uint32_t                flags;
    int32_t                 valid_for;
    pathname4               root;
    fs_locations_item4      items<>;
};

/* Constants for fs_charset_cap4 */
const FSCHARSET_CAP4_CONTAINS_NON_UTF8  = 0x1;
const FSCHARSET_CAP4_ALLOWS_ONLY_UTF8   = 0x2;

/*
 * Data structures new to NFSv4.2
 */

enum netloc_type4 {
    NL4_NAME    = 1,
    NL4_URL     = 2,
    NL4_NETADDR = 3
};

/* STRFMT1: {0} {1} */
union netloc4 switch (netloc_type4 type) {
    case NL4_NAME:    utf8str_cis name;
    case NL4_URL:     utf8str_cis url;
    case NL4_NETADDR: netaddr4    addr;
};

enum change_attr_type4 {
    NFS4_CHANGE_TYPE_IS_MONOTONIC_INCR         = 0,
    NFS4_CHANGE_TYPE_IS_VERSION_COUNTER        = 1,
    NFS4_CHANGE_TYPE_IS_VERSION_COUNTER_NOPNFS = 2,
    NFS4_CHANGE_TYPE_IS_TIME_METADATA          = 3,
    NFS4_CHANGE_TYPE_IS_UNDEFINED              = 4
};

/* STRFMT1: lfs:{0} pi:{1} */
struct labelformat_spec4 {
    policy4 lfs;
    policy4 pi;
};

/* STRFMT1: {0} data:{1} */
struct sec_label4 {
    labelformat_spec4       lfs;
    opaque                  data<>;
};

/* STRFMT1: mode:{0} umask:{1} */
struct mode_umask4 {
    mode4  mode;
    mode4  umask;
};

/* Used in RPCSEC_GSSv3 */
struct copy_from_auth_priv {
    secret4             secret;
    netloc4             destination;
    /* the NFSv4 user name that the user principal maps to */
    utf8str_mixed       username;
};

/* Used in RPCSEC_GSSv3 */
struct copy_to_auth_priv {
    /* equal to cfap_shared_secret */
    secret4             secret;
    netloc4             source<>;
    /* the NFSv4 user name that the user principal maps to */
    utf8str_mixed       username;
};

/* Used in RPCSEC_GSSv3 */
struct copy_confirm_auth_priv {
    /* equal to GSS_GetMIC() of cfap_shared_secret */
    opaque              secret<>;
    /* the NFSv4 user name that the user principal maps to */
    utf8str_mixed       username;
};

/*
 * Attributes
 */
typedef bitmap4                 fattr4_supported_attrs;
typedef nfs_ftype4              fattr4_type;
typedef uint32_t                fattr4_fh_expire_type;
typedef changeid4               fattr4_change;
typedef uint64_t                fattr4_size;
typedef bool                    fattr4_link_support;
typedef bool                    fattr4_symlink_support;
typedef bool                    fattr4_named_attr;
typedef fsid4                   fattr4_fsid;
typedef bool                    fattr4_unique_handles;
typedef nfs_lease4              fattr4_lease_time;
typedef nfsstat4                fattr4_rdattr_error;
typedef nfsace4                 fattr4_acl<>;
typedef uint32_t                fattr4_aclsupport;
typedef bool                    fattr4_archive;
typedef bool                    fattr4_cansettime;
typedef bool                    fattr4_case_insensitive;
typedef bool                    fattr4_case_preserving;
typedef bool                    fattr4_chown_restricted;
typedef uint64_t                fattr4_fileid;
typedef uint64_t                fattr4_files_avail;
typedef nfs_fh4                 fattr4_filehandle;
typedef uint64_t                fattr4_files_free;
typedef uint64_t                fattr4_files_total;
typedef fs_locations4           fattr4_fs_locations;
typedef bool                    fattr4_hidden;
typedef bool                    fattr4_homogeneous;
typedef uint64_t                fattr4_maxfilesize;
typedef uint32_t                fattr4_maxlink;
typedef uint32_t                fattr4_maxname;
typedef uint64_t                fattr4_maxread;
typedef uint64_t                fattr4_maxwrite;
typedef ascii_REQUIRED4         fattr4_mimetype;
typedef mode4                   fattr4_mode;
typedef uint64_t                fattr4_mounted_on_fileid;
typedef bool                    fattr4_no_trunc;
typedef uint32_t                fattr4_numlinks;
typedef utf8str_mixed           fattr4_owner;
typedef utf8str_mixed           fattr4_owner_group;
typedef uint64_t                fattr4_quota_avail_hard;
typedef uint64_t                fattr4_quota_avail_soft;
typedef uint64_t                fattr4_quota_used;
typedef specdata4               fattr4_rawdev;
typedef uint64_t                fattr4_space_avail;
typedef length4                 fattr4_space_free;
typedef uint64_t                fattr4_space_total;
typedef uint64_t                fattr4_space_used;
typedef bool                    fattr4_system;
typedef nfstime4                fattr4_time_access;
typedef settime4                fattr4_time_access_set;
typedef nfstime4                fattr4_time_backup;
typedef nfstime4                fattr4_time_create;
typedef nfstime4                fattr4_time_delta;
typedef nfstime4                fattr4_time_metadata;
typedef nfstime4                fattr4_time_modify;
typedef settime4                fattr4_time_modify_set;
/*
 * Attributes new to NFSv4.1
 */
typedef mode_masked4            fattr4_mode_set_masked;
typedef bitmap4                 fattr4_suppattr_exclcreat;
typedef nfstime4                fattr4_dir_notif_delay;
typedef nfstime4                fattr4_dirent_notif_delay;
typedef layouttype4             fattr4_fs_layout_types<>;
typedef fs4_status              fattr4_fs_status;
typedef fs_charset_cap4         fattr4_fs_charset_cap;
typedef uint32_t                fattr4_layout_alignment;
typedef uint32_t                fattr4_layout_blksize;
typedef layouthint4             fattr4_layout_hint;
typedef layouttype4             fattr4_layout_types<>;
typedef mdsthreshold4           fattr4_mdsthreshold;
typedef retention_get4          fattr4_retention_get;
typedef retention_set4          fattr4_retention_set;
typedef retention_get4          fattr4_retentevt_get;
typedef retention_set4          fattr4_retentevt_set;
typedef uint64_t                fattr4_retention_hold;
typedef nfsacl41                fattr4_dacl;
typedef nfsacl41                fattr4_sacl;
typedef change_policy4          fattr4_change_policy;
typedef fs_locations_info4      fattr4_fs_locations_info;
/*
 * Attributes new to NFSv4.2
 */
typedef uint64_t                fattr4_clone_blksize;
typedef uint64_t                fattr4_space_freed;
typedef change_attr_type4       fattr4_change_attr_type;
typedef sec_label4              fattr4_sec_label;
typedef mode_umask4             fattr4_mode_umask;

/* FMAP:1 */
enum nfs_fattr4 {
    /*
     * Mandatory Attributes
     */
    FATTR4_SUPPORTED_ATTRS    = 0,
    FATTR4_TYPE               = 1,
    FATTR4_FH_EXPIRE_TYPE     = 2,
    FATTR4_CHANGE             = 3,
    FATTR4_SIZE               = 4,
    FATTR4_LINK_SUPPORT       = 5,
    FATTR4_SYMLINK_SUPPORT    = 6,
    FATTR4_NAMED_ATTR         = 7,
    FATTR4_FSID               = 8,
    FATTR4_UNIQUE_HANDLES     = 9,
    FATTR4_LEASE_TIME         = 10,
    FATTR4_RDATTR_ERROR       = 11,
    FATTR4_FILEHANDLE         = 19,
    FATTR4_SUPPATTR_EXCLCREAT = 75, /* New to NFSv4.1 */

    /*
     * Recommended Attributes
     */
    FATTR4_ACL                = 12,
    FATTR4_ACLSUPPORT         = 13,
    FATTR4_ARCHIVE            = 14,
    FATTR4_CANSETTIME         = 15,
    FATTR4_CASE_INSENSITIVE   = 16,
    FATTR4_CASE_PRESERVING    = 17,
    FATTR4_CHOWN_RESTRICTED   = 18,
    FATTR4_FILEID             = 20,
    FATTR4_FILES_AVAIL        = 21,
    FATTR4_FILES_FREE         = 22,
    FATTR4_FILES_TOTAL        = 23,
    FATTR4_FS_LOCATIONS       = 24,
    FATTR4_HIDDEN             = 25,
    FATTR4_HOMOGENEOUS        = 26,
    FATTR4_MAXFILESIZE        = 27,
    FATTR4_MAXLINK            = 28,
    FATTR4_MAXNAME            = 29,
    FATTR4_MAXREAD            = 30,
    FATTR4_MAXWRITE           = 31,
    FATTR4_MIMETYPE           = 32,
    FATTR4_MODE               = 33,
    FATTR4_NO_TRUNC           = 34,
    FATTR4_NUMLINKS           = 35,
    FATTR4_OWNER              = 36,
    FATTR4_OWNER_GROUP        = 37,
    FATTR4_QUOTA_AVAIL_HARD   = 38,
    FATTR4_QUOTA_AVAIL_SOFT   = 39,
    FATTR4_QUOTA_USED         = 40,
    FATTR4_RAWDEV             = 41,
    FATTR4_SPACE_AVAIL        = 42,
    FATTR4_SPACE_FREE         = 43,
    FATTR4_SPACE_TOTAL        = 44,
    FATTR4_SPACE_USED         = 45,
    FATTR4_SYSTEM             = 46,
    FATTR4_TIME_ACCESS        = 47,
    FATTR4_TIME_ACCESS_SET    = 48,
    FATTR4_TIME_BACKUP        = 49,
    FATTR4_TIME_CREATE        = 50,
    FATTR4_TIME_DELTA         = 51,
    FATTR4_TIME_METADATA      = 52,
    FATTR4_TIME_MODIFY        = 53,
    FATTR4_TIME_MODIFY_SET    = 54,
    FATTR4_MOUNTED_ON_FILEID  = 55,

    /*
     * New to NFSv4.1
     */
    FATTR4_DIR_NOTIF_DELAY    = 56,
    FATTR4_DIRENT_NOTIF_DELAY = 57,
    FATTR4_DACL               = 58,
    FATTR4_SACL               = 59,
    FATTR4_CHANGE_POLICY      = 60,
    FATTR4_FS_STATUS          = 61,
    FATTR4_FS_LAYOUT_TYPES    = 62,
    FATTR4_LAYOUT_HINT        = 63,
    FATTR4_LAYOUT_TYPES       = 64,
    FATTR4_LAYOUT_BLKSIZE     = 65,
    FATTR4_LAYOUT_ALIGNMENT   = 66,
    FATTR4_FS_LOCATIONS_INFO  = 67,
    FATTR4_MDSTHRESHOLD       = 68,
    FATTR4_RETENTION_GET      = 69,
    FATTR4_RETENTION_SET      = 70,
    FATTR4_RETENTEVT_GET      = 71,
    FATTR4_RETENTEVT_SET      = 72,
    FATTR4_RETENTION_HOLD     = 73,
    FATTR4_MODE_SET_MASKED    = 74,
    FATTR4_FS_CHARSET_CAP     = 76,

    /*
     * New to NFSv4.2
     */
    FATTR4_CLONE_BLKSIZE      = 77,
    FATTR4_SPACE_FREED        = 78,
    FATTR4_CHANGE_ATTR_TYPE   = 79,
    FATTR4_SEC_LABEL          = 80,
    FATTR4_MODE_UMASK         = 81, /* draft-bfields-nfsv4-umask-01 */
};

/*
 * File attribute container
 */
/* BITDICT: nfs_fattr4 */
struct fattr4 {
    bitmap4    mask;
    attrlist4  values;
};

/*
 * Change info for the client
 */
struct change_info4 {
    bool       atomic;
    changeid4  before;
    changeid4  after;
};

struct state_owner4 {
    clientid4  clientid;
    opaque     owner<NFS4_OPAQUE_LIMIT>; /* STRHEX:1 */
};

typedef state_owner4 open_owner4;
typedef state_owner4 lock_owner4;

/* Input for computing subkeys */
enum ssv_subkey4 {
    SSV4_SUBKEY_MIC_I2T     = 1,
    SSV4_SUBKEY_MIC_T2I     = 2,
    SSV4_SUBKEY_SEAL_I2T    = 3,
    SSV4_SUBKEY_SEAL_T2I    = 4
};

/* Input for computing smt_hmac */
struct ssv_mic_plain_tkn4 {
    uint32_t  ssv_seq;
    opaque    orig_plain<>;
};

/* SSV GSS PerMsgToken token */
struct ssv_mic_tkn4 {
    uint32_t        ssv_seq;
    opaque          hmac<>;
};

/* Input for computing ssct_encr_data and ssct_hmac */
struct ssv_seal_plain_tkn4 {
    opaque          confounder<>;
    uint32_t        ssv_seq;
    opaque          orig_plain<>;
    opaque          pad<>;
};

/* SSV GSS SealedMessage token */
struct ssv_seal_cipher_tkn4 {
    uint32_t      ssv_seq;
    opaque        iv<>;
    opaque        encr_data<>;
    opaque        hmac<>;
};

/*
 * ======================================================================
 * NFSv4 Operation Definitions
 * ======================================================================
 */

/*
 * Operation array
 */
enum nfs_opnum4 {
    OP_ACCESS              = 3,
    OP_CLOSE               = 4,
    OP_COMMIT              = 5,
    OP_CREATE              = 6,
    OP_DELEGPURGE          = 7,
    OP_DELEGRETURN         = 8,
    OP_GETATTR             = 9,
    OP_GETFH               = 10,
    OP_LINK                = 11,
    OP_LOCK                = 12,
    OP_LOCKT               = 13,
    OP_LOCKU               = 14,
    OP_LOOKUP              = 15,
    OP_LOOKUPP             = 16,
    OP_NVERIFY             = 17,
    OP_OPEN                = 18,
    OP_OPENATTR            = 19,
    OP_OPEN_CONFIRM        = 20, /* Mandatory not-to-implement in NFSv4.1 */
    OP_OPEN_DOWNGRADE      = 21,
    OP_PUTFH               = 22,
    OP_PUTPUBFH            = 23,
    OP_PUTROOTFH           = 24,
    OP_READ                = 25,
    OP_READDIR             = 26,
    OP_READLINK            = 27,
    OP_REMOVE              = 28,
    OP_RENAME              = 29,
    OP_RENEW               = 30, /* Mandatory not-to-implement in NFSv4.1 */
    OP_RESTOREFH           = 31,
    OP_SAVEFH              = 32,
    OP_SECINFO             = 33,
    OP_SETATTR             = 34,
    OP_SETCLIENTID         = 35, /* Mandatory not-to-implement in NFSv4.1 */
    OP_SETCLIENTID_CONFIRM = 36, /* Mandatory not-to-implement in NFSv4.1 */
    OP_VERIFY              = 37,
    OP_WRITE               = 38,
    OP_RELEASE_LOCKOWNER   = 39, /* Mandatory not-to-implement in NFSv4.1 */
    /* New operations for NFSv4.1 */
    OP_BACKCHANNEL_CTL     = 40,
    OP_BIND_CONN_TO_SESSION= 41,
    OP_EXCHANGE_ID         = 42,
    OP_CREATE_SESSION      = 43,
    OP_DESTROY_SESSION     = 44,
    OP_FREE_STATEID        = 45,
    OP_GET_DIR_DELEGATION  = 46,
    OP_GETDEVICEINFO       = 47,
    OP_GETDEVICELIST       = 48, /* Mandatory not-to-implement in NFSv4.2 */
    OP_LAYOUTCOMMIT        = 49,
    OP_LAYOUTGET           = 50,
    OP_LAYOUTRETURN        = 51,
    OP_SECINFO_NO_NAME     = 52,
    OP_SEQUENCE            = 53,
    OP_SET_SSV             = 54,
    OP_TEST_STATEID        = 55,
    OP_WANT_DELEGATION     = 56,
    OP_DESTROY_CLIENTID    = 57,
    OP_RECLAIM_COMPLETE    = 58,
    /* New operations for NFSv4.2 */
    OP_ALLOCATE            = 59,
    OP_COPY                = 60,
    OP_COPY_NOTIFY         = 61,
    OP_DEALLOCATE          = 62,
    OP_IO_ADVISE           = 63,
    OP_LAYOUTERROR         = 64,
    OP_LAYOUTSTATS         = 65,
    OP_OFFLOAD_CANCEL      = 66,
    OP_OFFLOAD_STATUS      = 67,
    OP_READ_PLUS           = 68,
    OP_SEEK                = 69,
    OP_WRITE_SAME          = 70,
    OP_CLONE               = 71,
    /* Illegal operation */
    OP_ILLEGAL             = 10044
};

const ACCESS4_READ      = 0x00000001;
const ACCESS4_LOOKUP    = 0x00000002;
const ACCESS4_MODIFY    = 0x00000004;
const ACCESS4_EXTEND    = 0x00000008;
const ACCESS4_DELETE    = 0x00000010;
const ACCESS4_EXECUTE   = 0x00000020;

/*
 * ACCESS: Check Access Rights
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} acc:{0:#04x} */
struct ACCESS4args {
    /* CURRENT_FH: object */
    access4        access;
};

/* STRFMT1: supported:{0:#04x} acc:{1:#04x} */
struct ACCESS4resok {
    access4        supported;
    access4        access;
};

/* STRFMT1: {1} */
union ACCESS4res switch (nfsstat4 status) {
    case NFS4_OK:
        ACCESS4resok   resok;
    default:
        void;
};

/*
 * CLOSE: Close a File and Release Share Reservations
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{1} */
struct CLOSE4args {
    /* CURRENT_FH: object */
    seqid4          seqid;
    stateid4        stateid;
};

/* STRFMT1: stid:{1} */
union CLOSE4res switch (nfsstat4 status) {
    case NFS4_OK:
        stateid4       stateid;
    default:
        void;
};

/*
 * COMMIT: Commit Cached Data on Server to Stable Storage
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} off:{0:umax64} len:{1:umax32} */
struct COMMIT4args {
    /* CURRENT_FH: file */
    offset4         offset;
    count4          count;
};

/* STRFMT1: verf:{0} */
struct COMMIT4resok {
    verifier4       verifier;
};

/* STRFMT1: {1} */
union COMMIT4res switch (nfsstat4 status) {
    case NFS4_OK:
        COMMIT4resok   resok;
    default:
        void;
};

/*
 * CREATE: Create a Non-Regular File Object
 * ======================================================================
 */
/* STRFMT1: "" */
union createtype4 switch (nfs_ftype4 type) {
    case NF4LNK:
        /* STRFMT1: -> {1} */
        linktext4 linkdata;
    case NF4BLK:
    case NF4CHR:
        /* STRFMT1: {1} */
        specdata4 devdata;
    case NF4SOCK:
    case NF4FIFO:
    case NF4DIR:
        void;
    default:
        void;  /* server should return NFS4ERR_BADTYPE */
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: {0.type} DH:{fh:crc32}/{1} {0} */
struct CREATE4args {
    /* CURRENT_FH: directory for creation */
    createtype4     type;
    component4      name;
    fattr4          attributes;
};

struct CREATE4resok {
    change_info4    cinfo;
    bitmap4         attrset;        /* attributes set */
};

/* STRFMT1: "" */
union CREATE4res switch (nfsstat4 status) {
    case NFS4_OK:
        /* new CURRENTFH: created object */
        CREATE4resok resok;
    default:
        void;
};

/*
 * DELEGPURGE: Purge Delegations Awaiting Recovery
 * ======================================================================
 */
/* STRFMT1: clientid:{0} */
struct DELEGPURGE4args {
    clientid4       clientid;
};

/* STRFMT1: "" */
struct DELEGPURGE4res {
    nfsstat4        status;
};

/*
 * DELEGRETURN: Return Delegation
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} */
struct DELEGRETURN4args {
    /* CURRENT_FH: delegated object */
    stateid4        stateid;
};

/* STRFMT1: "" */
struct DELEGRETURN4res {
    nfsstat4        status;
};

/*
 * GETATTR: Get File Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} request:{0} */
struct GETATTR4args {
    /* CURRENT_FH: object */
    bitmap4         request;
};

struct GETATTR4resok {
    fattr4          attributes;
};

/* STRFMT1: "" */
union GETATTR4res switch (nfsstat4 status) {
    case NFS4_OK:
        GETATTR4resok  resok;
    default:
        void;
};

/*
 * GETFH: Get Current Filehandle
 * ======================================================================
 */
/* GLOBAL: nfs4_fh=fh */
/* STRFMT1: FH:{0:crc32} */
struct GETFH4resok {
    nfs_fh4         fh;
};

/* STRFMT1: {1} */
union GETFH4res switch (nfsstat4 status) {
    case NFS4_OK:
        GETFH4resok     resok;
    default:
        void;
};

/*
 * LINK: Create Link to an Object
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh,sfh=self.nfs4_sfh */
/* STRFMT1: DH:{fh:crc32}/{0} -> FH:{sfh:crc32} */
struct LINK4args {
    /* SAVED_FH: source object */
    /* CURRENT_FH: target directory */
    component4      name;
};

struct LINK4resok {
    change_info4    cinfo;
};

/* STRFMT1: "" */
union LINK4res switch (nfsstat4 status) {
    case NFS4_OK:
        LINK4resok resok;
    default:
        void;
};

/*
 * LOCK/LOCKT/LOCKU: Record Lock Management
 */
enum nfs_lock_type4 {
    READ_LT         = 1,
    WRITE_LT        = 2,
    READW_LT        = 3,    /* blocking read */
    WRITEW_LT       = 4     /* blocking write */
};

/*
 * For LOCK, transition from open_stateid and lock_owner
 * to a lock stateid.
 */
/* STRFMT1: open(stid:{1}, seqid:{0}) seqid:{2} */
struct open_to_lock_owner4 {
    seqid4          seqid;
    stateid4        stateid;
    seqid4          lock_seqid;
    lock_owner4     lock_owner;
};

/*
 * For LOCK, existing lock stateid continues to request new
 * file lock for the same lock_owner and open_stateid.
 */
/* STRFMT1: stid:{0} seqid:{1} */
struct exist_lock_owner4 {
    stateid4        stateid;
    seqid4          seqid;
};

/* STRFMT1: {1} */
union locker4 switch (bool new_lock_owner) {
    case TRUE:
        open_to_lock_owner4     open_owner;
    case FALSE:
        exist_lock_owner4       lock_owner;
};

/*
 * LOCK: Create Lock
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {0} off:{2:umax64} len:{3:umax64} {4} */
struct LOCK4args {
    /* CURRENT_FH: file */
    nfs_lock_type4  locktype;
    bool            reclaim;
    offset4         offset;
    length4         length;
    locker4         locker;
};

/* STRFMT1: {2} off:{0:umax64} len:{1:umax64} */
struct LOCK4denied {
    offset4         offset;
    length4         length;
    nfs_lock_type4  locktype;
    lock_owner4     owner;
};

/* STRFMT1: stid:{0} */
struct LOCK4resok {
    stateid4        stateid;
};

/* STRFMT1: {1} */
union LOCK4res switch (nfsstat4 status) {
    case NFS4_OK:
        LOCK4resok     resok;
    case NFS4ERR_DENIED:
        LOCK4denied    denied;
    default:
        void;
};

/*
 * LOCKT: Test For Lock
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {0} off:{1:umax64} len:{2:umax64} */
struct LOCKT4args {
    /* CURRENT_FH: file */
    nfs_lock_type4  locktype;
    offset4         offset;
    length4         length;
    lock_owner4     owner;
};

/* STRFMT1: {1} */
union LOCKT4res switch (nfsstat4 status) {
    case NFS4ERR_DENIED:
        LOCK4denied    denied;
    case NFS4_OK:
        void;
    default:
        void;
};

/*
 * LOCKU: Unlock File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {0} off:{3:umax64} len:{4:umax64} stid:{2} */
struct LOCKU4args {
    /* CURRENT_FH: file */
    nfs_lock_type4  locktype;
    seqid4          seqid;
    stateid4        stateid;
    offset4         offset;
    length4         length;
};

/* STRFMT1: stid:{1} */
union LOCKU4res switch (nfsstat4 status) {
    case NFS4_OK:
        stateid4       stateid;
    default:
        /* STRFMT1: "" */
        void;
};

/*
 * LOOKUP: Lookup Filename
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32}/{0} */
struct LOOKUP4args {
    /* CURRENT_FH: directory */
    component4      name;
};

/* STRFMT1: "" */
struct LOOKUP4res {
    /* New CURRENT_FH: object */
    nfsstat4        status;
};

/*
 * LOOKUPP: Lookup Parent Directory
 * ======================================================================
 */
/* STRFMT1: "" */
struct LOOKUPP4res {
    /* new CURRENT_FH: parent directory */
    nfsstat4        status;
};

/*
 * NVERIFY: Verify Difference in Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: "" */
struct NVERIFY4args {
    /* CURRENT_FH: object */
    fattr4          attributes;
};

/* STRFMT1: "" */
struct NVERIFY4res {
    nfsstat4        status;
};

/*
 * Various definitions for OPEN
 */
enum createmode4 {
    UNCHECKED4      = 0,
    GUARDED4        = 1,
    /* Deprecated in NFSv4.1. */
    EXCLUSIVE4      = 2,
    /*
     * New to NFSv4.1. If session is persistent,
     * GUARDED4 MUST be used. Otherwise, use
     * EXCLUSIVE4_1 instead of EXCLUSIVE4.
     */
    EXCLUSIVE4_1    = 3
};

struct creatverfattr {
    verifier4      verifier;
    fattr4         attrs;
};

union createhow4 switch (createmode4 mode) {
    case UNCHECKED4:
    case GUARDED4:
        fattr4         attributes;
    case EXCLUSIVE4:
        verifier4      verifier;
    case EXCLUSIVE4_1:
        creatverfattr  createboth;
};

enum opentype4 {
    OPEN4_NOCREATE  = 0,
    OPEN4_CREATE    = 1
};

union openflag4 switch (opentype4 opentype) {
    case OPEN4_CREATE:
        createhow4     how;
    default:
        void;
};

/* Next definitions used for OPEN delegation */
enum limit_by4 {
    NFS_LIMIT_SIZE          = 1,
    NFS_LIMIT_BLOCKS        = 2
    /* others as needed */
};

struct nfs_modified_limit4 {
    uint32_t        num_blocks;
    uint32_t        bytes_per_block;
};

union nfs_space_limit4 switch (limit_by4 limitby) {
    /* limit specified as file size */
    case NFS_LIMIT_SIZE:
        uint64_t               filesize;
    /* limit specified by number of blocks */
    case NFS_LIMIT_BLOCKS:
        nfs_modified_limit4    mod_blocks;
};

/*
 * Share Access and Deny constants for open argument
 */
const OPEN4_SHARE_ACCESS_READ   = 0x00000001;
const OPEN4_SHARE_ACCESS_WRITE  = 0x00000002;
const OPEN4_SHARE_ACCESS_BOTH   = 0x00000003;

const OPEN4_SHARE_DENY_NONE     = 0x00000000;
const OPEN4_SHARE_DENY_READ     = 0x00000001;
const OPEN4_SHARE_DENY_WRITE    = 0x00000002;
const OPEN4_SHARE_DENY_BOTH     = 0x00000003;

/* New flags for share_access field of OPEN4args */
const OPEN4_SHARE_ACCESS_WANT_DELEG_MASK        = 0xFF00;
const OPEN4_SHARE_ACCESS_WANT_NO_PREFERENCE     = 0x0000;
const OPEN4_SHARE_ACCESS_WANT_READ_DELEG        = 0x0100;
const OPEN4_SHARE_ACCESS_WANT_WRITE_DELEG       = 0x0200;
const OPEN4_SHARE_ACCESS_WANT_ANY_DELEG         = 0x0300;
const OPEN4_SHARE_ACCESS_WANT_NO_DELEG          = 0x0400;
const OPEN4_SHARE_ACCESS_WANT_CANCEL            = 0x0500;

const OPEN4_SHARE_ACCESS_WANT_SIGNAL_DELEG_WHEN_RESRC_AVAIL = 0x10000;
const OPEN4_SHARE_ACCESS_WANT_PUSH_DELEG_WHEN_UNCONTENDED = 0x20000;

enum open_delegation_type4 {
    OPEN_DELEGATE_NONE      = 0,
    OPEN_DELEGATE_READ      = 1,
    OPEN_DELEGATE_WRITE     = 2,
    OPEN_DELEGATE_NONE_EXT  = 3 /* New to NFSv4.1 */
};

enum open_claim_type4 {
    /*
     * Not a reclaim.
     */
    CLAIM_NULL              = 0,

    CLAIM_PREVIOUS          = 1,
    CLAIM_DELEGATE_CUR      = 2,
    CLAIM_DELEGATE_PREV     = 3,

    /*
     * Not a reclaim.
     *
     * Like CLAIM_NULL, but object identified
     * by the current filehandle.
     */
    CLAIM_FH                = 4, /* New to NFSv4.1 */

    /*
     * Like CLAIM_DELEGATE_CUR, but object identified
     * by current filehandle.
     */
    CLAIM_DELEG_CUR_FH      = 5, /* New to NFSv4.1 */

    /*
     * Like CLAIM_DELEGATE_PREV, but object identified
     * by current filehandle.
     */
    CLAIM_DELEG_PREV_FH     = 6 /* New to NFSv4.1 */
};

/* STRFMT1: {1} stid:{0} */
struct open_claim_delegate_cur4 {
    stateid4        stateid;
    component4      name;
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32}/{1} */
union open_claim4 switch (open_claim_type4 claim) {
    /*
     * No special rights to file.
     * Ordinary OPEN of the specified file.
     */
    case CLAIM_NULL:
        /* CURRENT_FH: directory */
        component4      name;

    /*
     * Right to the file established by an
     * open previous to server reboot. File
     * identified by filehandle obtained at
     * that time rather than by name.
     */
    case CLAIM_PREVIOUS:
        /* CURRENT_FH: file being reclaimed */
        /* STRFMT1: {0}:{fh:crc32} {1} */
        open_delegation_type4   deleg_type;

    /*
     * Right to file based on a delegation
     * granted by the server. File is
     * specified by name.
     */
    case CLAIM_DELEGATE_CUR:
        /* CURRENT_FH: directory */
        /* STRFMT1: {0} DH:{fh:crc32}/{1} */
        open_claim_delegate_cur4  deleg_info;

    /*
     * Right to file based on a delegation
     * granted to a previous boot instance
     * of the client.  File is specified by name.
     */
    case CLAIM_DELEGATE_PREV:
        /* CURRENT_FH: directory */
        /* STRFMT1: {0} DH:{fh:crc32}/{1} */
        component4      name;

    /*
     * Like CLAIM_NULL. No special rights
     * to file. Ordinary OPEN of the
     * specified file by current filehandle.
     */
    case CLAIM_FH: /* New to NFSv4.1 */
        /* CURRENT_FH: regular file to open */
        /* STRFMT1: {0}:{fh:crc32} */
        void;

    /*
     * Like CLAIM_DELEGATE_PREV. Right to file based on a
     * delegation granted to a previous boot
     * instance of the client.  File is identified by
     * by filehandle.
     */
    case CLAIM_DELEG_PREV_FH: /* New to NFSv4.1 */
        /* CURRENT_FH: file being opened */
        /* STRFMT1: {0}:{fh:crc32} */
        void;

    /*
     * Like CLAIM_DELEGATE_CUR. Right to file based on
     * a delegation granted by the server.
     * File is identified by filehandle.
     */
    case CLAIM_DELEG_CUR_FH: /* New to NFSv4.1 */
        /* CURRENT_FH: file being opened */
        /* STRFMT1: {0}:{fh:crc32} stid:{1} */
        stateid4       stateid;
};

/*
 * OPEN: Open a Regular File, Potentially Receiving an Open Delegation
 * ======================================================================
 */
/* STRFMT1: {5} acc:{1:#04x} deny:{2:#04x} */
struct OPEN4args {
    seqid4          seqid;
    uint32_t        access;
    uint32_t        deny;
    open_owner4     owner;
    openflag4       openhow;
    open_claim4     claim; /* FLATATTR:1 */
};

/* STRFMT1: rd_deleg_stid:{0} */
struct open_read_delegation4 {
    stateid4 stateid;    /* Stateid for delegation*/
    bool     recall;     /* Pre-recalled flag for delegations obtained by reclaim (CLAIM_PREVIOUS) */

    nfsace4 permissions; /* Defines users who don't need an ACCESS call to open for read */
};

/* STRFMT1: wr_deleg_stid:{0} */
struct open_write_delegation4 {
    stateid4 stateid;      /* Stateid for delegation */
    bool     recall;       /* Pre-recalled flag for delegations obtained by reclaim (CLAIM_PREVIOUS) */
    nfs_space_limit4 space_limit; /* Defines condition that the client must check to determine whether the file needs to be flushed to the server on close.  */
    nfsace4   permissions; /* Defines users who don't need an ACCESS call as part of a delegated open. */
};

/* New to NFSv4.1 */
enum why_no_delegation4 {
    WND4_NOT_WANTED         = 0,
    WND4_CONTENTION         = 1,
    WND4_RESOURCE           = 2,
    WND4_NOT_SUPP_FTYPE     = 3,
    WND4_WRITE_DELEG_NOT_SUPP_FTYPE = 4,
    WND4_NOT_SUPP_UPGRADE   = 5,
    WND4_NOT_SUPP_DOWNGRADE = 6,
    WND4_CANCELLED          = 7,
    WND4_IS_DIR             = 8
};

/* New to NFSv4.1 */
/* STRFMT1: {0} */
union open_none_delegation4 switch (why_no_delegation4 why) {
        case WND4_CONTENTION:
                /* Server will push delegation */
                /* STRFMT1: {0} push:{1} */
                bool push;
        case WND4_RESOURCE:
                /* Server will signal availability */
                /* STRFMT1: {0} signal:{1} */
                bool signal;
        default:
                void;
};

/* STRFMT1: {1} */
union open_delegation4 switch (open_delegation_type4 deleg_type) {
        case OPEN_DELEGATE_NONE:
                void;
        case OPEN_DELEGATE_READ:
                open_read_delegation4 read;
        case OPEN_DELEGATE_WRITE:
                open_write_delegation4 write;
        case OPEN_DELEGATE_NONE_EXT: /* New to NFSv4.1 */
                open_none_delegation4 whynone;
};

/*
 * Result flags
 */
/* Client must confirm open */
const OPEN4_RESULT_CONFIRM           = 0x00000002;
/* Type of file locking behavior at the server */
const OPEN4_RESULT_LOCKTYPE_POSIX    = 0x00000004;
/* Server will preserve file if removed while open */
const OPEN4_RESULT_PRESERVE_UNLINKED = 0x00000008;
/* Server may use CB_NOTIFY_LOCK on locks derived from this open */
const OPEN4_RESULT_MAY_NOTIFY_LOCK   = 0x00000020;

/* STRFMT1: stid:{0} {4} */
/* CLASSATTR: _opdisp=const.OP_GETFH */
struct OPEN4resok {
    stateid4       stateid;      /* Stateid for open */
    change_info4   cinfo;        /* Directory Change Info */
    uint32_t       rflags;       /* Result flags */
    bitmap4        attrset;      /* attribute set for create*/
    open_delegation4 delegation; /* Info on any open delegation */
};

/* STRFMT1: {1} */
union OPEN4res switch (nfsstat4 status) {
    case NFS4_OK:
        /* New CURRENT_FH: opened file */
        OPEN4resok      resok;
    default:
        void;
};

/*
 * OPENATTR: Open Named Attributes Directory
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: createdir:{0} */
struct OPENATTR4args {
    /* CURRENT_FH: object */
    bool    createdir;
};

/* STRFMT1: "" */
struct OPENATTR4res {
    /*
     * If status is NFS4_OK,
     *   new CURRENT_FH: named attribute directory
     */
    nfsstat4        status;
};

/*
 * OPEN_CONFIRM: Confirm the Open
 * ======================================================================
 * Obsolete in NFSv4.1
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: stid:{0} seqid:{1} */
struct OPEN_CONFIRM4args {
    /* CURRENT_FH: opened file */
    stateid4        stateid;
    seqid4          seqid;
};

/* STRFMT1: stid:{0} */
struct OPEN_CONFIRM4resok {
    stateid4        stateid;
};

/* STRFMT1: {1} */
union OPEN_CONFIRM4res switch (nfsstat4 status) {
    case NFS4_OK:
        OPEN_CONFIRM4resok     resok;
    default:
        void;
};

/*
 * OPEN_DOWNGRADE: Reduce Open File Access
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} acc:{2:#04x} deny:{3:#04x} */
struct OPEN_DOWNGRADE4args {
    /* CURRENT_FH: opened file */
    stateid4        stateid;
    seqid4          seqid;
    uint32_t        access;
    uint32_t        deny;
};

/* STRFMT1: stid:{0} */
struct OPEN_DOWNGRADE4resok {
    stateid4        stateid;
};

/* STRFMT1: {1} */
union OPEN_DOWNGRADE4res switch(nfsstat4 status) {
    case NFS4_OK:
        OPEN_DOWNGRADE4resok    resok;
    default:
        void;
};

/*
 * PUTFH: Set Current Filehandle
 * ======================================================================
 */
/* GLOBAL: nfs4_fh=fh */
/* STRFMT1: FH:{0:crc32} */
struct PUTFH4args {
    nfs_fh4         fh;
};

/* STRFMT1: "" */
struct PUTFH4res {
    /*
     * If status is NFS4_OK,
     *    new CURRENT_FH: argument to PUTFH
     */
    nfsstat4        status;
};

/*
 * PUTPUBFH: Set Public Filehandle
 * ======================================================================
 */
/* STRFMT1: "" */
struct PUTPUBFH4res {
    /*
     * If status is NFS4_OK,
     *   new CURRENT_FH: public fh
     */
    nfsstat4        status;
};

/*
 * PUTROOTFH: Set Root Filehandle
 * ======================================================================
 */
/* STRFMT1: "" */
struct PUTROOTFH4res {
    /*
     * If status is NFS4_OK,
     *   new CURRENT_FH: root fh
     */
    nfsstat4        status;
};

/*
 * READ: Read From File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{2:umax32} */
struct READ4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    count4          count;
};

/* STRFMT1: eof:{0} count:{1:umax32} */
struct READ4resok {
    bool            eof;
    opaque          data<>; /* FOPAQUE:count */
};

/* STRFMT1: {1} */
union READ4res switch (nfsstat4 status) {
    case NFS4_OK:
        READ4resok     resok;
    default:
        void;
};

/*
 * READDIR: Read Directory
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32} cookie:{0} verf:{1} count:{2:umax32} */
struct READDIR4args {
    /* CURRENT_FH: directory */
    nfs_cookie4     cookie;
    verifier4       verifier;
    count4          dircount;
    count4          maxcount;
    bitmap4         request;
};

struct entry4 {
    nfs_cookie4     cookie;
    component4      name;
    fattr4          attrs;
    entry4          *nextentry;
};

/* TRY: 1 */
/* STRFMT1: eof:{1} */
struct dirlist4 {
    entry4          *entries;
    bool            eof;
};

/* STRFMT1: verf:{0} {1} */
struct READDIR4resok {
    verifier4       verifier;
    dirlist4        reply;
};

/* STRFMT1: {1} */
union READDIR4res switch (nfsstat4 status) {
    case NFS4_OK:
        READDIR4resok  resok;
    default:
        void;
};

/*
 * READLINK: Read Symbolic Link
 * ======================================================================
 */
/* STRFMT1: {0} */
struct READLINK4resok {
    linktext4       link;
};

/* STRFMT1: {1} */
union READLINK4res switch (nfsstat4 status) {
    case NFS4_OK:
        READLINK4resok resok;
    default:
        void;
};

/*
 * REMOVE: Remove Filesystem Object
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: DH:{fh:crc32}/{0} */
struct REMOVE4args {
    /* CURRENT_FH: directory */
    component4      name;
};

struct REMOVE4resok {
    change_info4    cinfo;
};

/* STRFMT1: "" */
union REMOVE4res switch (nfsstat4 status) {
    case NFS4_OK:
        REMOVE4resok   resok;
    default:
        void;
};

/*
 * RENAME: Rename Directory Entry
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh,sfh=self.nfs4_sfh */
/* STRFMT1: {sfh:crc32}/{0} -> {fh:crc32}/{1} */
struct RENAME4args {
    /* SAVED_FH: source directory */
    component4      name;
    /* CURRENT_FH: target directory */
    component4      newname;
};

struct RENAME4resok {
    change_info4    source;
    change_info4    target;
};

/* STRFMT1: "" */
union RENAME4res switch (nfsstat4 status) {
    case NFS4_OK:
        RENAME4resok    resok;
    default:
        void;
};

/*
 * RENEW: Renew a Lease
 * ======================================================================
 * Obsolete in NFSv4.1
 */
/* STRFMT1: clientid:{0} */
struct RENEW4args {
    clientid4       clientid;
};

/* STRFMT1: "" */
struct RENEW4res {
    nfsstat4        status;
};

/*
 * RESTOREFH: Restore Saved Filehandle
 * ======================================================================
 */
/* STRFMT1: "" */
struct RESTOREFH4res {
    /*
     * If status is NFS4_OK,
     *     new CURRENT_FH: value of saved fh
     */
    nfsstat4        status;
};

/*
 * SAVEFH: Save Current Filehandle
 * ======================================================================
 */
/* STRFMT1: "" */
struct SAVEFH4res {
    /*
     * If status is NFS4_OK,
     *    new SAVED_FH: value of current fh
     */
    nfsstat4        status;
};

/*
 * SECINFO: Obtain Available Security Mechanisms
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: {fh:crc32}/{0} */
struct SECINFO4args {
    /* CURRENT_FH: directory */
    component4      name;
};

enum nfs_secflavor4 {
    AUTH_NONE  = 0;
    AUTH_SYS   = 1;
    RPCSEC_GSS = 6;
};

/*
 * From RFC 2203
 */
enum rpc_gss_svc_t {
    RPC_GSS_SVC_NONE        = 1,
    RPC_GSS_SVC_INTEGRITY   = 2,
    RPC_GSS_SVC_PRIVACY     = 3
};

/* STRFMT1: {2} */
struct rpcsec_gss_info {
    sec_oid4        oid;
    qop4            qop;
    rpc_gss_svc_t   service;
};

/* RPCSEC_GSS has a value of '6' - See RFC 2203 */
/* STRFMT1: {0} */
union secinfo4 switch (nfs_secflavor4 flavor) {
    case RPCSEC_GSS:
        /* STRFMT1: {1} */
        rpcsec_gss_info  info;
    default:
        void;
};

typedef secinfo4 SECINFO4resok<>;

/* STRFMT1: {1} */
union SECINFO4res switch (nfsstat4 status) {
    case NFS4_OK:
        /* CURRENTFH: consumed */
        SECINFO4resok resok;
    default:
        void;
};

/*
 * SETATTR: Set Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} */
struct SETATTR4args {
    /* CURRENT_FH: target object */
    stateid4        stateid;
    fattr4          attributes;
};

/* STRFMT1: attrset:{1} */
struct SETATTR4res {
    nfsstat4        status;
    bitmap4         attrset;
};

/*
 * Client ID
 */
struct nfs_client_id4 {
    verifier4  verifier;
    opaque     id<NFS4_OPAQUE_LIMIT>;
};

/*
 * Callback program info as provided by the client
 */
struct cb_client4 {
    uint32_t  cb_program;
    netaddr4  cb_location;
};

/*
 * SETCLIENTID: Negotiate Clientid
 * ======================================================================
 * Obsolete in NFSv4.1
 */
/* STRFMT1: "" */
struct SETCLIENTID4args {
    nfs_client_id4  client;
    cb_client4      callback;
    uint32_t        callback_ident;
};

/* STRFMT1: clientid:{0} */
struct SETCLIENTID4resok {
    clientid4       clientid;
    verifier4       verifier;
};

/* STRFMT1: {1} */
union SETCLIENTID4res switch (nfsstat4 status) {
    case NFS4_OK:
        SETCLIENTID4resok resok;
    case NFS4ERR_CLID_INUSE:
        /* STRFMT1: "" */
        clientaddr4       client;
    default:
        void;
};

/*
 * SETCLIENTID_CONFIRM: Confirm Clientid
 * ======================================================================
 * Obsolete in NFSv4.1
*/
/* STRFMT1: clientid:{0} */
struct SETCLIENTID_CONFIRM4args {
    clientid4       clientid;
    verifier4       verifier;
};

/* STRFMT1: "" */
struct SETCLIENTID_CONFIRM4res {
    nfsstat4        status;
};

/*
 * VERIFY: Verify Same Attributes
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: "" */
struct VERIFY4args {
    /* CURRENT_FH: object */
    fattr4          attributes;
};

/* STRFMT1: "" */
struct VERIFY4res {
    nfsstat4        status;
};

/*
 * WRITE: Write to File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{3:umax32} {2} */
struct WRITE4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    stable_how4     stable;
    opaque          data<>; /* FOPAQUE:count */
};

/* STRFMT1: count:{0:umax32} verf:{2} {1} */
struct WRITE4resok {
    count4          count;
    stable_how4     committed;
    verifier4       verifier;
};

/* STRFMT1: {1} */
union WRITE4res switch (nfsstat4 status) {
    case NFS4_OK:
        WRITE4resok    resok;
    default:
        void;
};

/*
 * RELEASE_LOCKOWNER: Notify Server to Release Lockowner State
 * ======================================================================
 * Obsolete in NFSv4.1
 */
/* STRFMT1: "" */
struct RELEASE_LOCKOWNER4args {
    lock_owner4     owner;
};

/* STRFMT1: "" */
struct RELEASE_LOCKOWNER4res {
    nfsstat4        status;
};

/*
 * ILLEGAL: Response for Illegal Operation Numbers
 * ======================================================================
 */
/* STRFMT1: "" */
struct ILLEGAL4res {
    nfsstat4        status;
};

/*
 * ======================================================================
 * Operations new to NFSv4.1
 * ======================================================================
 */
/*
 * BACKCHANNEL_CTL: Backchannel Control
 * ======================================================================
 */
struct authsys_parms {
    unsigned int  stamp;
    string        machinename<255>;
    unsigned int  uid;
    unsigned int  gid;
    unsigned int  gids<16>;
};

struct gss_cb_handles4 {
    rpc_gss_svc_t  service; /* RFC 2203 */
    gsshandle4_t   server_handle;
    gsshandle4_t   client_handle;
};

union callback_sec_parms4 switch (nfs_secflavor4 flavor) {
    case AUTH_NONE:
        void;
    case AUTH_SYS:
        authsys_parms   sys_cred; /* RFC 5531 */
    case RPCSEC_GSS:
        gss_cb_handles4 gss_handles;
};

/* STRFMT1: "" */
struct BACKCHANNEL_CTL4args {
    uint32_t                cb_program;
    callback_sec_parms4     sec_parms<>;
};

/* STRFMT1: "" */
struct BACKCHANNEL_CTL4res {
    nfsstat4 status;
};

/*
 * BIND_CONN_TO_SESSION: Associate Connection with Session
 * ======================================================================
 */
enum channel_dir_from_client4 {
    CDFC4_FORE             = 0x1,
    CDFC4_BACK             = 0x2,
    CDFC4_FORE_OR_BOTH     = 0x3,
    CDFC4_BACK_OR_BOTH     = 0x7
};

/* STRFMT1: "" */
struct BIND_CONN_TO_SESSION4args {
    sessionid4     sessionid;
    channel_dir_from_client4 dir;
    bool           rdma_mode;
};

enum channel_dir_from_server4 {
    CDFS4_FORE     = 0x1,
    CDFS4_BACK     = 0x2,
    CDFS4_BOTH     = 0x3
};

struct BIND_CONN_TO_SESSION4resok {
    sessionid4     sessionid;
    channel_dir_from_server4 dir;
    bool           rdma_mode;
};

/* STRFMT1: "" */
union BIND_CONN_TO_SESSION4res switch (nfsstat4 status) {
    case NFS4_OK:
        BIND_CONN_TO_SESSION4resok resok;
    default: void;
};

/*
 * EXCHANGE_ID: Instantiate Client ID
 * ======================================================================
 */
const EXCHGID4_FLAG_SUPP_MOVED_REFER    = 0x00000001;
const EXCHGID4_FLAG_SUPP_MOVED_MIGR     = 0x00000002;
const EXCHGID4_FLAG_SUPP_FENCE_OPS      = 0x00000004; /* New to NFSv4.2 */

const EXCHGID4_FLAG_BIND_PRINC_STATEID  = 0x00000100;

const EXCHGID4_FLAG_USE_NON_PNFS        = 0x00010000;
const EXCHGID4_FLAG_USE_PNFS_MDS        = 0x00020000;
const EXCHGID4_FLAG_USE_PNFS_DS         = 0x00040000;

const EXCHGID4_FLAG_MASK_PNFS           = 0x00070000;

const EXCHGID4_FLAG_UPD_CONFIRMED_REC_A = 0x40000000;
const EXCHGID4_FLAG_CONFIRMED_R         = 0x80000000;

struct client_owner4 {
    verifier4  verifier;
    opaque     ownerid<NFS4_OPAQUE_LIMIT>;
};

struct state_protect_ops4 {
    bitmap4 enforce;
    bitmap4 allow;
};

struct ssv_sp_parms4 {
    state_protect_ops4      ops;
    sec_oid4                hash_algs<>;
    sec_oid4                encr_algs<>;
    uint32_t                window;
    uint32_t                num_gss_handles;
};

enum state_protect_how4 {
    SP4_NONE = 0,
    SP4_MACH_CRED = 1,
    SP4_SSV = 2
};

/* STRFMT1: {0} */
union state_protect4_a switch(state_protect_how4 how) {
    case SP4_NONE:
        void;
    case SP4_MACH_CRED:
        state_protect_ops4  mach_ops;
    case SP4_SSV:
        ssv_sp_parms4       ssv_parms;
};

struct nfs_impl_id4 {
    utf8str_cis  domain;
    utf8str_cs   name;
    nfstime4     date;
};

/* STRFMT1: flags:{1:#010x} {2} */
struct EXCHANGE_ID4args {
    client_owner4           clientowner;
    uint32_t                flags;
    state_protect4_a        state_protect;
    nfs_impl_id4            client_impl_id<1>;
};

struct ssv_prot_info4 {
    state_protect_ops4     ops;
    uint32_t               hash_alg;
    uint32_t               encr_alg;
    uint32_t               ssv_len;
    uint32_t               window;
    gsshandle4_t           handles<>;
};

/* STRFMT1: {0} */
union state_protect4_r switch(state_protect_how4 how) {
    case SP4_NONE:
        void;
    case SP4_MACH_CRED:
        state_protect_ops4     mach_ops;
    case SP4_SSV:
        ssv_prot_info4         ssv_info;
};

/*
 * NFSv4.1 server Owner
 */
struct server_owner4 {
    uint64_t  minor_id;
    opaque    major_id<NFS4_OPAQUE_LIMIT>;
};

/* STRFMT1: clientid:{0} seqid:{1} flags:{2:#010x} {3} */
struct EXCHANGE_ID4resok {
    clientid4        clientid;
    sequenceid4      sequenceid;
    uint32_t         flags;
    state_protect4_r state_protect;
    server_owner4    server_owner;
    opaque           server_scope<NFS4_OPAQUE_LIMIT>;
    nfs_impl_id4     server_impl_id<1>;
};

/* STRFMT1: {1} */
union EXCHANGE_ID4res switch (nfsstat4 status) {
    case NFS4_OK:
        EXCHANGE_ID4resok  resok;
    default:
        void;
};

/*
 * CREATE_SESSION: Create New Session and Confirm Client ID
 * ======================================================================
 */
struct channel_attrs4 {
    count4                  headerpadsize;
    count4                  maxrequestsize;
    count4                  maxresponsesize;
    count4                  maxresponsesize_cached;
    count4                  maxoperations;
    count4                  maxrequests;
    uint32_t                rdma_ird<1>;
};

const CREATE_SESSION4_FLAG_PERSIST              = 0x00000001;
const CREATE_SESSION4_FLAG_CONN_BACK_CHAN       = 0x00000002;
const CREATE_SESSION4_FLAG_CONN_RDMA            = 0x00000004;

/* STRFMT1: clientid:{0} seqid:{1} flags:{2:#010x} cb_prog:{5:#010x} */
struct CREATE_SESSION4args {
    clientid4               clientid;
    sequenceid4             sequenceid;

    uint32_t                flags;

    channel_attrs4          fore_chan_attrs;
    channel_attrs4          back_chan_attrs;

    uint32_t                cb_program;
    callback_sec_parms4     sec_parms<>;
};

/* STRFMT1: sessionid:{0:crc32} seqid:{1} flags:{2:#010x} */
struct CREATE_SESSION4resok {
    sessionid4              sessionid;
    sequenceid4             sequenceid;
    uint32_t                flags;
    channel_attrs4          fore_chan_attrs;
    channel_attrs4          back_chan_attrs;
};

/* STRFMT1: {1} */
union CREATE_SESSION4res switch (nfsstat4 status) {
    case NFS4_OK:
        CREATE_SESSION4resok    resok;
    default:
        void;
};

/*
 * DESTROY_SESSION: Destroy a Session
 * ======================================================================
 */
/* STRFMT1: sessionid:{0:crc32} */
struct DESTROY_SESSION4args {
    sessionid4      sessionid;
};

/* STRFMT1: "" */
struct DESTROY_SESSION4res {
    nfsstat4 status;
};

/*
 * FREE_STATEID: Free Stateid with No Locks
 * ======================================================================
 */
/* STRFMT1: stid:{0} */
struct FREE_STATEID4args {
    stateid4        stateid;
};

/* STRFMT1: "" */
struct FREE_STATEID4res {
    nfsstat4 status;
};

/*
 * GET_DIR_DELEGATION: Get a Directory Delegation
 * ======================================================================
 */
typedef nfstime4 attr_notice4;

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: "" */
struct GET_DIR_DELEGATION4args {
    /* CURRENT_FH: delegated directory */
    bool            deleg_avail;
    bitmap4         notification;
    attr_notice4    child_attr_delay;
    attr_notice4    attr_delay;
    bitmap4         child_attributes;
    bitmap4         attributes;
};

struct GET_DIR_DELEGATION4resok {
    verifier4       verifier;
    /* Stateid for get_dir_delegation */
    stateid4        stateid;
    /* Which notifications can the server support */
    bitmap4         notification;
    bitmap4         child_attributes;
    bitmap4         attributes;
};

enum gddrnf4_status {
    GDD4_OK         = 0,
    GDD4_UNAVAIL    = 1
};

union GET_DIR_DELEGATION4res_non_fatal switch (gddrnf4_status status) {
    case GDD4_OK:
        GET_DIR_DELEGATION4resok  resok;
    case GDD4_UNAVAIL:
        bool  signal;
};

/* STRFMT1: "" */
union GET_DIR_DELEGATION4res switch (nfsstat4 status) {
    case NFS4_OK:
        GET_DIR_DELEGATION4res_non_fatal  resok;
    default:
        void;
};

/*
 * GETDEVICEINFO: Get Device Information
 * ======================================================================
 */
/* STRFMT1: devid:{0:crc16} count:{2:umax32} */
struct GETDEVICEINFO4args {
    deviceid4       deviceid;
    layouttype4     type;
    count4          maxcount;
    bitmap4         notification;
};

/* STRFMT1: {0} */
struct GETDEVICEINFO4resok {
    device_addr4    device_addr;
    bitmap4         notification;
};

/* STRFMT1: {1} */
union GETDEVICEINFO4res switch (nfsstat4 status) {
    case NFS4_OK:
        GETDEVICEINFO4resok     resok;
    case NFS4ERR_TOOSMALL:
        /* STRFMT1: count:{1:umax32} */
        count4                  mincount;
    default:
        void;
};

/*
 * GETDEVICELIST: Get All Device Mappings for a File System
 * ======================================================================
 * Obsolete in NFSv4.2
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: "" */
struct GETDEVICELIST4args {
    /* CURRENT_FH: object belonging to the file system */
    layouttype4     type;
    /* number of deviceIDs to return */
    count4          maxdevices;
    nfs_cookie4     cookie;
    verifier4       verifier;
};

struct GETDEVICELIST4resok {
    nfs_cookie4     cookie;
    verifier4       verifier;
    deviceid4       deviceid_list<>;
    bool            eof;
};

/* STRFMT1: "" */
union GETDEVICELIST4res switch (nfsstat4 status) {
    case NFS4_OK:
        GETDEVICELIST4resok     resok;
    default:
        void;
};

/*
 * LAYOUTCOMMIT: Commit Writes Made Using a Layout
 * ======================================================================
 */
union newtime4 switch (bool timechanged) {
    case TRUE:
        nfstime4           time;
    case FALSE:
        void;
};

union newoffset4 switch (bool newoffset) {
    case TRUE:
        offset4           offset;
    case FALSE:
        void;
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} off:{0:umax64} len:{1:umax64} stid:{3} */
struct LAYOUTCOMMIT4args {
    /* CURRENT_FH: file */
    offset4                 offset;
    length4                 length;
    bool                    reclaim;
    stateid4                stateid;
    newoffset4              last_write_offset;
    newtime4                time_modify;
    layoutupdate4           layoutupdate;
};

/* STRFMT1: size:{1:umax64} */
union newsize4 switch (bool sizechanged) {
    case TRUE:
        length4  size;
    case FALSE:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: {0} */
struct LAYOUTCOMMIT4resok {
    newsize4  newsize;
};

/* STRFMT1: {1} */
union LAYOUTCOMMIT4res switch (nfsstat4 status) {
    case NFS4_OK:
        LAYOUTCOMMIT4resok  resok;
    default:
        void;
};

/*
 * LAYOUTGET: Get Layout Information
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {2:@14} off:{3:umax64} len:{4:umax64} stid:{6} */
struct LAYOUTGET4args {
    /* CURRENT_FH: file */
    bool                    avail;
    layouttype4             type;
    layoutiomode4           iomode;
    offset4                 offset;
    length4                 length;
    length4                 minlength;
    stateid4                stateid;
    count4                  maxcount;
};

/* STRFMT1: stid:{1} layout:{2} */
struct LAYOUTGET4resok {
    bool               return_on_close;
    stateid4           stateid;
    layout4            layout<>;
};

/* STRFMT1: {1} */
union LAYOUTGET4res switch (nfsstat4 status) {
    case NFS4_OK:
        LAYOUTGET4resok  resok;
    case NFS4ERR_LAYOUTTRYLATER:
        /* Server will signal layout availability */
        /* STRFMT1: signal:{1} */
        bool  signal;
    default:
        void;
};

/*
 * LAYOUTRETURN: Release Layout Information
 * ======================================================================
 */
/* GLOBAL: nfs4_layouttype=type */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {2:@14} {3} */
struct LAYOUTRETURN4args {
    /* CURRENT_FH: file */
    bool           reclaim;
    layouttype4    type;
    layoutiomode4  iomode;
    layoutreturn4  layoutreturn;
};

/* STRFMT1: stid:{1} */
union layoutreturn_stateid switch (bool present) {
    case TRUE:
        stateid4  stateid;
    case FALSE:
        /* STRFMT1: "" */
        void;
};

/* STRFMT1: {1} */
union LAYOUTRETURN4res switch (nfsstat4 status) {
    case NFS4_OK:
        layoutreturn_stateid  stateid;
    default:
        void;
};

/*
 * SECINFO_NO_NAME: Get Security on Unnamed Object
 * ======================================================================
 */
enum secinfo_style4 {
    SECINFO_STYLE4_CURRENT_FH       = 0,
    SECINFO_STYLE4_PARENT           = 1
};

/*
 * Original definition
 * typedef secinfo_style4 SECINFO_NO_NAME4args;
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} {0} */
struct SECINFO_NO_NAME4args {
    /* CURRENT_FH: object or child directory */
    secinfo_style4  style;
};

/* CURRENTFH: consumed if status is NFS4_OK */
typedef SECINFO4res SECINFO_NO_NAME4res;

/*
 * SEQUENCE: Supply Per-Procedure Sequencing and Control
 * ======================================================================
 */
/* STRFMT1: "" */
struct SEQUENCE4args {
    sessionid4     sessionid;
    sequenceid4    sequenceid;
    slotid4        slotid;
    slotid4        highest_slotid;
    bool           cachethis;
};

const SEQ4_STATUS_CB_PATH_DOWN                  = 0x00000001;
const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRING      = 0x00000002;
const SEQ4_STATUS_CB_GSS_CONTEXTS_EXPIRED       = 0x00000004;
const SEQ4_STATUS_EXPIRED_ALL_STATE_REVOKED     = 0x00000008;
const SEQ4_STATUS_EXPIRED_SOME_STATE_REVOKED    = 0x00000010;
const SEQ4_STATUS_ADMIN_STATE_REVOKED           = 0x00000020;
const SEQ4_STATUS_RECALLABLE_STATE_REVOKED      = 0x00000040;
const SEQ4_STATUS_LEASE_MOVED                   = 0x00000080;
const SEQ4_STATUS_RESTART_RECLAIM_NEEDED        = 0x00000100;
const SEQ4_STATUS_CB_PATH_DOWN_SESSION          = 0x00000200;
const SEQ4_STATUS_BACKCHANNEL_FAULT             = 0x00000400;
const SEQ4_STATUS_DEVID_CHANGED                 = 0x00000800;
const SEQ4_STATUS_DEVID_DELETED                 = 0x00001000;

struct SEQUENCE4resok {
    sessionid4      sessionid;
    sequenceid4     sequenceid;
    slotid4         slotid;
    slotid4         highest_slotid;
    slotid4         target_highest_slotid;
    uint32_t        status_flags;
};

/* STRFMT1: "" */
union SEQUENCE4res switch (nfsstat4 status) {
    case NFS4_OK:
        SEQUENCE4resok  resok;
    default:
        void;
};

/*
 * SET_SSV: Update SSV for a Client ID
 * ======================================================================
 */
struct ssa_digest_input4 {
    SEQUENCE4args seqargs;
};

/* STRFMT1: "" */
struct SET_SSV4args {
    opaque          ssv<>;
    opaque          digest<>;
};

struct ssr_digest_input4 {
    SEQUENCE4res seqres;
};

struct SET_SSV4resok {
    opaque          digest<>;
};

/* STRFMT1: "" */
union SET_SSV4res switch (nfsstat4 status) {
    case NFS4_OK:
        SET_SSV4resok   resok;
    default:
        void;
};

/*
 * TEST_STATEID: Test Stateids for Validity
 * ======================================================================
 */
/* STRFMT1: stids:{0} */
struct TEST_STATEID4args {
    stateid4        stateids<>;
};

/* STRFMT1: status:{0} */
struct TEST_STATEID4resok {
    nfsstat4        status_codes<>;
};

/* STRFMT1: {1} */
union TEST_STATEID4res switch (nfsstat4 status) {
    case NFS4_OK:
        TEST_STATEID4resok resok;
    default:
        void;
};

/*
 * WANT_DELEGATION: Request Delegation
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: {0}:{fh:crc32} */
union deleg_claim4 switch (open_claim_type4 claim) {
    /*
     * No special rights to object. Ordinary delegation
     * request of the specified object. Object identified
     * by filehandle.
     */
    case CLAIM_FH:
        void;

    /*
     * Right to file based on a delegation granted
     * to a previous boot instance of the client.
     * File is specified by filehandle.
     */
    case CLAIM_DELEG_PREV_FH:
        /* CURRENT_FH: object being delegated */
        void;

    /*
     * Right to the file established by an open previous
     * to server reboot.  File identified by filehandle.
     * Used during server reclaim grace period.
     */
    case CLAIM_PREVIOUS:
        /* CURRENT_FH: object being reclaimed */
        /* STRFMT1: {0}:{fh:crc32} {1} */
        open_delegation_type4   deleg_type;
};

/* STRFMT1: want:{0:#x} {1} */
struct WANT_DELEGATION4args {
    uint32_t      want;
    deleg_claim4  claim;
};

/* STRFMT1: {1} */
union WANT_DELEGATION4res switch (nfsstat4 status) {
    case NFS4_OK:
        open_delegation4  resok;
    default:
        void;
};

/*
 * DESTROY_CLIENTID: Destroy a Client ID
 * ======================================================================
 */
/* STRFMT1: clientid:{0} */
struct DESTROY_CLIENTID4args {
    clientid4       clientid;
};

/* STRFMT1: "" */
struct DESTROY_CLIENTID4res {
    nfsstat4        status;
};

/*
 * RECLAIM_COMPLETE: Indicates Reclaims Finished
 * ======================================================================
 */
/*
 * Original definition
 * struct RECLAIM_COMPLETE4args {
 *     bool  one_fs;
 * };
 */
/* STRFMT1: "" */
union RECLAIM_COMPLETE4args switch (bool one_fs) {
    case TRUE:
        /*
         * If one_fs TRUE,
         *    CURRENT_FH: object in filesystem reclaim is complete for.
         */
        /* OBJATTR: fh=self.nfs4_fh */
        /* STRFMT1: FH:{fh:crc32} */
        void;
    default:
        void;
};

/* STRFMT1: "" */
struct RECLAIM_COMPLETE4res {
    nfsstat4        status;
};

/*
 * ======================================================================
 * Operations new to NFSv4.2
 * ======================================================================
 */

/*
 * ALLOCATE: Reserve Space in A Region of a File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{2:umax64} */
struct ALLOCATE4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    length4         length;
};

/* STRFMT1: "" */
struct ALLOCATE4res {
    nfsstat4        status;
};

/*
 * COPY: Initiate a server-side copy
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh,sfh=self.nfs4_sfh */
/* STRFMT1: FH:{fh:crc32} src:(stid:{0} off:{2:umax64}) dst:(stid:{1} off:{3:umax64}) len:{4:umax64} */
struct COPY4args {
    /* SAVED_FH: source file */
    /* CURRENT_FH: destination file */
    stateid4        src_stateid;
    stateid4        dst_stateid;
    offset4         src_offset;
    offset4         dst_offset;
    length4         count;
    bool            consecutive;
    bool            synchronous;
    netloc4         src_servers<>;
};

/* STRFMT1: {0:?stid\:{0} }len:{1:umax64} verf:{3} {2} */
struct write_response4 {
    stateid4        stateid<1>;
    length4         count;
    stable_how4     committed;
    verifier4       verifier;
};

/* STRFMT1: cons:{0} sync:{1} */
struct copy_requirements4 {
    bool            consecutive;
    bool            synchronous;
};

/* STRFMT1: {0} {1} */
struct COPY4resok {
    write_response4         response;     /* FLATATTR:1 */
    copy_requirements4      requirements; /* FLATATTR:1 */
};

/* STRFMT1: {1} */
union COPY4res switch (nfsstat4 status) {
    case NFS4_OK:
        COPY4resok              resok;
    case NFS4ERR_OFFLOAD_NO_REQS:
        copy_requirements4      requirements;
    default:
        void;
};

/*
 * COPY_NOTIFY: Notify a Source Server of a Future Copy
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} {1} */
struct COPY_NOTIFY4args {
    /* CURRENT_FH: source file */
    stateid4  stateid;
    netloc4   dst_server;
};

/* STRFMT1: stid:{1} {2} */
struct COPY_NOTIFY4resok {
    nfstime4  lease_time;
    stateid4  stateid;
    netloc4   src_servers<>;
};

/* STRFMT1: {1} */
union COPY_NOTIFY4res switch (nfsstat4 status) {
    case NFS4_OK:
        COPY_NOTIFY4resok resok;
    default:
        void;
};

/*
 * DEALLOCATE: Unreserve Space in a Region of a File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{2:umax64} */
struct DEALLOCATE4args {
    /* CURRENT_FH: file */
    stateid4  stateid;
    offset4   offset;
    length4   length;
};

/* STRFMT1: "" */
struct DEALLOCATE4res {
    nfsstat4  status;
};

/*
 * IO_ADVISE: Application I/O Access Pattern Hints
 * ======================================================================
 */
enum IO_ADVISE_type4 {
    IO_ADVISE4_NORMAL                  = 0,
    IO_ADVISE4_SEQUENTIAL              = 1,
    IO_ADVISE4_SEQUENTIAL_BACKWARDS    = 2,
    IO_ADVISE4_RANDOM                  = 3,
    IO_ADVISE4_WILLNEED                = 4,
    IO_ADVISE4_WILLNEED_OPPORTUNISTIC  = 5,
    IO_ADVISE4_DONTNEED                = 6,
    IO_ADVISE4_NOREUSE                 = 7,
    IO_ADVISE4_READ                    = 8,
    IO_ADVISE4_WRITE                   = 9,
    IO_ADVISE4_INIT_PROXIMITY          = 10
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{2:umax64} hints:{3} */
struct IO_ADVISE4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    length4         count;
    bitmap4         hints;
};

/* STRFMT1: hints:{0} */
struct IO_ADVISE4resok {
    bitmap4         hints;
};

/* STRFMT1: {1} */
union IO_ADVISE4res switch (nfsstat4 status) {
    case NFS4_OK:
        IO_ADVISE4resok resok;
    default:
        void;
};

/*
 * LAYOUTERROR: Provide Errors for the Layout
 * ======================================================================
 */
/* STRFMT1: devid:{0:crc16} stat:{1} op:{2} */
struct device_error4 {
    deviceid4       deviceid;
    nfsstat4        status;
    nfs_opnum4      opnum;
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} off:{0:umax64} len:{1:umax64} stid:{2} {3} */
struct LAYOUTERROR4args {
    /* CURRENT_FH: file */
    offset4         offset;
    length4         length;
    stateid4        stateid;
    device_error4   errors<>;
};

/* STRFMT1: "" */
struct LAYOUTERROR4res {
    nfsstat4        status;
};

/*
 * LAYOUTSTATS: Provide Statistics for the Layout
 * ======================================================================
 */
/* STRFMT1: count:{0:umax64} bytes:{1:umax64} */
struct io_info4 {
    uint64_t        count;
    uint64_t        bytes;
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} off:{0:umax64} len:{1:umax64} stid:{2} */
struct LAYOUTSTATS4args {
    /* CURRENT_FH: file */
    offset4         offset;
    length4         length;
    stateid4        stateid;
    io_info4        read;
    io_info4        write;
    deviceid4       deviceid;
    layoutupdate4   layoutupdate;
};

/* STRFMT1: "" */
struct LAYOUTSTATS4res {
    nfsstat4        status;
};

/*
 * OFFLOAD_CANCEL: Stop an Offloaded Operation
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} */
struct OFFLOAD_CANCEL4args {
    /* CURRENT_FH: file to cancel */
    stateid4        stateid;
};

/* STRFMT1: "" */
struct OFFLOAD_CANCEL4res {
    nfsstat4        status;
};

/*
 * OFFLOAD_STATUS: Poll for Status of Asynchronous Operation
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} */
struct OFFLOAD_STATUS4args {
    /* CURRENT_FH: destination file */
    stateid4        stateid;
};

/* STRFMT1: len:{0:umax64} {1} */
struct OFFLOAD_STATUS4resok {
    length4         count;
    nfsstat4        complete<1>;
};

/* STRFMT1: {1} */
union OFFLOAD_STATUS4res switch (nfsstat4 status) {
    case NFS4_OK:
        OFFLOAD_STATUS4resok  resok;
    default:
        void;
};

/*
 * READ_PLUS: READ Data or Holes from a File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} len:{2:umax32} */
struct READ_PLUS4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    count4          count;
};

enum data_content4 {
    NFS4_CONTENT_DATA = 0,
    NFS4_CONTENT_HOLE = 1
};

/* STRFMT1: off:{0:umax64} count:{1:umax32} */
struct data4 {
    offset4         offset;
    opaque          data<>; /* FOPAQUE:count */
};

/* STRFMT1: off:{0:umax64} len:{1:umax64} */
struct data_info4 {
    offset4         offset;
    length4         count;
};

/* STRFMT1: {1} */
union read_plus_content switch (data_content4 content) {
    case NFS4_CONTENT_DATA:
        data4       data;
    case NFS4_CONTENT_HOLE:
        data_info4  hole;
    default:
        void;
};

/*
 * Allow a return of an array of contents.
 */
/* STRFMT1: eof:{0} {1} */
struct read_plus_res4 {
    bool               eof;
    read_plus_content  contents<>;
};

/* STRFMT1: {1} */
union READ_PLUS4res switch (nfsstat4 status) {
    case NFS4_OK:
        read_plus_res4  resok;
    default:
        void;
};

/*
 * SEEK: Find the Next Data or Hole
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} off:{1:umax64} {2} */
struct SEEK4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    offset4         offset;
    data_content4   what;
};

/* STRFMT1: eof:{0} off:{1:umax64} */
struct seek_res4 {
    bool            eof;
    offset4         offset;
};

/* STRFMT1: {1} */
union SEEK4res switch (nfsstat4 status) {
    case NFS4_OK:
        seek_res4   resok;
    default:
        void;
};

/*
 * WRITE_SAME: WRITE an ADB Multiple Times to a File
 * ======================================================================
 */
/* STRFMT1: off:{0:umax64} bsize:{1:umax64} bcount:{2:umax64} */
struct app_data_block4 {
    offset4         offset;
    length4         block_size;
    length4         block_count;
    length4         reloff_blocknum;
    count4          block_num;
    length4         reloff_pattern;
    opaque          pattern<>;
};

/* OBJATTR: fh=self.nfs4_fh */
/* STRFMT1: FH:{fh:crc32} stid:{0} {2} {1} */
struct WRITE_SAME4args {
    /* CURRENT_FH: file */
    stateid4        stateid;
    stable_how4     stable;
    app_data_block4 adb;
};

/* STRFMT1: {1} */
union WRITE_SAME4res switch (nfsstat4 status) {
    case NFS4_OK:
        write_response4  resok;
    default:
        void;
};

/*
 * CLONE: Clone a Range of File Into Another File
 * ======================================================================
 */
/* OBJATTR: fh=self.nfs4_fh,sfh=self.nfs4_sfh */
/* STRFMT1: FH:{fh:crc32} src:(stid:{0} off:{2:umax64}) dst:(stid:{1} off:{3:umax64}) len:{4:umax64} */
struct CLONE4args {
    /* SAVED_FH: source file */
    /* CURRENT_FH: destination file */
    stateid4        src_stateid;
    stateid4        dst_stateid;
    offset4         src_offset;
    offset4         dst_offset;
    length4         count;
};

/* STRFMT1: "" */
struct CLONE4res {
    nfsstat4        status;
};

/* OBJATTR: op=argop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_argop4 switch (nfs_opnum4 argop) {
    case OP_ACCESS:
        ACCESS4args opaccess;
    case OP_CLOSE:
        CLOSE4args opclose;
    case OP_COMMIT:
        COMMIT4args opcommit;
    case OP_CREATE:
        CREATE4args opcreate;
    case OP_DELEGPURGE:
        DELEGPURGE4args opdelegpurge;
    case OP_DELEGRETURN:
        DELEGRETURN4args opdelegreturn;
    case OP_GETATTR:
        GETATTR4args opgetattr;
    case OP_GETFH:
        /* STRFMT2: GETFH4args() */
        void;
    case OP_LINK:
        LINK4args oplink;
    case OP_LOCK:
        LOCK4args oplock;
    case OP_LOCKT:
        LOCKT4args oplockt;
    case OP_LOCKU:
        LOCKU4args oplocku;
    case OP_LOOKUP:
        LOOKUP4args oplookup;
    case OP_LOOKUPP:
        /* STRFMT2: LOOKUPP4args() */
        void;
    case OP_NVERIFY:
        NVERIFY4args opnverify;
    case OP_OPEN:
        OPEN4args opopen;
    case OP_OPENATTR:
        OPENATTR4args opopenattr;
    case OP_OPEN_CONFIRM:
        /* Not used in NFSv4.1 */
        OPEN_CONFIRM4args opopen_confirm;
    case OP_OPEN_DOWNGRADE:
        OPEN_DOWNGRADE4args opopen_downgrade;
    case OP_PUTFH:
        PUTFH4args opputfh;
    case OP_PUTPUBFH:
        /* STRFMT2: PUTPUBFH4args() */
        void;
    case OP_PUTROOTFH:
        /* STRFMT2: PUTROOTFH4args() */
        void;
    case OP_READ:
        READ4args opread;
    case OP_READDIR:
        READDIR4args opreaddir;
    case OP_READLINK:
        /* OBJATTR: fh=self.nfs4_fh */
        /* STRFMT1: FH:{fh:crc32} */
        /* STRFMT2: READLINK4args() */
        void;
    case OP_REMOVE:
        REMOVE4args opremove;
    case OP_RENAME:
        RENAME4args oprename;
    case OP_RENEW:
        /* Not used in NFSv4.1 */
        RENEW4args oprenew;
    case OP_RESTOREFH:
        /* GLOBAL: nfs4_fh=self.nfs4_sfh */
        /* STRFMT2: RESTOREFH4args() */
        void;
    case OP_SAVEFH:
        /* GLOBAL: nfs4_sfh=self.nfs4_fh */
        /* STRFMT2: SAVEFH4args() */
        void;
    case OP_SECINFO:
        SECINFO4args opsecinfo;
    case OP_SETATTR:
        SETATTR4args opsetattr;
    case OP_SETCLIENTID:
        /* Not used in NFSv4.1 */
        SETCLIENTID4args opsetclientid;
    case OP_SETCLIENTID_CONFIRM:
        /* Not used in NFSv4.1 */
        SETCLIENTID_CONFIRM4args opsetclientid_confirm;
    case OP_VERIFY:
        VERIFY4args opverify;
    case OP_WRITE:
        WRITE4args opwrite;
    case OP_RELEASE_LOCKOWNER:
        /* Not used in NFSv4.1 */
        RELEASE_LOCKOWNER4args oprelease_lockowner;

    /* New to NFSv4.1 */
    case OP_BACKCHANNEL_CTL:
        BACKCHANNEL_CTL4args opbackchannel_ctl;
    case OP_BIND_CONN_TO_SESSION:
        BIND_CONN_TO_SESSION4args opbind_conn_to_session;
    case OP_EXCHANGE_ID:
        EXCHANGE_ID4args opexchange_id;
    case OP_CREATE_SESSION:
        CREATE_SESSION4args opcreate_session;
    case OP_DESTROY_SESSION:
        DESTROY_SESSION4args opdestroy_session;
    case OP_FREE_STATEID:
        FREE_STATEID4args opfree_stateid;
    case OP_GET_DIR_DELEGATION:
        GET_DIR_DELEGATION4args opget_dir_delegation;
    case OP_GETDEVICEINFO:
        GETDEVICEINFO4args opgetdeviceinfo;
    case OP_GETDEVICELIST:
        /* Not used in NFSv4.2 */
        GETDEVICELIST4args opgetdevicelist;
    case OP_LAYOUTCOMMIT:
        LAYOUTCOMMIT4args oplayoutcommit;
    case OP_LAYOUTGET:
        LAYOUTGET4args oplayoutget;
    case OP_LAYOUTRETURN:
        LAYOUTRETURN4args oplayoutreturn;
    case OP_SECINFO_NO_NAME:
        SECINFO_NO_NAME4args opsecinfo_no_name;
    case OP_SEQUENCE:
        SEQUENCE4args opsequence;
    case OP_SET_SSV:
        SET_SSV4args opset_ssv;
    case OP_TEST_STATEID:
        TEST_STATEID4args optest_stateid;
    case OP_WANT_DELEGATION:
        WANT_DELEGATION4args opwant_delegation;
    case OP_DESTROY_CLIENTID:
        DESTROY_CLIENTID4args opdestroy_clientid;
    case OP_RECLAIM_COMPLETE:
        RECLAIM_COMPLETE4args opreclaim_complete;

    /* New to NFSv4.2 */
    case OP_ALLOCATE:
        ALLOCATE4args opallocate;
    case OP_COPY:
        COPY4args opcopy;
    case OP_COPY_NOTIFY:
        COPY_NOTIFY4args opcopy_notify;
    case OP_DEALLOCATE:
        DEALLOCATE4args opdeallocate;
    case OP_IO_ADVISE:
        IO_ADVISE4args opio_advise;
    case OP_LAYOUTERROR:
        LAYOUTERROR4args oplayouterror;
    case OP_LAYOUTSTATS:
        LAYOUTSTATS4args oplayoutstats;
    case OP_OFFLOAD_CANCEL:
        OFFLOAD_CANCEL4args opoffload_cancel;
    case OP_OFFLOAD_STATUS:
        OFFLOAD_STATUS4args opoffload_status;
    case OP_READ_PLUS:
        READ_PLUS4args opread_plus;
    case OP_SEEK:
        SEEK4args opseek;
    case OP_WRITE_SAME:
        WRITE_SAME4args opwrite_same;
    case OP_CLONE:
        CLONE4args opclone;

    case OP_ILLEGAL:
        /* Illegal operation */
        /* STRFMT2: ILLEGAL4args() */
        void;
};

/* OBJATTR: op=resop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_resop4 switch (nfs_opnum4 resop){
    case OP_ACCESS:
        ACCESS4res opaccess;
    case OP_CLOSE:
        CLOSE4res opclose;
    case OP_COMMIT:
        COMMIT4res opcommit;
    case OP_CREATE:
        CREATE4res opcreate;
    case OP_DELEGPURGE:
        DELEGPURGE4res opdelegpurge;
    case OP_DELEGRETURN:
        DELEGRETURN4res opdelegreturn;
    case OP_GETATTR:
        GETATTR4res opgetattr;
    case OP_GETFH:
        GETFH4res opgetfh;
    case OP_LINK:
        LINK4res oplink;
    case OP_LOCK:
        LOCK4res oplock;
    case OP_LOCKT:
        LOCKT4res oplockt;
    case OP_LOCKU:
        LOCKU4res oplocku;
    case OP_LOOKUP:
        LOOKUP4res oplookup;
    case OP_LOOKUPP:
        LOOKUPP4res oplookupp;
    case OP_NVERIFY:
        NVERIFY4res opnverify;
    case OP_OPEN:
        OPEN4res opopen;
    case OP_OPENATTR:
        OPENATTR4res opopenattr;
    case OP_OPEN_CONFIRM:
        /* Not used in NFSv4.1 */
        OPEN_CONFIRM4res opopen_confirm;
    case OP_OPEN_DOWNGRADE:
        OPEN_DOWNGRADE4res opopen_downgrade;
    case OP_PUTFH:
        PUTFH4res opputfh;
    case OP_PUTPUBFH:
        PUTPUBFH4res opputpubfh;
    case OP_PUTROOTFH:
        PUTROOTFH4res opputrootfh;
    case OP_READ:
        READ4res opread;
    case OP_READDIR:
        READDIR4res opreaddir;
    case OP_READLINK:
        READLINK4res opreadlink;
    case OP_REMOVE:
        REMOVE4res opremove;
    case OP_RENAME:
        RENAME4res oprename;
    case OP_RENEW:
        /* Not used in NFSv4.1 */
        RENEW4res oprenew;
    case OP_RESTOREFH:
        RESTOREFH4res oprestorefh;
    case OP_SAVEFH:
        SAVEFH4res opsavefh;
    case OP_SECINFO:
        SECINFO4res opsecinfo;
    case OP_SETATTR:
        SETATTR4res opsetattr;
    case OP_SETCLIENTID:
        /* Not used in NFSv4.1 */
        SETCLIENTID4res opsetclientid;
    case OP_SETCLIENTID_CONFIRM:
        /* Not used in NFSv4.1 */
        SETCLIENTID_CONFIRM4res opsetclientid_confirm;
    case OP_VERIFY:
        VERIFY4res opverify;
    case OP_WRITE:
        WRITE4res opwrite;
    case OP_RELEASE_LOCKOWNER:
        /* Not used in NFSv4.1 */
        RELEASE_LOCKOWNER4res oprelease_lockowner;

    /* New to NFSv4.1 */
    case OP_BACKCHANNEL_CTL:
        BACKCHANNEL_CTL4res opbackchannel_ctl;
    case OP_BIND_CONN_TO_SESSION:
        BIND_CONN_TO_SESSION4res opbind_conn_to_session;
    case OP_EXCHANGE_ID:
        EXCHANGE_ID4res opexchange_id;
    case OP_CREATE_SESSION:
        CREATE_SESSION4res opcreate_session;
    case OP_DESTROY_SESSION:
        DESTROY_SESSION4res opdestroy_session;
    case OP_FREE_STATEID:
        FREE_STATEID4res opfree_stateid;
    case OP_GET_DIR_DELEGATION:
        GET_DIR_DELEGATION4res opget_dir_delegation;
    case OP_GETDEVICEINFO:
        GETDEVICEINFO4res opgetdeviceinfo;
    case OP_GETDEVICELIST:
        /* Not used in NFSv4.2 */
        GETDEVICELIST4res opgetdevicelist;
    case OP_LAYOUTCOMMIT:
        LAYOUTCOMMIT4res oplayoutcommit;
    case OP_LAYOUTGET:
        LAYOUTGET4res oplayoutget;
    case OP_LAYOUTRETURN:
        LAYOUTRETURN4res oplayoutreturn;
    case OP_SECINFO_NO_NAME:
        SECINFO_NO_NAME4res opsecinfo_no_name;
    case OP_SEQUENCE:
        SEQUENCE4res opsequence;
    case OP_SET_SSV:
        SET_SSV4res opset_ssv;
    case OP_TEST_STATEID:
        TEST_STATEID4res optest_stateid;
    case OP_WANT_DELEGATION:
        WANT_DELEGATION4res opwant_delegation;
    case OP_DESTROY_CLIENTID:
        DESTROY_CLIENTID4res opdestroy_clientid;
    case OP_RECLAIM_COMPLETE:
        RECLAIM_COMPLETE4res opreclaim_complete;

    /* New to NFSv4.2 */
    case OP_ALLOCATE:
        ALLOCATE4res opallocate;
    case OP_COPY:
        COPY4res opcopy;
    case OP_COPY_NOTIFY:
        COPY_NOTIFY4res opcopy_notify;
    case OP_DEALLOCATE:
        DEALLOCATE4res opdeallocate;
    case OP_IO_ADVISE:
        IO_ADVISE4res opio_advise;
    case OP_LAYOUTERROR:
        LAYOUTERROR4res oplayouterror;
    case OP_LAYOUTSTATS:
        LAYOUTSTATS4res oplayoutstats;
    case OP_OFFLOAD_CANCEL:
        OFFLOAD_CANCEL4res opoffload_cancel;
    case OP_OFFLOAD_STATUS:
        OFFLOAD_STATUS4res opoffload_status;
    case OP_READ_PLUS:
        READ_PLUS4res opread_plus;
    case OP_SEEK:
        SEEK4res opseek;
    case OP_WRITE_SAME:
        WRITE_SAME4res opwrite_same;
    case OP_CLONE:
        CLONE4res opclone;

    case OP_ILLEGAL:
        /* Illegal operation */
        ILLEGAL4res opillegal;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None,nfs4_sfh=None,nfs4_layouttype=None */
struct COMPOUND4args {
    utf8str_cs      tag;
    uint32_t        minorversion;
    nfs_argop4      array<>;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None,nfs4_sfh=None,nfs4_layouttype=None */
/* XARG: minorversion */
struct COMPOUND4res {
    nfsstat4        status;
    utf8str_cs      tag;
    nfs_resop4      array<>;
};

/*
 * ======================================================================
 * NFS4 Callback Operation Definitions
 * ======================================================================
 */

/*
 * Callback operation array
 */
enum nfs_cb_opnum4 {
    OP_CB_GETATTR               = 3,
    OP_CB_RECALL                = 4,
    /* Callback operations new to NFSv4.1 */
    OP_CB_LAYOUTRECALL          = 5,
    OP_CB_NOTIFY                = 6,
    OP_CB_PUSH_DELEG            = 7,
    OP_CB_RECALL_ANY            = 8,
    OP_CB_RECALLABLE_OBJ_AVAIL  = 9,
    OP_CB_RECALL_SLOT           = 10,
    OP_CB_SEQUENCE              = 11,
    OP_CB_WANTS_CANCELLED       = 12,
    OP_CB_NOTIFY_LOCK           = 13,
    OP_CB_NOTIFY_DEVICEID       = 14,
    /* Callback operations new to NFSv4.2 */
    OP_CB_OFFLOAD               = 15,
    /* Illegal callback operation */
    OP_CB_ILLEGAL               = 10044
};

/*
 * CB_GETATTR: Get Attributes of a File That Has Been Write Delegated
 * ======================================================================
 */
/* STRFMT1: FH:{0:crc32} request:{1} */
struct CB_GETATTR4args {
    nfs_fh4 fh;
    bitmap4 request;
};

struct CB_GETATTR4resok {
    fattr4  attributes;
};

/* STRFMT1: "" */
union CB_GETATTR4res switch (nfsstat4 status) {
    case NFS4_OK:
        CB_GETATTR4resok       resok;
    default:
        void;
};

/*
 * CB_RECALL: Recall an Open Delegation
 * ======================================================================
 */
/* STRFMT1: FH:{2:crc32} stid:{0} trunc:{1} */
struct CB_RECALL4args {
    stateid4        stateid;
    bool            truncate;
    nfs_fh4         fh;
};

/* STRFMT1: "" */
struct CB_RECALL4res {
    nfsstat4        status;
};

/*
 * CB_ILLEGAL: Response for illegal operation numbers
 * ======================================================================
 */
/* STRFMT1: "" */
struct CB_ILLEGAL4res {
    nfsstat4        status;
};

/*
 * NFSv4.1 callback arguments and results
 */

/*
 * CB_LAYOUTRECALL: Recall Layout from Client
 * ======================================================================
 */
enum layoutrecall_type4 {
    LAYOUTRECALL4_FILE = LAYOUT4_RET_REC_FILE,
    LAYOUTRECALL4_FSID = LAYOUT4_RET_REC_FSID,
    LAYOUTRECALL4_ALL  = LAYOUT4_RET_REC_ALL
};

/* STRFMT1: FH:{0:crc32} stid:{3} off:{1:umax64} len:{2:umax64} */
struct layoutrecall_file4 {
    nfs_fh4         fh;
    offset4         offset;
    length4         length;
    stateid4        stateid;
};

/* STRFMT1: {1} */
union layoutrecall4 switch(layoutrecall_type4 recalltype) {
    case LAYOUTRECALL4_FILE:
        layoutrecall_file4 layout;
    case LAYOUTRECALL4_FSID:
        fsid4              fsid;
    case LAYOUTRECALL4_ALL:
        void;
};

/* STRFMT1: {1:@14} {3} */
struct CB_LAYOUTRECALL4args {
    layouttype4             type;
    layoutiomode4           iomode;
    bool                    changed;
    layoutrecall4           recall;
};

/* STRFMT1: "" */
struct CB_LAYOUTRECALL4res {
    nfsstat4        status;
};

/*
 * CB_NOTIFY: Notify Client of Directory Changes
 * ======================================================================
 */

/*
 * Directory notification types.
 */
enum notify_type4 {
    NOTIFY4_CHANGE_CHILD_ATTRS     = 0,
    NOTIFY4_CHANGE_DIR_ATTRS       = 1,
    NOTIFY4_REMOVE_ENTRY           = 2,
    NOTIFY4_ADD_ENTRY              = 3,
    NOTIFY4_RENAME_ENTRY           = 4,
    NOTIFY4_CHANGE_COOKIE_VERIFIER = 5
};

/* Changed entry information.  */
struct notify_entry4 {
    component4      name;
    fattr4          attrs;
};

/* Previous entry information */
struct prev_entry4 {
    notify_entry4   entry;
    /* what READDIR returned for this entry */
    nfs_cookie4     cookie;
};

struct notify_remove4 {
    notify_entry4   entry;
    nfs_cookie4     cookie;
};

struct notify_add4 {
    /*
     * Information on object
     * possibly renamed over.
     */
    notify_remove4      old_entry<1>;
    notify_entry4       new_entry;
    /* what READDIR would have returned for this entry */
    nfs_cookie4         new_cookie<1>;
    prev_entry4         prev_entry<1>;
    bool                last_entry;
};

struct notify_attr4 {
    notify_entry4   entry;
};

struct notify_rename4 {
    notify_remove4  old_entry;
    notify_add4     new_entry;
};

struct notify_verifier4 {
    verifier4       old_verifier;
    verifier4       new_verifier;
};

/*
 * Objects of type notify_<>4 and
 * notify_device_<>4 are encoded in this.
 */
typedef opaque notifylist4<>; /* STRHEX:1 */

struct notify4 {
    /* composed from notify_type4 or notify_deviceid_type4 */
    bitmap4         mask;
    notifylist4     values;
};

/* STRFMT1: FH:{1:crc32} stid:{0} */
struct CB_NOTIFY4args {
    stateid4    stateid;
    nfs_fh4     fh;
    notify4     changes<>;
};

/* STRFMT1: "" */
struct CB_NOTIFY4res {
    nfsstat4    status;
};

/*
 * CB_PUSH_DELEG: Offer Previously Requested Delegation to Client
 * ======================================================================
 */
/* STRFMT1: FH:{0:crc32} {1} */
struct CB_PUSH_DELEG4args {
    nfs_fh4          fh;
    open_delegation4 delegation;

};

/* STRFMT1: "" */
struct CB_PUSH_DELEG4res {
    nfsstat4 status;
};

/*
 * CB_RECALL_ANY: Keep Any N Recallable Objects
 * ======================================================================
 */
const RCA4_TYPE_MASK_RDATA_DLG          = 0;
const RCA4_TYPE_MASK_WDATA_DLG          = 1;
const RCA4_TYPE_MASK_DIR_DLG            = 2;
const RCA4_TYPE_MASK_FILE_LAYOUT        = 3;
const RCA4_TYPE_MASK_BLK_LAYOUT         = 4;
const RCA4_TYPE_MASK_OBJ_LAYOUT_MIN     = 8;
const RCA4_TYPE_MASK_OBJ_LAYOUT_MAX     = 9;
const RCA4_TYPE_MASK_OTHER_LAYOUT_MIN   = 12;
const RCA4_TYPE_MASK_OTHER_LAYOUT_MAX   = 15;

/* STRFMT1: keep:{0} mask:{1} */
struct CB_RECALL_ANY4args      {
    uint32_t        objects_to_keep;
    bitmap4         mask;
};

/* STRFMT1: "" */
struct CB_RECALL_ANY4res {
    nfsstat4        status;
};

/*
 * CB_RECALLABLE_OBJ_AVAIL: Signal Resources for Recallable Objects
 * ======================================================================
 */
typedef CB_RECALL_ANY4args CB_RECALLABLE_OBJ_AVAIL4args;

/* STRFMT1: "" */
struct CB_RECALLABLE_OBJ_AVAIL4res {
    nfsstat4        status;
};

/*
 * CB_RECALL_SLOT: Change Flow Control Limits
 * ======================================================================
 */
/* STRFMT1: slotid:{0}  */
struct CB_RECALL_SLOT4args {
    slotid4       target_highest_slotid;
};

/* STRFMT1: "" */
struct CB_RECALL_SLOT4res {
    nfsstat4   status;
};

/*
 * CB_SEQUENCE: Supply Backchannel Sequencing and Control
 * ======================================================================
 */
struct referring_call4 {
    sequenceid4     sequenceid;
    slotid4         slotid;
};

struct referring_call_list4 {
    sessionid4      sessionid;
    referring_call4 referring_calls<>;
};

/* STRFMT1: "" */
struct CB_SEQUENCE4args {
    sessionid4           sessionid;
    sequenceid4          sequenceid;
    slotid4              slotid;
    slotid4              highest_slotid;
    bool                 cachethis;
    referring_call_list4 referring_call_lists<>;
};

struct CB_SEQUENCE4resok {
    sessionid4         sessionid;
    sequenceid4        sequenceid;
    slotid4            slotid;
    slotid4            highest_slotid;
    slotid4            target_highest_slotid;
};

/* STRFMT1: "" */
union CB_SEQUENCE4res switch (nfsstat4 status) {
    case NFS4_OK:
        CB_SEQUENCE4resok  resok;
    default:
        void;
};

/*
 * CB_WANTS_CANCELLED: Cancel Pending Delegation Wants
 * ======================================================================
 */
/* STRFMT1: contended:{0} resourced:{1} */
struct CB_WANTS_CANCELLED4args {
    bool contended;
    bool resourced;
};

/* STRFMT1: "" */
struct CB_WANTS_CANCELLED4res {
    nfsstat4        status;
};

/*
 * CB_NOTIFY_LOCK: Notify Client of Possible Lock Availability
 * ======================================================================
 */
/* STRFMT1: FH:{0:crc32} */
struct CB_NOTIFY_LOCK4args {
    nfs_fh4      fh;
    lock_owner4  lock_owner;
};

/* STRFMT1: "" */
struct CB_NOTIFY_LOCK4res {
    nfsstat4  status;
};

/*
 * CB_NOTIFY_DEVICEID: Notify Client of Device ID Changes
 * ======================================================================
 */
/*
 * Device notification types.
 */
enum notify_deviceid_type4 {
    NOTIFY_DEVICEID4_CHANGE = 1,
    NOTIFY_DEVICEID4_DELETE = 2
};

/* For NOTIFY4_DEVICEID4_DELETE */
struct notify_deviceid_delete4 {
    layouttype4     type;
    deviceid4       deviceid;
};

/* For NOTIFY4_DEVICEID4_CHANGE */
struct notify_deviceid_change4 {
    layouttype4     type;
    deviceid4       deviceid;
    bool            immediate;
};

/* STRFMT1: "" */
struct CB_NOTIFY_DEVICEID4args {
    notify4 changes<>;
};

/* STRFMT1: "" */
struct CB_NOTIFY_DEVICEID4res {
    nfsstat4        status;
};

/*
 * New to NFSv4.2
 * ======================================================================
 */

/*
 * CB_OFFLOAD: Report Results of an Asynchronous Operation
 * ======================================================================
 */
/* STRFMT1: {1} */
union offload_info4 switch (nfsstat4 status) {
    case NFS4_OK:
        write_response4 resok;
    default:
        /* STRFMT1: len:{1} {0} */
        length4         count;
};

/* STRFMT1: FH:{0:crc32} stid:{1} {2} */
struct CB_OFFLOAD4args {
    nfs_fh4         fh;
    stateid4        stateid;
    offload_info4   info; /* FLATATTR:1 */
};

/* STRFMT1: "" */
struct CB_OFFLOAD4res {
    nfsstat4        status;
};

/* OBJATTR: op=argop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_cb_argop4 switch (nfs_cb_opnum4 argop) {
    case OP_CB_GETATTR:
        CB_GETATTR4args opcbgetattr;
    case OP_CB_RECALL:
        CB_RECALL4args opcbrecall;

    /* New to NFSv4.1 */
    case OP_CB_LAYOUTRECALL:
        CB_LAYOUTRECALL4args opcblayoutrecall;
    case OP_CB_NOTIFY:
        CB_NOTIFY4args opcbnotify;
    case OP_CB_PUSH_DELEG:
        CB_PUSH_DELEG4args opcbpush_deleg;
    case OP_CB_RECALL_ANY:
        CB_RECALL_ANY4args opcbrecall_any;
    case OP_CB_RECALLABLE_OBJ_AVAIL:
        CB_RECALLABLE_OBJ_AVAIL4args opcbrecallable_obj_avail;
    case OP_CB_RECALL_SLOT:
        CB_RECALL_SLOT4args opcbrecall_slot;
    case OP_CB_SEQUENCE:
        CB_SEQUENCE4args opcbsequence;
    case OP_CB_WANTS_CANCELLED:
        CB_WANTS_CANCELLED4args opcbwants_cancelled;
    case OP_CB_NOTIFY_LOCK:
        CB_NOTIFY_LOCK4args opcbnotify_lock;
    case OP_CB_NOTIFY_DEVICEID:
        CB_NOTIFY_DEVICEID4args opcbnotify_deviceid;

    /* New to NFSv4.2 */
    case OP_CB_OFFLOAD:
        CB_OFFLOAD4args opcboffload;

    case OP_CB_ILLEGAL:
        /* Illegal callback operation */
        /* STRFMT2: CB_ILLEGAL4args() */
        void;
};

/* OBJATTR: op=resop */
/* STRFMT1: {1} */
/* STRFMT2: {1} */
union nfs_cb_resop4 switch (nfs_cb_opnum4 resop){
    case OP_CB_GETATTR:
        CB_GETATTR4res opcbgetattr;
    case OP_CB_RECALL:
        CB_RECALL4res opcbrecall;

    /* New to NFSv4.1 */
    case OP_CB_LAYOUTRECALL:
        CB_LAYOUTRECALL4res opcblayoutrecall;
    case OP_CB_NOTIFY:
        CB_NOTIFY4res opcbnotify;
    case OP_CB_PUSH_DELEG:
        CB_PUSH_DELEG4res opcbpush_deleg;
    case OP_CB_RECALL_ANY:
        CB_RECALL_ANY4res opcbrecall_any;
    case OP_CB_RECALLABLE_OBJ_AVAIL:
        CB_RECALLABLE_OBJ_AVAIL4res opcbrecallable_obj_avail;
    case OP_CB_RECALL_SLOT:
        CB_RECALL_SLOT4res opcbrecall_slot;
    case OP_CB_SEQUENCE:
        CB_SEQUENCE4res opcbsequence;
    case OP_CB_WANTS_CANCELLED:
        CB_WANTS_CANCELLED4res opcbwants_cancelled;
    case OP_CB_NOTIFY_LOCK:
        CB_NOTIFY_LOCK4res opcbnotify_lock;
    case OP_CB_NOTIFY_DEVICEID:
        CB_NOTIFY_DEVICEID4res opcbnotify_deviceid;

    /* New to NFSv4.2 */
    case OP_CB_OFFLOAD:
        CB_OFFLOAD4res opcboffload;

    case OP_CB_ILLEGAL:
        /* Illegal callback operation */
        CB_ILLEGAL4res opcbillegal;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None,nfs4_sfh=None,nfs4_layouttype=None */
struct CB_COMPOUND4args {
    utf8str_cs      tag;
    uint32_t        minorversion;
    uint32_t        callback_ident;
    nfs_cb_argop4   array<>;
};

/* INHERIT: packet.nfs.nfsbase.NFSbase */
/* GLOBAL: nfs4_fh=None,nfs4_sfh=None,nfs4_layouttype=None */
/* XARG: minorversion */
struct CB_COMPOUND4res {
    nfsstat4 status;
    utf8str_cs      tag;
    nfs_cb_resop4   array<>;
};
