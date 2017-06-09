/*
 * Copyright (c) 1995
 *
 * Port Mapper Program Version 2 Protocol Specification
 * The document authors are identified in RFC 1833
 *
 *=====================================================================
 * This Document was changed to add directives for converting
 * it to python code. Also the name of some variables were
 * changed to be consistent throughout this document and to
 * have a similar interface with other protocols.
 *=====================================================================
 */
/* COPYRIGHT: 2014 */
/* VERSION: "2.0" */

enum proto2 {
    TCP = 6;      /* protocol number for TCP/IP */
    UDP = 17;     /* protocol number for UDP/IP */
};

/* Procedures */
/* CLASSATTR: _offset=9 */
enum portmap_proc2 {
    PMAPPROC_NULL    = 0,
    PMAPPROC_SET     = 1,
    PMAPPROC_UNSET   = 2,
    PMAPPROC_GETPORT = 3,
    PMAPPROC_DUMP    = 4,
    PMAPPROC_CALLIT  = 5,
};

/* Program Numbers */
enum portmap_prog2 {
    PORTMAP   = 100000,
    RSTAT     = 100001,
    RUSERS    = 100002,
    NFS       = 100003,
    YPSERV    = 100004,
    MOUNT     = 100005,
    RDBX      = 100006,
    YPBIND    = 100007,
    WALL      = 100008,
    YPPASSWDD = 100009,
    ETHERSTAT = 100010,
    RQUOTA    = 100011,
    REXEC     = 100017,
    NLOCKMGR  = 100021,
    STATMON1  = 100023,
    STATMON2  = 100024,
    YPUPDATE  = 100028,
    NFS_ACL   = 100227,
};

/* STRFMT1: prog:{0} vers:{1} proto:{2} port:{3} */
struct mapping {
    portmap_prog2 prog;
    unsigned int  vers;
    proto2        prot;
    unsigned int  port;
};

typedef mapping SET2args;     /* INHERIT:1 */
typedef mapping UNSET2args;   /* INHERIT:1 */
typedef mapping GETPORT2args; /* INHERIT:1 */

/* STRFMT1: {0} */
struct entry2 {
    mapping   map;
    entry2   *next;
};

/* STRFMT1: {0} */
struct DUMP2res {
    entry2 *entries;
};

/* STRFMT1: prog:{0} vers:{1} proc:{2} */
struct CALLIT2args {
    portmap_prog2 prog;
    unsigned int  vers;
    unsigned int  proc;
    opaque args<>;
};

/* STRFMT1: port:{0} res:{1:#x} */
struct CALLIT2res {
    unsigned int port;
    opaque res<>;
};

/* STRFMT1: {0} */
struct bool_res {
    bool result;
};

typedef bool_res SET2res;   /* INHERIT:1 */
typedef bool_res UNSET2res; /* INHERIT:1 */

/* STRFMT1: {0} */
struct GETPORT2res {
    unsigned int result;
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _strname="PORTMAP" */
/* OBJATTR: argop=procedure,op=procedure */
union PORTMAP2args switch(portmap_proc2 procedure) {
    case PMAPPROC_NULL:    void; /* STRFMT2: NULL() */
    case PMAPPROC_SET:     SET2args     opset;
    case PMAPPROC_UNSET:   UNSET2args   opunset;
    case PMAPPROC_GETPORT: GETPORT2args opgetport;
    case PMAPPROC_DUMP:    void; /* STRFMT2: DUMP2args() */
    case PMAPPROC_CALLIT:  CALLIT2args  opcallit;
};

/* INHERIT: RPCload */
/* XARG: procedure;disp */
/* CLASSATTR: _strname="PORTMAP" */
/* OBJATTR: resop=procedure,op=procedure */
union PORTMAP2res switch(portmap_proc2 procedure) {
    case PMAPPROC_NULL:    void; /* STRFMT2: NULL() */
    case PMAPPROC_SET:     SET2res     opset;
    case PMAPPROC_UNSET:   UNSET2res   opunset;
    case PMAPPROC_GETPORT: GETPORT2res opgetport;
    case PMAPPROC_DUMP:    DUMP2res    opdump;
    case PMAPPROC_CALLIT:  CALLIT2res  opcallit;
};

program PMAP_PROG {
    version PORTMAP {
        void
        PMAPPROC_NULL(void)         = 0;

        SET2res
        PMAPPROC_SET(SET2args)      = 1;

        UNSET2res
        PMAPPROC_UNSET(UNSET2args)  = 2;

        GETPORT2res
        PMAPPROC_GETPORT(GETPORT2args) = 3;

        DUMP2res
        PMAPPROC_DUMP(void)         = 4;

        CALLIT2res
        PMAPPROC_CALLIT(CALLIT2args)  = 5;
    } = 2;
} = 100000;
