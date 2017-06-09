/*
 * Copyright (c) 2012 IETF Trust and the persons identified
 * as authors of the code. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with
 * or without modification, are permitted provided that the
 * following conditions are met:
 *
 * o Redistributions of source code must retain the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer.
 *
 * o Redistributions in binary form must reproduce the above
 *   copyright notice, this list of conditions and the
 *   following disclaimer in the documentation and/or other
 *   materials provided with the distribution.
 *
 * o Neither the name of Internet Society, IETF or IETF
 *   Trust, nor the names of specific contributors, may be
 *   used to endorse or promote products derived from this
 *   software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS
 *   AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED
 *   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *   IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 *   FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO
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
 * This code was derived from [draft-ietf-nfsv4-flex-files-08].
 */

/* STRFMT1: vers:{0}.{1} */
struct ff_device_versions4 {
    uint32_t  version;
    uint32_t  minorversion;
    uint32_t  rsize;
    uint32_t  wsize;
    bool      tightly_coupled;
};

/* STRFMT1: {1} {2} */
struct ff_device_addr4 {
    uint32_t             size;  /* opaque size from device_addr4 */
    multipath_list4      netaddrs;
    ff_device_versions4  versions<>;
};

const FF_FLAGS_NO_LAYOUTCOMMIT   = 0x00000001;
const FF_FLAGS_NO_IO_THRU_MDS    = 0x00000002;
const FF_FLAGS_NO_READ_IO        = 0x00000004;
typedef uint32_t  ff_flags4;

/* STRFMT1: {3:crc32} */
struct ff_data_server4 {
    deviceid4           deviceid;
    uint32_t            efficiency;
    stateid4            stateid;
    nfs_fh4             fh_list<>;
    fattr4_owner        user;
    fattr4_owner_group  group;
};

/* STRFMT1: {0} */
struct ff_mirror4 {
    ff_data_server4  data_servers<>;
};

/* STRFMT1: {2} */
struct ff_layout4 {
    uint32_t    size;  /* opaque size from layout_content4 */
    length4     stripe_unit;
    ff_mirror4  mirrors<>;
    ff_flags4   flags;
    uint32_t    stats_hint;
};

struct ff_ioerr4 {
    offset4        offset;
    length4        length;
    stateid4       stateid;
    device_error4  errors<>;
};

struct ff_io_latency4 {
    uint64_t  ops_requested;
    uint64_t  bytes_requested;
    uint64_t  ops_completed;
    uint64_t  bytes_completed;
    uint64_t  bytes_not_delivered;
    nfstime4  total_busy_time;
    nfstime4  aggregate_completion_time;
};

struct ff_layoutupdate4 {
    netaddr4        addr;
    nfs_fh4         fh;
    ff_io_latency4  read;
    ff_io_latency4  write;
    nfstime4        duration;
    bool            local;
};

struct ff_iostats4 {
    offset4           offset;
    length4           length;
    stateid4          stateid;
    io_info4          read;
    io_info4          write;
    deviceid4         deviceid;
    ff_layoutupdate4  layoutupdate;
};

struct ff_layoutreturn4 {
    uint32_t     size;  /* opaque size from layoutreturn_file4 */
    ff_ioerr4    ioerr_report<>;
    ff_iostats4  iostats_report<>;
};

union ff_mirrors_hint switch (bool ffmc_valid) {
    case TRUE:
        uint32_t  mirrors;
    case FALSE:
        void;
};

struct ff_layouthint4 {
    ff_mirrors_hint  mirrors_hint;
};

enum ff_cb_recall_any_mask {
    FF_RCA4_TYPE_MASK_READ = -2,
    FF_RCA4_TYPE_MASK_RW   = -1
};
