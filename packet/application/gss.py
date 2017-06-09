#===============================================================================
# Copyright 2013 NetApp, Inc. All Rights Reserved,
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
GSS module

Decode GSS layers.

RFC 2203 RPCSEC_GSS Protocol Specification
RFC 1964 The Kerberos Version 5 GSS-API Mechanism

NOTE:
  Only procedures RPCSEC_GSS_INIT and RPCSEC_GSS_DATA are supported
"""
import krb5
import rpc_const
import gss_const as const
from packet.utils import *
import nfstest_config as c
from baseobj import BaseObj
from packet.derunpack import DERunpack

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.4"

# Token Identifier TOK_ID
KRB_AP_REQ       = 0x0100
KRB_AP_REP       = 0x0200
KRB_ERROR        = 0x0300
KRB_TOKEN_GETMIC = 0x0101

# Integrity algorithm indicator
class gss_sgn_alg(Enum):
    """enum gss_sgn_alg"""
    _enumdict = const.gss_sgn_alg

# GSS Major Status Codes
class gss_major_status(Enum):
    """enum gss_major_status"""
    _enumdict = const.gss_major_status

# GSS Minor Status Codes
class gss_minor_status(Enum):
    """enum gss_minor_status"""
    _enumdict = const.gss_minor_status

class GetMIC(BaseObj):
    """struct GSS_GetMIC {
           unsigned short sgn_alg;      /* Integrity algorithm indicator */
           opaque         filler[4];    /* Filler bytes: 0xffffffff */
           opaque         snd_seq[8];   /* Sequence number field */
           opaque         sgn_cksum[8]; /* Checksum of "to-be-signed data" */
       };
    """
    # Class attributes
    _strfmt2  = "GetMIC({0}, snd_seq:{1}, sgn_cksum:{2})"
    _attrlist = ("sgn_alg", "snd_seq", "sgn_cksum")

    def __init__(self, unpack):
        ulist = unpack.unpack(22, "!H4s8s8s")
        self.sgn_alg   = gss_sgn_alg(ulist[0])
        self.filler    = ulist[1]
        self.snd_seq   = StrHex(ulist[2])
        self.sgn_cksum = StrHex(ulist[3])

class GSS_API(BaseObj):
    """GSS-API DEFINITIONS ::=

       BEGIN

       MechType ::= OBJECT IDENTIFIER
       -- representing Kerberos V5 mechanism

       GSSAPI-Token ::=
       -- option indication (delegation, etc.) indicated within
       -- mechanism-specific token
       [APPLICATION 0] IMPLICIT SEQUENCE {
               thisMech MechType,
               innerToken ANY DEFINED BY thisMech
                  -- contents mechanism-specific
                  -- ASN.1 structure not required
               }

       END
    """
    # Class attributes
    _strfmt2  = "GSS_API(OID:{0}, {2})"
    _attrlist = ("oid", "tok_id", "krb5")

    def __init__(self, data):
        self._valid = False
        derunpack = DERunpack(data)
        # Get the Kerberos 5 OID only -- from application 0
        krbobj = derunpack.get_item(oid="1.2.840.113554.1.2.2").get(0)
        if krbobj is not None and len(krbobj) > 0:
            self.oid    = krbobj.get(0)
            self.tok_id = derunpack.unpack_ushort()
            self.krb5   = None

            if self.tok_id == KRB_AP_REQ:
                krbobj = derunpack.get_item()
                self.krb5 = krb5.AP_REQ(krbobj)
                self.krb5.set_strfmt(2, "{1}, opts:{2}, Ticket({3})")
                self.krb5.ticket.set_strfmt(2, "{2}@{1}({2.ntype}), {3.etype}")
                self.krb5.ticket.sname.set_strfmt(2, "{1:/:}")
            elif self.tok_id == KRB_AP_REP:
                krbobj = derunpack.get_item()
                self.krb5 = krb5.AP_REP(krbobj)
                self.krb5.set_strfmt(2, "{1}, {2.etype}")
            elif self.tok_id == KRB_ERROR:
                krbobj = derunpack.get_item()
                self.krb5 = krb5.KRB_ERROR(krbobj.get(30))
            elif self.tok_id == KRB_TOKEN_GETMIC:
                self.krb5 = GetMIC(derunpack)
            else:
                self.krb5 = StrHex(derunpack.getbytes())
            self._valid = True

    def __nonzero__(self):
        """Truth value testing for the built-in operation bool()"""
        return self._valid

class GSS_init_arg(BaseObj):
    """struct rpc_gss_init_arg {
           opaque  gss_token<>;
       };
    """
    # Class attributes
    _strfmt2  = "token: {0:#x:.32}..."
    _attrlist = ("token",)

    def __init__(self, unpack):
        self.token = unpack.unpack_opaque()
        krb5 = GSS_API(self.token)
        if krb5:
            self.token = krb5
            self.set_strfmt(2, "{0}")

class GSS_init_res(BaseObj):
    """struct rpc_gss_init_res {
           opaque        handle<>;
           unsigned int  gss_major;
           unsigned int  gss_minor;
           unsigned int  seq_window;
           opaque        gss_token<>;
       };
    """
    # Class attributes
    _strfmt2  = "context: {0}, token: {4:#x:.16}..."
    _attrlist = ("context", "major", "minor", "seq_window", "token")

    def __init__(self, unpack):
        self.context    = StrHex(unpack.unpack_opaque())
        self.major      = gss_major_status(unpack.unpack_uint())
        self.minor      = gss_minor_status(unpack.unpack_int())
        self.seq_window = unpack.unpack_uint()
        self.token      = unpack.unpack_opaque()
        if self.major not in (const.GSS_S_COMPLETE, const.GSS_S_CONTINUE_NEEDED):
            # Display major and minor codes on error
            self.set_strfmt(2, "major: {1}, minor: {2}")
        else:
            # Try to decode the token
            krb5 = GSS_API(self.token)
            if krb5:
                # Replace token attribute with the decoded object
                self.token = krb5
                self.set_strfmt(2, "context: {0}, {4}")

class GSS_data(BaseObj):
    """struct rpc_gss_data_t {
           unsigned int    seq_num;
           proc_req_arg_t  arg;
       };
    """
    # Class attributes
    _strfmt2  = "length: {0}, seq_num: {1}"
    _attrlist = ("length", "seq_num")

    def __init__(self, unpack):
        self.length  = unpack.unpack_uint()
        self.seq_num = unpack.unpack_uint()

class GSS_checksum(GSS_init_arg): pass

class GSS(BaseObj):
    """GSS Data object

       This is a base object and should not be instantiated.
       It gives the following methods:
           # Decode data preceding the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_data()

           # Decode data following the RPC payload when flavor is RPCSEC_GSS
           x.decode_gss_checksum()
    """
    def _gss_data_call(self):
        """Internal method to decode GSS data on a CALL"""
        if self.credential.flavor != rpc_const.RPCSEC_GSS:
            # Not a GSS encoded packet
            return
        unpack = self._pktt.unpack
        if self.credential.gss_proc == const.RPCSEC_GSS_DATA:
            if self.credential.gss_service == const.rpc_gss_svc_integrity:
                return GSS_data(unpack)
        elif self.credential.gss_proc == const.RPCSEC_GSS_INIT:
            return GSS_init_arg(unpack)

    def _gss_data_reply(self):
        """Internal method to decode GSS data on a REPLY"""
        if self.verifier.flavor != rpc_const.RPCSEC_GSS and not hasattr(self.verifier, 'gss_proc'):
            # Not a GSS encoded packet
            return
        unpack = self._pktt.unpack
        if self.verifier.gss_proc == const.RPCSEC_GSS_DATA:
            if self.verifier.gss_service == const.rpc_gss_svc_integrity:
                return GSS_data(unpack)
        elif self.verifier.gss_proc == const.RPCSEC_GSS_INIT:
            return GSS_init_res(unpack)

    def decode_gss_data(self):
        """Decode GSS data"""
        try:
            pktt = self._pktt
            if pktt.unpack.size() < 4:
                # Not a GSS encoded packet
                return
            if self.type == rpc_const.CALL:
                gss = self._gss_data_call()
            else:
                gss = self._gss_data_reply()
            if gss is not None:
                pktt.pkt.gssd = gss
        except:
            pass

    def decode_gss_checksum(self):
        """Decode GSS checksum"""
        try:
            pktt = self._pktt
            unpack = pktt.unpack
            if unpack.size() < 4:
                # Not a GSS encoded packet
                return
            gss = None
            if self.type == rpc_const.CALL:
                cred = self.credential
            else:
                cred = self.verifier
            if cred.flavor == rpc_const.RPCSEC_GSS and cred.gss_proc == const.RPCSEC_GSS_DATA:
                if cred.gss_service == const.rpc_gss_svc_integrity:
                    gss = GSS_checksum(unpack)
            if gss is not None:
                pktt.pkt.gssc = gss
        except:
            pass
