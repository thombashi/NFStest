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
KRB5 module

Decode KRB5 layer
Decoding using ASN.1 DER (Distinguished Encoding Representation)

RFC 4120 The Kerberos Network Authentication Service (V5)
RFC 6113 A Generalized Framework for Kerberos Pre-Authentication
"""
from packet.utils import *
import krb5_const as const
import nfstest_config as c
from baseobj import BaseObj
from packet.derunpack import DERunpack

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2015 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

def SequenceOf(obj, objtype):
    """SEQUENCE OF: return list of the given object type"""
    ret = []
    if obj is not None:
        for item in obj:
            ret.append(objtype(item))
    return ret

def Optional(obj, objtype):
    """Get Optional item of the given object type"""
    if obj is not None:
        return objtype(obj)

def KerberosTime(stime, usec=None):
    """Convert floating point time to a DateStr object,
       include the microseconds if given
    """
    if stime is not None:
        if usec is not None:
            stime += (0.000001*usec)
        return DateStr(stime)

class KDCOptions(OptionFlags):
    """KDC Option flags"""
    _bitnames = const.kdc_options
    _reversed = 31

class APOptions(OptionFlags):
    """AP Option flags"""
    _bitnames = const.ap_options
    _reversed = 31

# Application Tag Numbers
class krb5_application(Enum):
    """enum krb5_application"""
    _enumdict = const.krb5_application

# Principal Names
class krb5_principal(Enum):
    """enum krb5_principal"""
    _enumdict = const.krb5_principal

# Pre-authentication and Typed Data
class krb5_patype(Enum):
    """enum krb5_patype"""
    _enumdict = const.krb5_patype

# Address Types
class krb5_addrtype(Enum):
    """enum krb5_addrtype"""
    _enumdict = const.krb5_addrtype

# Authorization Data Types
class krb5_adtype(Enum):
    """enum krb5_adtype"""
    _enumdict = const.krb5_adtype

# Kerberos Encryption Type Numbers
class krb5_etype(Enum):
    """enum krb5_etype"""
    _enumdict = const.krb5_etype

# Kerberos Checksum Type Numbers
class krb5_ctype(Enum):
    """enum krb5_ctype"""
    _enumdict = const.krb5_ctype

# Kerberos Fast Armor Type Numbers
class krb5_fatype(Enum):
    """enum krb5_fatype"""
    _enumdict = const.krb5_fatype

# Error Codes
class krb5_status(Enum):
    """enum krb5_status"""
    _enumdict = const.krb5_status

class PrincipalName(BaseObj):
    """
       PrincipalName  ::= SEQUENCE {
           name-type    [0] Int32,
           name-string  [1] SEQUENCE OF KerberosString
       }
    """
    # Class attributes
    _strfmt1  = "{0} {1}"
    _attrlist = ("ntype", "name")

    def __init__(self, obj):
        self.ntype = krb5_principal(obj.get(0))
        self.name  = obj.get(1)

class HostAddress(BaseObj):
    """
       HostAddress  ::= SEQUENCE  {
           addr-type  [0] Int32,
           address    [1] OCTET STRING
       }
    """
    # Class attributes
    _strfmt1  = "{0} {1}"
    _attrlist = ("atype", "address")

    def __init__(self, obj):
        self.atype   = krb5_addrtype(obj.get(0))
        self.address = obj.get(1)

class EtypeInfo2Entry(BaseObj):
    """
       ETYPE-INFO2-ENTRY  ::= SEQUENCE {
           etype      [0] Int32,
           salt       [1] KerberosString OPTIONAL,
           s2kparams  [2] OCTET STRING OPTIONAL
       }
    """
    # Class attributes
    _attrlist = ("etype", "salt", "s2kparams")

    def __init__(self, obj):
        self.etype     = krb5_etype(obj.get(0))
        self.salt      = obj.get(1)
        self.s2kparams = obj.get(2)

class Checksum(BaseObj):
    """
       Checksum  ::= SEQUENCE {
           cksumtype  [0] Int32,
           checksum   [1] OCTET STRING
       }
    """
    # Class attributes
    _strfmt2  = "Checksum(ctype={0})"
    _attrlist = ("ctype", "checksum")

    def __init__(self, obj):
        self.ctype    = krb5_ctype(obj.get(0))
        self.checksum = obj.get(1)

class KrbFastArmor(BaseObj):
    """
       KrbFastArmor  ::= SEQUENCE {
           armor-type   [0] Int32,
               -- Type of the armor.
           armor-value  [1] OCTET STRING,
               -- Value of the armor.
       }
    """
    # Class attributes
    _strfmt2  = "KrbFastArmor(fatype={0})"
    _attrlist = ("fatype", "value")

    def __init__(self, obj):
        self.fatype = krb5_fatype(obj.get(0))
        self.value  = obj.get(1)

class KrbFastArmoredReq(BaseObj):
    """
       KrbFastArmoredReq ::= SEQUENCE {
           armor        [0] KrbFastArmor OPTIONAL,
               -- Contains the armor that identifies the armor key.
               -- MUST be present in AS-REQ.
           req-checksum [1] Checksum,
               -- For AS, contains the checksum performed over the type
               -- KDC-REQ-BODY for the req-body field of the KDC-REQ
               -- structure;
               -- For TGS, contains the checksum performed over the type
               -- AP-REQ in the PA-TGS-REQ padata.
               -- The checksum key is the armor key, the checksum
               -- type is the required checksum type for the enctype of
               -- the armor key, and the key usage number is
               -- KEY_USAGE_FAST_REQ_CHKSUM.
           enc-fast-req [2] EncryptedData, -- KrbFastReq --
               -- The encryption key is the armor key, and the key usage
               -- number is KEY_USAGE_FAST_ENC.
       }
    """
    # Class attributes
    _attrlist = ("armor", "checksum", "enc_fast")

    def __init__(self, obj):
        self.armor    = Optional(obj.get(0), KrbFastArmor)
        self.checksum = Checksum(obj.get(1))
        self.enc_fast = EncryptedData(obj.get(2))

class KrbFastArmoredRep(BaseObj):
    """
       KrbFastArmoredRep ::= SEQUENCE {
          enc-fast-rep  [0] EncryptedData, -- KrbFastResponse --
              -- The encryption key is the armor key in the request, and
              -- the key usage number is KEY_USAGE_FAST_REP.
       }
    """
    # Class attributes
    _attrlist = ("enc_fast",)

    def __init__(self, obj):
        self.enc_fast = EncryptedData(obj.get(0))

class paData(BaseObj):
    """
       PA-DATA  ::= SEQUENCE {
           -- NOTE: first tag is [1], not [0]
           padata-type   [1] Int32,
           padata-value  [2] OCTET STRING
       }
    """
    # Class attributes
    _attrlist = ("patype", "value")

    def __init__(self, obj):
        self.patype = krb5_patype(obj.get(1))
        self.value  = obj.get(2)

        if len(self.value) > 0:
            if self.patype == const.PA_ETYPE_INFO2:
                self.value = SequenceOf(DERunpack(self.value).get_item(), EtypeInfo2Entry)
            elif self.patype == const.PA_ENC_TIMESTAMP:
                self.value = EncryptedData(DERunpack(self.value).get_item())
            elif self.patype == const.PA_TGS_REQ:
                self.value = AP_REQ(DERunpack(self.value).get_item())
            elif self.patype == const.PA_FX_FAST:
                pobj = DERunpack(self.value).get_item()
                # Get the CHOICE tag and value
                tag, value = pobj.popitem()
                if tag == 0:
                    if len(value) == 1:
                        # PA-FX-FAST-REPLY ::= CHOICE {
                        #     armored-data [0] KrbFastArmoredRep,
                        # }
                        self.value = KrbFastArmoredRep(value)
                    else:
                        # PA-FX-FAST-REQUEST ::= CHOICE {
                        #     armored-data [0] KrbFastArmoredReq,
                        # }
                        self.value = KrbFastArmoredReq(value)

class EncryptedData(BaseObj):
    """
       EncryptedData  ::= SEQUENCE {
           etype   [0] Int32 -- EncryptionType --,
           kvno    [1] UInt32 OPTIONAL,
           cipher  [2] OCTET STRING -- ciphertext
       }
    """
    # Class attributes
    _strfmt2  = "EncryptedData(etype={0})"
    _attrlist = ("etype", "kvno", "cipher")

    def __init__(self, obj):
        self.etype  = krb5_etype(obj.get(0))
        self.kvno   = obj.get(1)
        self.cipher = obj.get(2)

class Ticket(BaseObj):
    """
       Ticket  ::= [APPLICATION 1] SEQUENCE {
           tkt-vno   [0] INTEGER (5),
           realm     [1] Realm,
           sname     [2] PrincipalName,
           enc-part  [3] EncryptedData -- EncTicketPart
       }
    """
    # Class attributes
    _attrlist = ("tkt_vno", "realm", "sname", "enc_part")

    def __init__(self, obj):
        obj = obj[1] # Application 1
        self.tkt_vno  = obj.get(0)
        self.realm    = obj.get(1)
        self.sname    = PrincipalName(obj.get(2))
        self.enc_part = EncryptedData(obj.get(3))

class AP_REQ(BaseObj):
    """
       AP-REQ  ::= [APPLICATION 14] SEQUENCE {
           pvno           [0] INTEGER (5),
           msg-type       [1] INTEGER (14),
           options        [2] APOptions,
           ticket         [3] Ticket,
           authenticator  [4] EncryptedData -- Authenticator
       }
    """
    # Class attributes
    _attrlist = ("pvno", "msgtype", "options", "ticket", "authenticator")

    def __init__(self, obj):
        obj = obj[14] # Application 14
        self.pvno          = obj.get(0)
        self.msgtype       = krb5_application(obj.get(1))
        self.options       = APOptions(obj.get(2))
        self.ticket        = Ticket(obj.get(3))
        self.authenticator = EncryptedData(obj.get(4))

class AP_REP(BaseObj):
    """
       AP-REP  ::= [APPLICATION 15] SEQUENCE {
           pvno      [0] INTEGER (5),
           msg-type  [1] INTEGER (15),
           enc-part  [2] EncryptedData -- EncAPRepPart
       }
    """
    # Class attributes
    _attrlist = ("pvno", "msgtype", "enc_part")

    def __init__(self, obj):
        obj = obj[15] # Application 15
        self.pvno     = obj.get(0)
        self.msgtype  = krb5_application(obj.get(1))
        self.enc_part = EncryptedData(obj.get(2))

class KDC_REQ_BODY(BaseObj):
    """
       KDC-REQ-BODY  ::= SEQUENCE {
           options                  [0] KDCOptions,
           cname                    [1] PrincipalName OPTIONAL
                                        -- Used only in AS-REQ --,
           realm                    [2] Realm
                                        -- Server's realm
                                        -- Also client's in AS-REQ --,
           sname                    [3] PrincipalName OPTIONAL,
           from                     [4] KerberosTime OPTIONAL,
           till                     [5] KerberosTime,
           rtime                    [6] KerberosTime OPTIONAL,
           nonce                    [7] UInt32,
           etype                    [8] SEQUENCE OF Int32 -- EncryptionType
                                        -- in preference order --,
           addresses                [9] HostAddresses OPTIONAL,
           enc-authorization-data  [10] EncryptedData OPTIONAL
                                        -- AuthorizationData --,
           additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
                                        -- NOTE: not empty
       }
    """
    # Class attributes
    _attrlist = ("options", "cname", "realm", "sname", "stime", "etime",
                 "rtime", "nonce", "etype", "addrs", "edata", "tickets")

    def __init__(self, obj):
        self.options = KDCOptions(obj.get(0))
        self.cname   = Optional(obj.get(1), PrincipalName)
        self.realm   = obj.get(2)
        self.sname   = Optional(obj.get(3), PrincipalName)
        self.stime   = KerberosTime(obj.get(4))
        self.etime   = KerberosTime(obj.get(5))
        self.rtime   = KerberosTime(obj.get(6))
        self.nonce   = obj.get(7)
        self.etype   = [krb5_etype(x) for x in obj.get(8)]
        self.addrs   = SequenceOf(obj.get(9), HostAddress)
        self.edata   = Optional(obj.get(10), EncryptedData)
        self.tickets = SequenceOf(obj.get(11), Ticket)

        if self.cname is not None:
            self.set_strfmt(1, "cname:({1}) {2}")
        else:
            self.set_strfmt(1, "sname:({3}) {2}")

class KDC_REQ(BaseObj):
    """
       KDC-REQ  ::= SEQUENCE {
           -- NOTE: first tag is [1], not [0]
           pvno      [1] INTEGER (5) ,
           msg-type  [2] INTEGER (10 -- AS -- | 12 -- TGS --),
           padata    [3] SEQUENCE OF PA-DATA OPTIONAL
                         -- NOTE: not empty --,
           req-body  [4] KDC-REQ-BODY
       }
    """
    # Class attributes
    _strfmt1  = "KRB{0} {1} {3}"
    _attrlist = ("pvno", "msgtype", "padata", "body")

    def __init__(self, obj):
        self.pvno    = obj.get(1)
        self.msgtype = krb5_application(obj.get(2))
        self.padata  = SequenceOf(obj.get(3), paData)
        self.body    = KDC_REQ_BODY(obj.get(4))

class KDC_REP(BaseObj):
    """
       KDC-REP  ::= SEQUENCE {
           pvno      [0] INTEGER (5),
           msg-type  [1] INTEGER (11 -- AS -- | 13 -- TGS --),
           padata    [2] SEQUENCE OF PA-DATA OPTIONAL
                         -- NOTE: not empty --,
           crealm    [3] Realm,
           cname     [4] PrincipalName,
           ticket    [5] Ticket,
           enc-part  [6] EncryptedData
                         -- EncASRepPart or EncTGSRepPart,
                         -- as appropriate
       }
    """
    # Class attributes
    _strfmt1  = "KRB{0} {1} cname:({4}) {3}"
    _attrlist = ("pvno", "msgtype", "padata", "crealm", "cname",
                 "ticket", "enc_part")

    def __init__(self, obj):
        self.pvno     = obj.get(0)
        self.msgtype  = krb5_application(obj.get(1))
        self.padata   = SequenceOf(obj.get(2), paData)
        self.crealm   = obj.get(3)
        self.cname    = PrincipalName(obj.get(4))
        self.ticket   = Ticket(obj.get(5))
        self.enc_part = EncryptedData(obj.get(6))

class KRB_ERROR(BaseObj):
    """
       KRB-ERROR  ::= [APPLICATION 30] SEQUENCE {
           pvno        [0] INTEGER (5),
           msg-type    [1] INTEGER (30),
           ctime       [2] KerberosTime OPTIONAL,
           cusec       [3] Microseconds OPTIONAL,
           stime       [4] KerberosTime,
           susec       [5] Microseconds,
           error-code  [6] Int32,
           crealm      [7] Realm OPTIONAL,
           cname       [8] PrincipalName OPTIONAL,
           realm       [9] Realm -- service realm --,
           sname       [10] PrincipalName -- service name --,
           e-text      [11] KerberosString OPTIONAL,
           e-data      [12] OCTET STRING OPTIONAL
       }
    """
    # Class attributes
    _strfmt1  = "KRB{0} {4}"
    _attrlist = ("pvno", "msgtype", "ctime", "stime", "error", "crealm",
                 "cname", "realm", "sname", "etext", "edata")

    def __init__(self, obj):
        # Application 30: do not process the application here, it should be
        # done at the parent class to know what type of object to instantiate
        self.pvno    = obj.get(0)
        self.msgtype = krb5_application(obj.get(1))
        self.ctime   = KerberosTime(obj.get(2), obj.get(3))
        self.stime   = KerberosTime(obj.get(4), obj.get(5))
        self.error   = krb5_status(obj.get(6))
        self.crealm  = obj.get(7)
        self.cname   = Optional(obj.get(8), PrincipalName)
        self.realm   = obj.get(9)
        self.sname   = PrincipalName(obj.get(10))
        self.etext   = obj.get(11)
        edata        = obj.get(12)
        if edata is not None:
            if self.error == const.KDC_ERR_PREAUTH_REQUIRED:
                edata = SequenceOf(DERunpack(edata).get_item(), paData)
        self.edata = edata

class KRB5(BaseObj):
    """KRB5 object

       Usage:
           from packet.application.krb5 import KRB5

           # Decode KRB5 layer
           x = KRB5(pktt, proto)

       Object definition:

       KRB5(
           appid = int,  # Application Identifier
           kdata = KDC_REQ|KDC_REP|KRB_ERROR
       }
    """
    # Class attributes
    _fattrs   = ("kdata",)
    _strfmt1  = "{1}"
    _attrlist = ("appid", "kdata")

    def __init__(self, pktt, proto):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
           proto:
               Transport layer protocol.
        """
        self._krb5 = False

        try:
            unpack = pktt.unpack
            if proto == 6:
                # Get the length of the TCP record
                length = unpack.unpack_ushort()
                if length < len(unpack):
                    return

            slen = unpack.size()
            derunpack = DERunpack(unpack.getbytes())
            krbobj = derunpack.get_item()
            appid, obj = krbobj.items()[0]
            self.appid = krb5_application(appid)
            if self.appid in (const.AS_REQ, const.TGS_REQ):
                # AS-REQ  ::= [APPLICATION 10] KDC-REQ
                # TGS-REQ ::= [APPLICATION 12] KDC-REQ
                self.kdata = KDC_REQ(obj)
            elif self.appid in (const.AS_REP, const.TGS_REP):
                # AS-REP  ::= [APPLICATION 11] KDC-REP
                # TGS-REP ::= [APPLICATION 13] KDC-REP
                self.kdata = KDC_REP(obj)
            elif self.appid == const.KRB_ERROR:
                self.kdata = KRB_ERROR(obj)
            else:
                self.kdata = obj
        except Exception as e:
            return
        if len(derunpack) > 0:
            return
        unpack.read(slen)
        self._krb5 = True

    def __nonzero__(self):
        """Truth value testing for the built-in operation bool()"""
        return self._krb5
