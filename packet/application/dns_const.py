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
DNS constants module

Provide constant values and mapping dictionaries for the DNS layer.

RFC 1035 Domain Names - Implementation and Specification
RFC 2671 Extension Mechanisms for DNS (EDNS0)
RFC 4034 Resource Records for the DNS Security Extensions
RFC 4035 Protocol Modifications for the DNS Security Extensions
RFC 4255 Using DNS to Securely Publish Secure Shell (SSH) Key Fingerprints
"""
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

# Enum dns_query
QUERY = 0
REPLY = 1

dns_query = {
    0 : "QUERY",
    1 : "REPLY",
}

# Enum dns_opcode
QUERY  = 0
IQUERY = 1
STATUS = 2
NOTIFY = 4
UPDATE = 5

dns_opcode = {
    0 : "QUERY",
    1 : "IQUERY",
    2 : "STATUS",
    4 : "NOTIFY",
    5 : "UPDATE",
}

# Enum dns_rcode
NOERROR          = 0   # No Error [RFC1035]
DNSERR_FORMERR   = 1   # Format Error [RFC1035]
DNSERR_SERVFAIL  = 2   # Server Failure [RFC1035]
DNSERR_NXDOMAIN  = 3   # Non-Existent Domain [RFC1035]
DNSERR_NOTIMP    = 4   # Not Implemented [RFC1035]
DNSERR_REFUSED   = 5   # Query Refused [RFC1035]
DNSERR_YXDOMAIN  = 6   # Name Exists when it should not [RFC2136][RFC6672]
DNSERR_YXRRSET   = 7   # RR Set Exists when it should not [RFC2136]
DNSERR_NXRRSET   = 8   # RR Set that should exist does not [RFC2136]
DNSERR_NOTAUTH   = 9   # Server Not Authoritative for zone [RFC2136]
                       # Not Authorized [RFC2845]
DNSERR_NOTZONE   = 10  # Name not contained in zone [RFC2136]
DNSERR_BADVERS   = 16  # Bad OPT Version [RFC6891]
                       # TSIG Signature Failure [RFC2845]
DNSERR_BADKEY    = 17  # Key not recognized [RFC2845]
DNSERR_BADTIME   = 18  # Signature out of time window [RFC2845]
DNSERR_BADMODE   = 19  # Bad TKEY Mode [RFC2930]
DNSERR_BADNAME   = 20  # Duplicate key name [RFC2930]
DNSERR_BADALG    = 21  # Algorithm not supported [RFC2930]
DNSERR_BADTRUNC  = 22  # Bad Truncation [RFC4635]
DNSERR_BADCOOKIE = 23  # Bad/missing Server Cookie [RFC7873]

dns_rcode = {
     0 : "NOERROR",
     1 : "DNSERR_FORMERR",
     2 : "DNSERR_SERVFAIL",
     3 : "DNSERR_NXDOMAIN",
     4 : "DNSERR_NOTIMP",
     5 : "DNSERR_REFUSED",
     6 : "DNSERR_YXDOMAIN",
     7 : "DNSERR_YXRRSET",
     8 : "DNSERR_NXRRSET",
     9 : "DNSERR_NOTAUTH",
    10 : "DNSERR_NOTZONE",
    16 : "DNSERR_BADVERS",
    17 : "DNSERR_BADKEY",
    18 : "DNSERR_BADTIME",
    19 : "DNSERR_BADMODE",
    20 : "DNSERR_BADNAME",
    21 : "DNSERR_BADALG",
    22 : "DNSERR_BADTRUNC",
    23 : "DNSERR_BADCOOKIE",
}

# Enum dns_type
A          = 1      # Host address
NS         = 2      # Authoritative name server
MD         = 3      # Mail destination (Obsolete - use MX)
MF         = 4      # Mail forwarder (Obsolete - use MX)
CNAME      = 5      # Canonical name for an alias
SOA        = 6      # Marks the start of a zone of authority
MB         = 7      # Mailbox domain name (EXPERIMENTAL)
MG         = 8      # Mail group member (EXPERIMENTAL)
MR         = 9      # Mail rename domain name (EXPERIMENTAL)
NULL       = 10     # Null RR (EXPERIMENTAL)
WKS        = 11     # Well known service description
PTR        = 12     # Domain name pointer
HINFO      = 13     # Host information
MINFO      = 14     # Mailbox or mail list information
MX         = 15     # Mail exchange
TXT        = 16     # Text strings
RP         = 17     # Responsible Person [RFC1183]
AFSDB      = 18     # AFS Data Base location [RFC1183][RFC5864]
X25        = 19     # X.25 PSDN address [RFC1183]
ISDN       = 20     # ISDN address [RFC1183]
RT         = 21     # Route Through [RFC1183]
NSAP       = 22     # NSAP address, NSAP style A record [RFC1706]
NSAPPTR    = 23     # Domain name pointer, NSAP style [RFC1348][RFC1637][RFC1706]
SIG        = 24     # Security signature [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2931][RFC3110][RFC3008]
KEY        = 25     # Security key [RFC4034][RFC3755][RFC2535][RFC2536][RFC2537][RFC2539][RFC3008][RFC3110]
PX         = 26     # X.400 mail mapping information [RFC2163]
GPOS       = 27     # Geographical Position [RFC1712]
AAAA       = 28     # IPv6 address
LOC        = 29     # Location record
NXT        = 30     # Next Domain (OBSOLETE) [RFC3755][RFC2535]
EID        = 31     # Endpoint Identifier
NIMLOC     = 32     # Nimrod Locator
SRV        = 33     # Service locator
ATMA       = 34     # ATM Address
NAPTR      = 35     # Naming Authority Pointer [RFC2915][RFC2168][RFC3403]
KX         = 36     # Key Exchanger [RFC2230]
CERT       = 37     # CERT [RFC4398]
A6         = 38     # A6 (OBSOLETE - use AAAA) [RFC3226][RFC2874][RFC6563]
DNAME      = 39     # DNAME [RFC6672]
SINK       = 40     # SINK
OPT        = 41     # OPT pseudo-RR [RFC6891][RFC3225][RFC2671]
APL        = 42     # APL [RFC3123]
DS         = 43     # Delegation Signer [RFC4034][RFC3658]
SSHFP      = 44     # Secure shell fingerprint
IPSECKEY   = 45     # IPSECKEY [RFC4025]
RRSIG      = 46     # Resource record digital signature
NSEC       = 47     # NSEC [RFC4034][RFC3755]
DNSKEY     = 48     # DNSKEY [RFC4034][RFC3755]
DHCID      = 49     # DHCID [RFC4701]
NSEC3      = 50     # NSEC3 [RFC5155]
NSEC3PARAM = 51     # NSEC3PARAM [RFC5155]
TLSA       = 52     # TLSA [RFC6698]
SMIMEA     = 53     # S/MIME cert association [draft-ietf-dane-smime]
HIP        = 55     # Host Identity Protocol [RFC5205]
NINFO      = 56     # NINFO [Jim_Reid] NINFO/ninfo-completed-template 2008-01-21
RKEY       = 57     # RKEY [Jim_Reid] RKEY/rkey-completed-template 2008-01-21
TALINK     = 58     # Trust Anchor LINK [Wouter_Wijngaards] TALINK/talink-completed-template 2010-02-17
CDS        = 59     # Child DS [RFC7344] CDS/cds-completed-template 2011-06-06
CDNSKEY    = 60     # DNSKEY(s) the Child wants reflected in DS [RFC7344] 2014-06-16
OPENPGPKEY = 61     # OpenPGP Key [RFC-ietf-dane-openpgpkey-12] OPENPGPKEY/openpgpkey-completed-template 2014-08-12
CSYNC      = 62     # Child-To-Parent Synchronization [RFC7477] 2015-01-27
SPF        = 99     # [RFC7208]
UINFO      = 100    # [IANA-Reserved]
UID        = 101    # [IANA-Reserved]
GID        = 102    # [IANA-Reserved]
UNSPEC     = 103    # [IANA-Reserved]
NID        = 104    # [RFC6742] ILNP/nid-completed-template
L32        = 105    # [RFC6742] ILNP/l32-completed-template
L64        = 106    # [RFC6742] ILNP/l64-completed-template
LP         = 107    # [RFC6742] ILNP/lp-completed-template
EUI48      = 108    # EUI-48 address [RFC7043] EUI48/eui48-completed-template 2013-03-27
EUI64      = 109    # EUI-64 address [RFC7043] EUI64/eui64-completed-template 2013-03-27
TKEY       = 249    # Transaction Key [RFC2930]
TSIG       = 250    # Transaction Signature [RFC2845]
IXFR       = 251    # Incremental transfer [RFC1995]
AXFR       = 252    # Transfer of an entire zone [RFC1035][RFC5936]
MAILB      = 253    # Mailbox-related RRs (MB, MG or MR) [RFC1035]
MAILA      = 254    # Mail agent RRs (OBSOLETE - see MX) [RFC1035]
ANY        = 255    # Request all records
URI        = 256    # URI [RFC7553]
CAA        = 257    # Certification Authority Restriction [RFC6844]
AVC        = 258    # Application Visibility and Control
TA         = 32768  # DNSSEC Trust Authorities
DLV        = 32769  # DNSSEC Lookaside Validation [RFC4431]

dns_type = {
        1 : "A",
        2 : "NS",
        3 : "MD",
        4 : "MF",
        5 : "CNAME",
        6 : "SOA",
        7 : "MB",
        8 : "MG",
        9 : "MR",
       10 : "NULL",
       11 : "WKS",
       12 : "PTR",
       13 : "HINFO",
       14 : "MINFO",
       15 : "MX",
       16 : "TXT",
       17 : "RP",
       18 : "AFSDB",
       19 : "X25",
       20 : "ISDN",
       21 : "RT",
       22 : "NSAP",
       23 : "NSAPPTR",
       24 : "SIG",
       25 : "KEY",
       26 : "PX",
       27 : "GPOS",
       28 : "AAAA",
       29 : "LOC",
       30 : "NXT",
       31 : "EID",
       32 : "NIMLOC",
       33 : "SRV",
       34 : "ATMA",
       35 : "NAPTR",
       36 : "KX",
       37 : "CERT",
       38 : "A6",
       39 : "DNAME",
       40 : "SINK",
       41 : "OPT",
       42 : "APL",
       43 : "DS",
       44 : "SSHFP",
       45 : "IPSECKEY",
       46 : "RRSIG",
       47 : "NSEC",
       48 : "DNSKEY",
       49 : "DHCID",
       50 : "NSEC3",
       51 : "NSEC3PARAM",
       52 : "TLSA",
       53 : "SMIMEA",
       55 : "HIP",
       56 : "NINFO",
       57 : "RKEY",
       58 : "TALINK",
       59 : "CDS",
       60 : "CDNSKEY",
       61 : "OPENPGPKEY",
       62 : "CSYNC",
       99 : "SPF",
      100 : "UINFO",
      101 : "UID",
      102 : "GID",
      103 : "UNSPEC",
      104 : "NID",
      105 : "L32",
      106 : "L64",
      107 : "LP",
      108 : "EUI48",
      109 : "EUI64",
      249 : "TKEY",
      250 : "TSIG",
      251 : "IXFR",
      252 : "AXFR",
      253 : "MAILB",
      254 : "MAILA",
      255 : "ANY",
      256 : "URI",
      257 : "CAA",
      258 : "AVC",
    32768 : "TA",
    32769 : "DLV",
}

# Enum dns_class
IN   = 1    # Internet
CS   = 2    # Chaos
CH   = 3    # Hesiod
HS   = 4    # Internet
NONE = 254  # QCLASS None
ANY  = 255  # QCLASS Any

dns_class = {
      1 : "IN",
      2 : "CS",
      3 : "CH",
      4 : "HS",
    254 : "NONE",
    255 : "ANY",
}

# Enum dns_algorithm
RSA     = 1  # RSA Algorithm [RFC4255]
DSS     = 2  # DSS Algorithm [RFC4255]
ECDSA   = 3  # Elliptic Curve Digital Signature Algorithm [RFC6594]
Ed25519 = 4  # Ed25519 Signature Algorithm [RFC7479]

dns_algorithm = {
    1 : "RSA",
    2 : "DSS",
    3 : "ECDSA",
    4 : "Ed25519",
}

# Enum dns_fptype
SHA1   = 1  # Secure Hash Algorithm 1
SHA256 = 2  # Secure Hash Algorithm 256

dns_fptype = {
    1 : "SHA-1",
    2 : "SHA-256",
}
