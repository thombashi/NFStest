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
KRB5 constants module

Provide constant values and mapping dictionaries for the KRB5 layer.

RFC 4120 The Kerberos Network Authentication Service (V5)
RFC 6113 A Generalized Framework for Kerberos Pre-Authentication
"""
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2015 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

# KDCOptions
kdc_options = {
     0 : "reserved",
     1 : "forwardable",
     2 : "forwarded",
     3 : "proxiable",
     4 : "proxy",
     5 : "allow_postdate",
     6 : "postdated",
     8 : "renewable",
    11 : "opt_hardware_auth",
    14 : "constrained_delegation",
    15 : "canonicalize",
    26 : "disable_transited_check",
    27 : "renewable_ok",
    28 : "enc_tkt_in_skey",
    30 : "renew",
    31 : "validate",
}

# APOptions
ap_options = {
    0 : "reserved",
    1 : "use_session_key",
    2 : "mutual_required",
}

# Enum krb5_application
Ticket         = 1   # PDU
Authenticator  = 2   # non-PDU
EncTicketPart  = 3   # non-PDU
AS_REQ         = 10  # PDU
AS_REP         = 11  # PDU
TGS_REQ        = 12  # PDU
TGS_REP        = 13  # PDU
AP_REQ         = 14  # PDU
AP_REP         = 15  # PDU
RESERVED16     = 16  # TGT-REQ (for user-to-user)
RESERVED17     = 17  # TGT-REP (for user-to-user)
KRB_SAFE       = 20  # PDU
KRB_PRIV       = 21  # PDU
KRB_CRED       = 22  # PDU
EncASRepPart   = 25  # non-PDU
EncTGSRepPart  = 26  # non-PDU
EncApRepPart   = 27  # non-PDU
EncKrbPrivPart = 28  # non-PDU
EncKrbCredPart = 29  # non-PDU
KRB_ERROR      = 30  # PDU

krb5_application = {
     1 : "Ticket",
     2 : "Authenticator",
     3 : "EncTicketPart",
    10 : "AS-REQ",
    11 : "AS-REP",
    12 : "TGS-REQ",
    13 : "TGS-REP",
    14 : "AP-REQ",
    15 : "AP-REP",
    16 : "RESERVED16",
    17 : "RESERVED17",
    20 : "KRB-SAFE",
    21 : "KRB-PRIV",
    22 : "KRB-CRED",
    25 : "EncASRepPart",
    26 : "EncTGSRepPart",
    27 : "EncApRepPart",
    28 : "EncKrbPrivPart",
    29 : "EncKrbCredPart",
    30 : "KRB-ERROR",
}

# Enum krb5_principal
UNKNOWN        = 0   # Name type not known
PRINCIPAL      = 1   # Just the name of the principal as in DCE, or for users
SRV_INST       = 2   # Service and other unique instance (krbtgt)
SRV_HST        = 3   # Service with host name as instance (telnet, rcommands)
SRV_XHST       = 4   # Service with host as remaining components
UID            = 5   # Unique ID
X500_PRINCIPAL = 6   # Encoded X.509 Distinguished name [RFC2253]
SMTP_NAME      = 7   # Name in form of SMTP email name (e.g., user@example.com)
ENTERPRISE     = 10  # Enterprise name - may be mapped to principal name

krb5_principal = {
     0 : "UNKNOWN",
     1 : "PRINCIPAL",
     2 : "SRV-INST",
     3 : "SRV-HST",
     4 : "SRV-XHST",
     5 : "UID",
     6 : "X500-PRINCIPAL",
     7 : "SMTP-NAME",
    10 : "ENTERPRISE",
}

# Enum krb5_patype
PA_TGS_REQ                 = 1    # [RFC4120]
PA_ENC_TIMESTAMP           = 2    # [RFC4120]
PA_PW_SALT                 = 3    # [RFC4120]
PA_ENC_UNIX_TIME           = 5    # (deprecated) [RFC4120]
PA_SANDIA_SECUREID         = 6    # [RFC4120]
PA_SESAME                  = 7    # [RFC4120]
PA_OSF_DCE                 = 8    # [RFC4120]
PA_CYBERSAFE_SECUREID      = 9    # [RFC4120]
PA_AFS3_SALT               = 10   # [RFC4120][RFC3961]
PA_ETYPE_INFO              = 11   # [RFC4120]
PA_SAM_CHALLENGE           = 12   # [draft-ietf-cat-kerberos-passwords-04]
PA_SAM_RESPONSE            = 13   # [draft-ietf-cat-kerberos-passwords-04]
PA_PK_AS_REQ_OLD           = 14   # [draft-ietf-cat-kerberos-pk-init-09]
PA_PK_AS_REP_OLD           = 15   # [draft-ietf-cat-kerberos-pk-init-09]
PA_PK_AS_REQ               = 16   # [RFC4556]
PA_PK_AS_REP               = 17   # [RFC4556]
PA_PK_OCSP_RESPONSE        = 18   # [RFC4557]
PA_ETYPE_INFO2             = 19   # [RFC4120]
PA_USE_SPECIFIED_KVNO      = 20   # [RFC4120]
PA_SVR_REFERRAL_INFO       = 20   # [RFC6806]
PA_SAM_REDIRECT            = 21   # [draft-ietf-krb-wg-kerberos-sam-03]
PA_GET_FROM_TYPED_DATA     = 22   # [(embedded in typed data)][RFC4120]
TD_PADATA                  = 22   # [(embeds padata)][RFC4120]
PA_SAM_ETYPE_INFO          = 23   # [(sam/otp)][draft-ietf-krb-wg-kerberos-sam-03]
PA_ALT_PRINC               = 24   # [draft-ietf-krb-wg-hw-auth-04]
PA_SERVER_REFERRAL         = 25   # [draft-ietf-krb-wg-kerberos-referrals-11]
PA_SAM_CHALLENGE2          = 30   # [draft-ietf-krb-wg-kerberos-sam-03]
PA_SAM_RESPONSE2           = 31   # [draft-ietf-krb-wg-kerberos-sam-03]
PA_EXTRA_TGT               = 41   # [Reserved extra TGT][RFC6113]
TD_PKINIT_CMS_CERTIFICATES = 101  # [RFC4556]
TD_KRB_PRINCIPAL           = 102  # [PrincipalName][RFC6113]
TD_KRB_REALM               = 103  # [Realm][RFC6113]
TD_TRUSTED_CERTIFIERS      = 104  # [RFC4556]
TD_CERTIFICATE_INDEX       = 105  # [RFC4556]
TD_APP_DEFINED_ERROR       = 106  # [Application specific][RFC6113]
TD_REQ_NONCE               = 107  # [INTEGER][RFC6113]
TD_REQ_SEQ                 = 108  # [INTEGER][RFC6113]
TD_DH_PARAMETERS           = 109  # [RFC4556]
TD_CMS_DIGEST_ALGORITHMS   = 111  # [draft-ietf-krb-wg-pkinit-alg-agility]
TD_CERT_DIGEST_ALGORITHMS  = 112  # [draft-ietf-krb-wg-pkinit-alg-agility]
PA_PAC_REQUEST             = 128  # [MSKILE][http://msdn2.microsoft.com/en-us/library/cc206927.aspx]
PA_FOR_USER                = 129  # [MSKILE][http://msdn2.microsoft.com/en-us/library/cc206927.aspx]
PA_FOR_X509_USER           = 130  # [MSKILE][http://msdn2.microsoft.com/en-us/library/cc206927.aspx]
PA_FOR_CHECK_DUPS          = 131  # [MSKILE][http://msdn2.microsoft.com/en-us/library/cc206927.aspx]
PA_AS_CHECKSUM             = 132  # [MSKILE][http://msdn2.microsoft.com/en-us/library/cc206927.aspx]
PA_FX_COOKIE               = 133  # [RFC6113]
PA_AUTHENTICATION_SET      = 134  # [RFC6113]
PA_AUTH_SET_SELECTED       = 135  # [RFC6113]
PA_FX_FAST                 = 136  # [RFC6113]
PA_FX_ERROR                = 137  # [RFC6113]
PA_ENCRYPTED_CHALLENGE     = 138  # [RFC6113]
PA_OTP_CHALLENGE           = 141  # [RFC6560]
PA_OTP_REQUEST             = 142  # [RFC6560]
PA_OTP_CONFIRM             = 143  # (OBSOLETED) [RFC6560]
PA_OTP_PIN_CHANGE          = 144  # [RFC6560]
PA_EPAK_AS_REQ             = 145  # [RFC6113]
PA_EPAK_AS_REP             = 146  # [RFC6113]
PA_PKINIT_KX               = 147  # [RFC6112]
PA_PKU2U_NAME              = 148  # [draft-zhu-pku2u]
PA_REQ_ENC_PA_REP          = 149  # [RFC6806]
PA_AS_FRESHNESS            = 150  # [draft-ietf-kitten-pkinit-freshness]
PA_SUPPORTED_ETYPES        = 165  # [MSKILE][http://msdn2.microsoft.com/en-us/library/cc206927.aspx]
PA_EXTENDED_ERROR          = 166  # [MSKILE][http://msdn2.microsoft.com/en-us/library/cc206927.aspx]

krb5_patype = {
      1 : "PA-TGS-REQ",
      2 : "PA-ENC-TIMESTAMP",
      3 : "PA-PW-SALT",
      5 : "PA-ENC-UNIX-TIME",
      6 : "PA-SANDIA-SECUREID",
      7 : "PA-SESAME",
      8 : "PA-OSF-DCE",
      9 : "PA-CYBERSAFE-SECUREID",
     10 : "PA-AFS3-SALT",
     11 : "PA-ETYPE-INFO",
     12 : "PA-SAM-CHALLENGE",
     13 : "PA-SAM-RESPONSE",
     14 : "PA-PK-AS-REQ_OLD",
     15 : "PA-PK-AS-REP_OLD",
     16 : "PA-PK-AS-REQ",
     17 : "PA-PK-AS-REP",
     18 : "PA-PK-OCSP-RESPONSE",
     19 : "PA-ETYPE-INFO2",
     20 : "PA-USE-SPECIFIED-KVNO",
     20 : "PA-SVR-REFERRAL-INFO",
     21 : "PA-SAM-REDIRECT",
     22 : "PA-GET-FROM-TYPED-DATA",
     22 : "TD-PADATA",
     23 : "PA-SAM-ETYPE-INFO",
     24 : "PA-ALT-PRINC",
     25 : "PA-SERVER-REFERRAL",
     30 : "PA-SAM-CHALLENGE2",
     31 : "PA-SAM-RESPONSE2",
     41 : "PA-EXTRA-TGT",
    101 : "TD-PKINIT-CMS-CERTIFICATES",
    102 : "TD-KRB-PRINCIPAL",
    103 : "TD-KRB-REALM",
    104 : "TD-TRUSTED-CERTIFIERS",
    105 : "TD-CERTIFICATE-INDEX",
    106 : "TD-APP-DEFINED-ERROR",
    107 : "TD-REQ-NONCE",
    108 : "TD-REQ-SEQ",
    109 : "TD_DH_PARAMETERS",
    111 : "TD-CMS-DIGEST-ALGORITHMS",
    112 : "TD-CERT-DIGEST-ALGORITHMS",
    128 : "PA-PAC-REQUEST",
    129 : "PA-FOR_USER",
    130 : "PA-FOR-X509-USER",
    131 : "PA-FOR-CHECK_DUPS",
    132 : "PA-AS-CHECKSUM",
    133 : "PA-FX-COOKIE",
    134 : "PA-AUTHENTICATION-SET",
    135 : "PA-AUTH-SET-SELECTED",
    136 : "PA-FX-FAST",
    137 : "PA-FX-ERROR",
    138 : "PA-ENCRYPTED-CHALLENGE",
    141 : "PA-OTP-CHALLENGE",
    142 : "PA-OTP-REQUEST",
    143 : "PA-OTP-CONFIRM",
    144 : "PA-OTP-PIN-CHANGE",
    145 : "PA-EPAK-AS-REQ",
    146 : "PA-EPAK-AS-REP",
    147 : "PA_PKINIT_KX",
    148 : "PA_PKU2U_NAME",
    149 : "PA-REQ-ENC-PA-REP",
    150 : "PA_AS_FRESHNESS",
    165 : "PA-SUPPORTED-ETYPES",
    166 : "PA-EXTENDED_ERROR",
}

# Enum krb5_addrtype
IPv4            = 2
Directional     = 3
ChaosNet        = 5
XNS             = 6
ISO             = 7
DECNET_Phase_IV = 12
AppleTalk_DDP   = 16
NetBios         = 20
IPv6            = 24

krb5_addrtype = {
     2 : "IPv4",
     3 : "Directional",
     5 : "ChaosNet",
     6 : "XNS",
     7 : "ISO",
    12 : "DECNET-Phase-IV",
    16 : "AppleTalk-DDP",
    20 : "NetBios",
    24 : "IPv6",
}

# Enum krb5_adtype
AD_IF_RELEVANT                    = 1
AD_INTENDED_FOR_SERVER            = 2
AD_INTENDED_FOR_APPLICATION_CLASS = 3
AD_KDC_ISSUED                     = 4
AD_AND_OR                         = 5
AD_MANDATORY_TICKET_EXTENSIONS    = 6
AD_IN_TICKET_EXTENSIONS           = 7
AD_MANDATORY_FOR_KDC              = 8
OSF_DCE                           = 64
SESAME                            = 65
AD_OSF_DCE_PKI_CERTID             = 66
AD_WIN2K_PAC                      = 128
AD_ETYPE_NEGOTIATION              = 129

krb5_adtype = {
      1 : "AD-IF-RELEVANT",
      2 : "AD-INTENDED-FOR-SERVER",
      3 : "AD-INTENDED-FOR-APPLICATION-CLASS",
      4 : "AD-KDC-ISSUED",
      5 : "AD-AND-OR",
      6 : "AD-MANDATORY-TICKET-EXTENSIONS",
      7 : "AD-IN-TICKET-EXTENSIONS",
      8 : "AD-MANDATORY-FOR-KDC",
     64 : "OSF-DCE",
     65 : "SESAME",
     66 : "AD-OSF-DCE-PKI-CERTID",
    128 : "AD-WIN2K-PAC",
    129 : "AD-ETYPE-NEGOTIATION",
}

# Enum krb5_etype
des_cbc_crc                  = 1   # [RFC3961]
des_cbc_md4                  = 2   # [RFC3961]
des_cbc_md5                  = 3   # [RFC3961]
des3_cbc_md5                 = 5
des3_cbc_sha1                = 7
dsaWithSHA1_CmsOID           = 9   # [RFC4556]
md5WithRSAEncryption_CmsOID  = 10  # [RFC4556]
sha1WithRSAEncryption_CmsOID = 11  # [RFC4556]
rc2CBC_EnvOID                = 12  # [RFC4556]
rsaEncryption_EnvOID         = 13  # [RFC4556][from PKCS#1 v1.5]]
rsaES_OAEP_ENV_OID           = 14  # [RFC4556][from PKCS#1 v2.0]]
des_ede3_cbc_Env_OID         = 15  # [RFC4556]
des3_cbc_sha1_kd             = 16  # [RFC3961]
aes128_cts_hmac_sha1_96      = 17  # [RFC3962]
aes256_cts_hmac_sha1_96      = 18  # [RFC3962]
rc4_hmac                     = 23  # [RFC4757]
rc4_hmac_exp                 = 24  # [RFC4757]
camellia128_cts_cmac         = 25  # [RFC6803]
camellia256_cts_cmac         = 26  # [RFC6803]
subkey_keymaterial           = 65  # [(opaque; PacketCable)]

krb5_etype = {
     1 : "des-cbc-crc",
     2 : "des-cbc-md4",
     3 : "des-cbc-md5",
     5 : "des3-cbc-md5",
     7 : "des3-cbc-sha1",
     9 : "dsaWithSHA1-CmsOID",
    10 : "md5WithRSAEncryption-CmsOID",
    11 : "sha1WithRSAEncryption-CmsOID",
    12 : "rc2CBC-EnvOID",
    13 : "rsaEncryption-EnvOID",
    14 : "rsaES-OAEP-ENV-OID",
    15 : "des-ede3-cbc-Env-OID",
    16 : "des3-cbc-sha1-kd",
    17 : "aes128-cts-hmac-sha1-96",
    18 : "aes256-cts-hmac-sha1-96",
    23 : "rc4-hmac",
    24 : "rc4-hmac-exp",
    25 : "camellia128-cts-cmac",
    26 : "camellia256-cts-cmac",
    65 : "subkey-keymaterial",
}

# Enum krb5_ctype
CRC32               = 1   # Checksum size:4  [RFC3961]
rsa_md4             = 2   # Checksum size:16 [RFC3961]
rsa_md4_des         = 3   # Checksum size:24 [RFC3961]
des_mac             = 4   # Checksum size:16 [RFC3961]
des_mac_k           = 5   # Checksum size:8  [RFC3961]
rsa_md4_des_k       = 6   # Checksum size:16 [RFC3961]
rsa_md5             = 7   # Checksum size:16 [RFC3961]
rsa_md5_des         = 8   # Checksum size:24 [RFC3961]
rsa_md5_des3        = 9   # Checksum size:24
sha1                = 10  # Checksum size:20 (unkeyed)
hmac_sha1_des3_kd   = 12  # Checksum size:20 [RFC3961]
hmac_sha1_des3      = 13  # Checksum size:20
sha1                = 14  # Checksum size:20 (unkeyed)
hmac_sha1_96_aes128 = 15  # Checksum size:20 [RFC3962]
hmac_sha1_96_aes256 = 16  # Checksum size:20 [RFC3962]
cmac_camellia128    = 17  # Checksum size:16 [RFC6803]
cmac_camellia256    = 18  # Checksum size:16 [RFC6803]

krb5_ctype = {
     1 : "CRC32",
     2 : "rsa-md4",
     3 : "rsa-md4-des",
     4 : "des-mac",
     5 : "des-mac-k",
     6 : "rsa-md4-des-k",
     7 : "rsa-md5",
     8 : "rsa-md5-des",
     9 : "rsa-md5-des3",
    10 : "sha1",
    12 : "hmac-sha1-des3-kd",
    13 : "hmac-sha1-des3",
    14 : "sha1",
    15 : "hmac-sha1-96-aes128",
    16 : "hmac-sha1-96-aes256",
    17 : "cmac-camellia128",
    18 : "cmac-camellia256",
}

# Enum krb5_fatype
RESERVED                 = 0
FX_FAST_ARMOR_AP_REQUEST = 1  # Ticket armor using an ap-req

krb5_fatype = {
    0 : "RESERVED",
    1 : "FX_FAST_ARMOR_AP_REQUEST",
}

# Enum krb5_status
KDC_OK                                = 0   # No error
KDC_ERR_NAME_EXP                      = 1   # Client's entry in database has expired
KDC_ERR_SERVICE_EXP                   = 2   # Server's entry in database has expired
KDC_ERR_BAD_PVNO                      = 3   # Requested protocol version number not supported
KDC_ERR_C_OLD_MAST_KVNO               = 4   # Client's key encrypted in old master key
KDC_ERR_S_OLD_MAST_KVNO               = 5   # Server's key encrypted in old master key
KDC_ERR_C_PRINCIPAL_UNKNOWN           = 6   # Client not found in Kerberos database
KDC_ERR_S_PRINCIPAL_UNKNOWN           = 7   # Server not found in Kerberos database
KDC_ERR_PRINCIPAL_NOT_UNIQUE          = 8   # Multiple principal entries in database
KDC_ERR_NULL_KEY                      = 9   # The client or server has a null key
KDC_ERR_CANNOT_POSTDATE               = 10  # Ticket not eligible for postdating
KDC_ERR_NEVER_VALID                   = 11  # Requested starttime is later than end time
KDC_ERR_POLICY                        = 12  # KDC policy rejects request
KDC_ERR_BADOPTION                     = 13  # KDC cannot accommodate requested option
KDC_ERR_ETYPE_NOSUPP                  = 14  # KDC has no support for encryption type
KDC_ERR_SUMTYPE_NOSUPP                = 15  # KDC has no support for checksum type
KDC_ERR_PADATA_TYPE_NOSUPP            = 16  # KDC has no support for padata type
KDC_ERR_TRTYPE_NOSUPP                 = 17  # KDC has no support for transited type
KDC_ERR_CLIENT_REVOKED                = 18  # Clients credentials have been revoked
KDC_ERR_SERVICE_REVOKED               = 19  # Credentials for server have been revoked
KDC_ERR_TGT_REVOKED                   = 20  # TGT has been revoked
KDC_ERR_CLIENT_NOTYET                 = 21  # Client not yet valid; try again later
KDC_ERR_SERVICE_NOTYET                = 22  # Server not yet valid; try again later
KDC_ERR_KEY_EXPIRED                   = 23  # Password has expired; change password to reset
KDC_ERR_PREAUTH_FAILED                = 24  # Pre-authentication information was invalid
KDC_ERR_PREAUTH_REQUIRED              = 25  # Additional pre-authentication required
KDC_ERR_SERVER_NOMATCH                = 26  # Requested server and ticket don't match
KDC_ERR_MUST_USE_USER2USER            = 27  # Server principal valid for user2user only
KDC_ERR_PATH_NOT_ACCEPTED             = 28  # KDC Policy rejects transited path
KDC_ERR_SVC_UNAVAILABLE               = 29  # A service is not available
KRB_AP_ERR_BAD_INTEGRITY              = 31  # Integrity check on decrypted field failed
KRB_AP_ERR_TKT_EXPIRED                = 32  # Ticket expired
KRB_AP_ERR_TKT_NYV                    = 33  # Ticket not yet valid
KRB_AP_ERR_REPEAT                     = 34  # Request is a replay
KRB_AP_ERR_NOT_US                     = 35  # The ticket isn't for us
KRB_AP_ERR_BADMATCH                   = 36  # Ticket and authenticator don't match
KRB_AP_ERR_SKEW                       = 37  # Clock skew too great
KRB_AP_ERR_BADADDR                    = 38  # Incorrect net address
KRB_AP_ERR_BADVERSION                 = 39  # Protocol version mismatch
KRB_AP_ERR_MSG_TYPE                   = 40  # Invalid msg type
KRB_AP_ERR_MODIFIED                   = 41  # Message stream modified
KRB_AP_ERR_BADORDER                   = 42  # Message out of order
KRB_AP_ERR_BADKEYVER                  = 44  # Specified version of key is not available
KRB_AP_ERR_NOKEY                      = 45  # Service key not available
KRB_AP_ERR_MUT_FAIL                   = 46  # Mutual authentication failed
KRB_AP_ERR_BADDIRECTION               = 47  # Incorrect message direction
KRB_AP_ERR_METHOD                     = 48  # Alternative authentication method required
KRB_AP_ERR_BADSEQ                     = 49  # Incorrect sequence number in message
KRB_AP_ERR_INAPP_CKSUM                = 50  # Inappropriate type of checksum in message
KRB_AP_ERR_PATH_NOT_ACCEPTED          = 51  # Policy rejects transited path
KRB_ERR_RESPONSE_TOO_BIG              = 52  # Response too big for UDP; retry with TCP
KRB_ERR_GENERIC                       = 60  # Generic error (description in e-text)
KRB_ERR_FIELD_TOOLONG                 = 61  # Field is too long for this implementation
KDC_ERR_CLIENT_NOT_TRUSTED            = 62  # Reserved for PKINIT
KDC_ERR_KDC_NOT_TRUSTED               = 63  # Reserved for PKINIT
KDC_ERR_INVALID_SIG                   = 64  # Reserved for PKINIT
KDC_ERR_KEY_TOO_WEAK                  = 65  # Reserved for PKINIT
KDC_ERR_CERTIFICATE_MISMATCH          = 66  # Reserved for PKINIT
KRB_AP_ERR_NO_TGT                     = 67  # No TGT available to validate USER-TO-USER
KDC_ERR_WRONG_REALM                   = 68  # Reserved for future use
KRB_AP_ERR_USER_TO_USER_REQUIRED      = 69  # Ticket must be for USER-TO-USER
KDC_ERR_CANT_VERIFY_CERTIFICATE       = 70  # Reserved for PKINIT
KDC_ERR_INVALID_CERTIFICATE           = 71  # Reserved for PKINIT
KDC_ERR_REVOKED_CERTIFICATE           = 72  # Reserved for PKINIT
KDC_ERR_REVOCATION_STATUS_UNKNOWN     = 73  # Reserved for PKINIT
KDC_ERR_REVOCATION_STATUS_UNAVAILABLE = 74  # Reserved for PKINIT
KDC_ERR_CLIENT_NAME_MISMATCH          = 75  # Reserved for PKINIT
KDC_ERR_KDC_NAME_MISMATCH             = 76  # Reserved for PKINIT

krb5_status = {
     0 : "KDC_OK",
     1 : "KDC_ERR_NAME_EXP",
     2 : "KDC_ERR_SERVICE_EXP",
     3 : "KDC_ERR_BAD_PVNO",
     4 : "KDC_ERR_C_OLD_MAST_KVNO",
     5 : "KDC_ERR_S_OLD_MAST_KVNO",
     6 : "KDC_ERR_C_PRINCIPAL_UNKNOWN",
     7 : "KDC_ERR_S_PRINCIPAL_UNKNOWN",
     8 : "KDC_ERR_PRINCIPAL_NOT_UNIQUE",
     9 : "KDC_ERR_NULL_KEY",
    10 : "KDC_ERR_CANNOT_POSTDATE",
    11 : "KDC_ERR_NEVER_VALID",
    12 : "KDC_ERR_POLICY",
    13 : "KDC_ERR_BADOPTION",
    14 : "KDC_ERR_ETYPE_NOSUPP",
    15 : "KDC_ERR_SUMTYPE_NOSUPP",
    16 : "KDC_ERR_PADATA_TYPE_NOSUPP",
    17 : "KDC_ERR_TRTYPE_NOSUPP",
    18 : "KDC_ERR_CLIENT_REVOKED",
    19 : "KDC_ERR_SERVICE_REVOKED",
    20 : "KDC_ERR_TGT_REVOKED",
    21 : "KDC_ERR_CLIENT_NOTYET",
    22 : "KDC_ERR_SERVICE_NOTYET",
    23 : "KDC_ERR_KEY_EXPIRED",
    24 : "KDC_ERR_PREAUTH_FAILED",
    25 : "KDC_ERR_PREAUTH_REQUIRED",
    26 : "KDC_ERR_SERVER_NOMATCH",
    27 : "KDC_ERR_MUST_USE_USER2USER",
    28 : "KDC_ERR_PATH_NOT_ACCEPTED",
    29 : "KDC_ERR_SVC_UNAVAILABLE",
    31 : "KRB_AP_ERR_BAD_INTEGRITY",
    32 : "KRB_AP_ERR_TKT_EXPIRED",
    33 : "KRB_AP_ERR_TKT_NYV",
    34 : "KRB_AP_ERR_REPEAT",
    35 : "KRB_AP_ERR_NOT_US",
    36 : "KRB_AP_ERR_BADMATCH",
    37 : "KRB_AP_ERR_SKEW",
    38 : "KRB_AP_ERR_BADADDR",
    39 : "KRB_AP_ERR_BADVERSION",
    40 : "KRB_AP_ERR_MSG_TYPE",
    41 : "KRB_AP_ERR_MODIFIED",
    42 : "KRB_AP_ERR_BADORDER",
    44 : "KRB_AP_ERR_BADKEYVER",
    45 : "KRB_AP_ERR_NOKEY",
    46 : "KRB_AP_ERR_MUT_FAIL",
    47 : "KRB_AP_ERR_BADDIRECTION",
    48 : "KRB_AP_ERR_METHOD",
    49 : "KRB_AP_ERR_BADSEQ",
    50 : "KRB_AP_ERR_INAPP_CKSUM",
    51 : "KRB_AP_ERR_PATH_NOT_ACCEPTED",
    52 : "KRB_ERR_RESPONSE_TOO_BIG",
    60 : "KRB_ERR_GENERIC",
    61 : "KRB_ERR_FIELD_TOOLONG",
    62 : "KDC_ERR_CLIENT_NOT_TRUSTED",
    63 : "KDC_ERR_KDC_NOT_TRUSTED",
    64 : "KDC_ERR_INVALID_SIG",
    65 : "KDC_ERR_KEY_TOO_WEAK",
    66 : "KDC_ERR_CERTIFICATE_MISMATCH",
    67 : "KRB_AP_ERR_NO_TGT",
    68 : "KDC_ERR_WRONG_REALM",
    69 : "KRB_AP_ERR_USER_TO_USER_REQUIRED",
    70 : "KDC_ERR_CANT_VERIFY_CERTIFICATE",
    71 : "KDC_ERR_INVALID_CERTIFICATE",
    72 : "KDC_ERR_REVOKED_CERTIFICATE",
    73 : "KDC_ERR_REVOCATION_STATUS_UNKNOWN",
    74 : "KDC_ERR_REVOCATION_STATUS_UNAVAILABLE",
    75 : "KDC_ERR_CLIENT_NAME_MISMATCH",
    76 : "KDC_ERR_KDC_NAME_MISMATCH",
}
