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
GSS constants module

Provide constant values and mapping dictionaries for the GSS layer.

RFC 2203 RPCSEC_GSS Protocol Specification
RFC 1964 The Kerberos Version 5 GSS-API Mechanism
"""
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

# Enum rpc_gss_service_t
rpc_gss_svc_none         = 1
rpc_gss_svc_integrity    = 2
rpc_gss_svc_privacy      = 3
rpc_gss_svc_channel_prot = 4
rpc_gss_service = {
    1: 'rpc_gss_svc_none',
    2: 'rpc_gss_svc_integrity',
    3: 'rpc_gss_svc_privacy',
    4: 'rpc_gss_svc_channel_prot',
}

# Enum rpc_gss_proc_t
RPCSEC_GSS_DATA          = 0
RPCSEC_GSS_INIT          = 1
RPCSEC_GSS_CONTINUE_INIT = 2
RPCSEC_GSS_DESTROY       = 3
RPCSEC_GSS_BIND_CHANNEL  = 4
rpc_gss_proc = {
    0: 'RPCSEC_GSS_DATA',
    1: 'RPCSEC_GSS_INIT',
    2: 'RPCSEC_GSS_CONTINUE_INIT',
    3: 'RPCSEC_GSS_DESTROY',
    4: 'RPCSEC_GSS_BIND_CHANNEL',
}

# Enum rgss2_bind_chan_status
RGSS2_BIND_CHAN_OK           = 0
RGSS2_BIND_CHAN_PREF_NOTSUPP = 1
RGSS2_BIND_CHAN_HASH_NOTSUPP = 2
gss_bind_chan_stat = {
    0: 'RGSS2_BIND_CHAN_OK',
    1: 'RGSS2_BIND_CHAN_PREF_NOTSUPP',
    2: 'RGSS2_BIND_CHAN_HASH_NOTSUPP',
}

RPCSEC_GSS_VERS_1 = 1
RPCSEC_GSS_VERS_2 = 2

# Integrity algorithm indicator
DES_MAC_MD5 = 0x0000
MD2_5       = 0x0100
DES_MAC     = 0x0200

gss_sgn_alg = {
    0x0000: "DES_MAC_MD5",
    0x0100: "MD2.5",
    0x0200: "DES_MAC",
}

# Enum gss_major_status
GSS_S_COMPLETE                   = 0x00000000  # Indicates an absence of any API errors or supplementary information bits
# Supplementary Information Codes
GSS_S_CONTINUE_NEEDED            = 0x00000001  # Returned only by gss_init_sec_context() or gss_accept_sec_context().
                                               # The routine must be called again to complete its function
GSSERR_S_DUPLICATE_TOKEN         = 0x00000002  # The token was a duplicate of an earlier token
GSSERR_S_OLD_TOKEN               = 0x00000004  # The token's validity period has expired
GSSERR_S_UNSEQ_TOKEN             = 0x00000008  # A later token has already been processed
GSSERR_S_GAP_TOKEN               = 0x00000010  # An expected per-message token was not received
# Routine Errors
GSSERR_S_BAD_MECH                = 0x00010000  # An unsupported mechanism was requested
GSSERR_S_BAD_NAME                = 0x00020000  # An invalid name was supplied
GSSERR_S_BAD_NAMETYPE            = 0x00030000  # A supplied name was of an unsupported type
GSSERR_S_BAD_BINDINGS            = 0x00040000  # Incorrect channel bindings were supplied
GSSERR_S_BAD_STATUS              = 0x00050000  # An invalid status code was supplied
GSSERR_S_BAD_SIG                 = 0x00060000  # A token had an invalid MIC
GSSERR_S_BAD_MIC                 = 0x00060000  # A token had an invalid MIC
GSSERR_S_NO_CRED                 = 0x00070000  # No credentials were supplied, or the credentials were unavailable or inaccessible
GSSERR_S_NO_CONTEXT              = 0x00080000  # No context has been established
GSSERR_S_DEFECTIVE_TOKEN         = 0x00090000  # A token was invalid
GSSERR_S_DEFECTIVE_CREDENTIAL    = 0x000a0000  # A credential was invalid
GSSERR_S_CREDENTIALS_EXPIRED     = 0x000b0000  # The referenced credentials have expired
GSSERR_S_CONTEXT_EXPIRED         = 0x000c0000  # The context has expired
GSSERR_S_FAILURE                 = 0x000d0000  # Miscellaneous failure. The underlying mechanism detected an error for which no
                                               # specific GSS-API status code is defined. The mechanism-specific status code
                                               # (minor-status code) provides more details about the error.
GSSERR_S_BAD_QOP                 = 0x000e0000  # The quality-of-protection requested could not be provided
GSSERR_S_UNAUTHORIZED            = 0x000f0000  # The operation is forbidden by local security policy
GSSERR_S_UNAVAILABLE             = 0x00100000  # The operation or option is unavailable
GSSERR_S_DUPLICATE_ELEMENT       = 0x00110000  # The requested credential element already exists
GSSERR_S_NAME_NOT_MN             = 0x00120000  # The provided name was not a Mechanism Name (MN)
# Calling Errors
GSSERR_S_CALL_INACCESSIBLE_READ  = 0x01000000  # A required input parameter could not be read
GSSERR_S_CALL_INACCESSIBLE_WRITE = 0x02000000  # A required output parameter could not be written
GSSERR_S_CALL_BAD_STRUCTURE      = 0x03000000  # A parameter was malformed

gss_major_status = {
    0x00000000 : "GSS_S_COMPLETE",
    0x00000001 : "GSS_S_CONTINUE_NEEDED",
    0x00000002 : "GSSERR_S_DUPLICATE_TOKEN",
    0x00000004 : "GSSERR_S_OLD_TOKEN",
    0x00000008 : "GSSERR_S_UNSEQ_TOKEN",
    0x00000010 : "GSSERR_S_GAP_TOKEN",
    0x00010000 : "GSSERR_S_BAD_MECH",
    0x00020000 : "GSSERR_S_BAD_NAME",
    0x00030000 : "GSSERR_S_BAD_NAMETYPE",
    0x00040000 : "GSSERR_S_BAD_BINDINGS",
    0x00050000 : "GSSERR_S_BAD_STATUS",
    0x00060000 : "GSSERR_S_BAD_SIG",
    0x00060000 : "GSSERR_S_BAD_MIC",
    0x00070000 : "GSSERR_S_NO_CRED",
    0x00080000 : "GSSERR_S_NO_CONTEXT",
    0x00090000 : "GSSERR_S_DEFECTIVE_TOKEN",
    0x000a0000 : "GSSERR_S_DEFECTIVE_CREDENTIAL",
    0x000b0000 : "GSSERR_S_CREDENTIALS_EXPIRED",
    0x000c0000 : "GSSERR_S_CONTEXT_EXPIRED",
    0x000d0000 : "GSSERR_S_FAILURE",
    0x000e0000 : "GSSERR_S_BAD_QOP",
    0x000f0000 : "GSSERR_S_UNAUTHORIZED",
    0x00100000 : "GSSERR_S_UNAVAILABLE",
    0x00110000 : "GSSERR_S_DUPLICATE_ELEMENT",
    0x00120000 : "GSSERR_S_NAME_NOT_MN",
    0x01000000 : "GSSERR_S_CALL_INACCESSIBLE_READ",
    0x02000000 : "GSSERR_S_CALL_INACCESSIBLE_WRITE",
    0x03000000 : "GSSERR_S_CALL_BAD_STRUCTURE",
}

# Enum gss_minor_status
KRB5KDC_ERR_NONE                 = -1765328384  # No error
KRB5KDC_ERR_NAME_EXP             = -1765328383  # Client's entry in database has expired
KRB5KDC_ERR_SERVICE_EXP          = -1765328382  # Server's entry in database has expired
KRB5KDC_ERR_BAD_PVNO             = -1765328381  # Requested protocol version not supported
KRB5KDC_ERR_C_OLD_MAST_KVNO      = -1765328380  # Client's key is encrypted in an old master key
KRB5KDC_ERR_S_OLD_MAST_KVNO      = -1765328379  # Server's key is encrypted in an old master key
KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN  = -1765328378  # Client not found in Kerberos database
KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN  = -1765328377  # Server not found in Kerberos database
KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE = -1765328376  # Principal has multiple entries in Kerberos database
KRB5KDC_ERR_NULL_KEY             = -1765328375  # Client or server has a null key
KRB5KDC_ERR_CANNOT_POSTDATE      = -1765328374  # Ticket is ineligible for postdating
KRB5KDC_ERR_NEVER_VALID          = -1765328373  # Requested effective lifetime is negative or too short
KRB5KDC_ERR_POLICY               = -1765328372  # KDC policy rejects request
KRB5KDC_ERR_BADOPTION            = -1765328371  # KDC can't fulfill requested option
KRB5KDC_ERR_ETYPE_NOSUPP         = -1765328370  # KDC has no support for encryption type
KRB5KDC_ERR_SUMTYPE_NOSUPP       = -1765328369  # KDC has no support for checksum type
KRB5KDC_ERR_PADATA_TYPE_NOSUPP   = -1765328368  # KDC has no support for padata type
KRB5KDC_ERR_TRTYPE_NOSUPP        = -1765328367  # KDC has no support for transited type
KRB5KDC_ERR_CLIENT_REVOKED       = -1765328366  # Client's credentials have been revoked
KRB5KDC_ERR_SERVICE_REVOKED      = -1765328365  # Credentials for server have been revoked
KRB5KDC_ERR_TGT_REVOKED          = -1765328364  # TGT has been revoked
KRB5KDC_ERR_CLIENT_NOTYET        = -1765328363  # Client not yet valid, try again later
KRB5KDC_ERR_SERVICE_NOTYET       = -1765328362  # Server not yet valid, try again later
KRB5KDC_ERR_KEY_EXP              = -1765328361  # Password has expired
KRB5KDC_ERR_PREAUTH_FAILED       = -1765328360  # Preauthentication failed
KRB5KDC_ERR_PREAUTH_REQUIRED     = -1765328359  # Additional preauthentication required
KRB5KDC_ERR_SERVER_NOMATCH       = -1765328358  # Requested server and ticket don't match
KRB5KRB_AP_ERR_BAD_INTEGRITY     = -1765328353  # Decrypt integrity check failed
KRB5KRB_AP_ERR_TKT_EXPIRED       = -1765328352  # Ticket expired
KRB5KRB_AP_ERR_TKT_NYV           = -1765328351  # Ticket not yet valid
KRB5KRB_AP_ERR_REPEAT            = -1765328350  # Request is a replay
KRB5KRB_AP_ERR_NOT_US            = -1765328349  # The ticket isn't for us
KRB5KRB_AP_ERR_BADMATCH          = -1765328348  # Ticket/authenticator do not match
KRB5KRB_AP_ERR_SKEW              = -1765328347  # Clock skew too great
KRB5KRB_AP_ERR_BADADDR           = -1765328346  # Incorrect net address
KRB5KRB_AP_ERR_BADVERSION        = -1765328345  # Protocol version mismatch
KRB5KRB_AP_ERR_MSG_TYPE          = -1765328344  # Invalid message type
KRB5KRB_AP_ERR_MODIFIED          = -1765328343  # Message stream modified
KRB5KRB_AP_ERR_BADORDER          = -1765328342  # Message out of order
KRB5KRB_AP_ERR_ILL_CR_TKT        = -1765328341  # Illegal cross-realm ticket
KRB5KRB_AP_ERR_BADKEYVER         = -1765328340  # Key version is not available
KRB5KRB_AP_ERR_NOKEY             = -1765328339  # Service key not available
KRB5KRB_AP_ERR_MUT_FAIL          = -1765328338  # Mutual authentication failed
KRB5KRB_AP_ERR_BADDIRECTION      = -1765328337  # Incorrect message direction
KRB5KRB_AP_ERR_METHOD            = -1765328336  # Alternative authentication method required
KRB5KRB_AP_ERR_BADSEQ            = -1765328335  # Incorrect sequence number in message
KRB5KRB_AP_ERR_INAPP_CKSUM       = -1765328334  # Inappropriate type of checksum in message
KRB5KRB_ERR_GENERIC              = -1765328324  # Generic error
KRB5KRB_ERR_FIELD_TOOLONG        = -1765328323  # Field is too long for this implementation
KRB5ERR_LIBOS_BADLOCKFLAG        = -1765328255  # Invalid flag for file lock mode
KRB5ERR_LIBOS_CANTREADPWD        = -1765328254  # Cannot read password
KRB5ERR_LIBOS_BADPWDMATCH        = -1765328253  # Password mismatch
KRB5ERR_LIBOS_PWDINTR            = -1765328252  # Password read interrupted
KRB5ERR_PARSE_ILLCHAR            = -1765328251  # Illegal character in component name
KRB5ERR_PARSE_MALFORMED          = -1765328250  # Malformed representation of principal
KRB5ERR_CONFIG_CANTOPEN          = -1765328249  # Can't open/find Kerberos /etc/krb5/krb5 configuration file
KRB5ERR_CONFIG_BADFORMAT         = -1765328248  # Improper format of Kerberos /etc/krb5/krb5 configuration file
KRB5ERR_CONFIG_NOTENUFSPACE      = -1765328247  # Insufficient space to return complete information
KRB5ERR_BADMSGTYPE               = -1765328246  # Invalid message type has been specified for encoding
KRB5ERR_CC_BADNAME               = -1765328245  # Credential cache name malformed
KRB5ERR_CC_UNKNOWN_TYPE          = -1765328244  # Unknown credential cache type
KRB5ERR_CC_NOTFOUND              = -1765328243  # No matching credential has been found
KRB5ERR_CC_END                   = -1765328242  # End of credential cache reached
KRB5ERR_NO_TKT_SUPPLIED          = -1765328241  # Request did not supply a ticket
KRB5KRB_AP_ERR_WRONG_PRINC       = -1765328240  # Wrong principal in request
KRB5KRB_AP_ERR_TKT_INVALID       = -1765328239  # Ticket has invalid flag set
KRB5ERR_PRINC_NOMATCH            = -1765328238  # Requested principal and ticket don't match
KRB5ERR_KDCREP_MODIFIED          = -1765328237  # KDC reply did not match expectations
KRB5ERR_KDCREP_SKEW              = -1765328236  # Clock skew too great in KDC reply
KRB5ERR_IN_TKT_REALM_MISMATCH    = -1765328235  # Client/server realm mismatch in initial ticket request
KRB5ERR_PROG_ETYPE_NOSUPP        = -1765328234  # Program lacks support for encryption type
KRB5ERR_PROG_KEYTYPE_NOSUPP      = -1765328233  # Program lacks support for key type
KRB5ERR_WRONG_ETYPE              = -1765328232  # Requested encryption type not used in message
KRB5ERR_PROG_SUMTYPE_NOSUPP      = -1765328231  # Program lacks support for checksum type
KRB5ERR_REALM_UNKNOWN            = -1765328230  # Cannot find KDC for requested realm
KRB5ERR_SERVICE_UNKNOWN          = -1765328229  # Kerberos service unknown
KRB5ERR_KDC_UNREACH              = -1765328228  # Cannot contact any KDC for requested realm
KRB5ERR_NO_LOCALNAME             = -1765328227  # No local name found for principal name
KRB5ERR_MUTUAL_FAILED            = -1765328226  # Mutual authentication failed
KRB5ERR_RC_TYPE_EXISTS           = -1765328225  # Replay cache type is already registered
KRB5ERR_RC_MALLOC                = -1765328224  # No more memory to allocate in replay cache code
KRB5ERR_RC_TYPE_NOTFOUND         = -1765328223  # Replay cache type is unknown
KRB5ERR_RC_UNKNOWN               = -1765328222  # Generic unknown RC error
KRB5ERR_RC_REPLAY                = -1765328221  # Message is a replay
KRB5ERR_RC_IO                    = -1765328220  # Replay I/O operation failed
KRB5ERR_RC_NOIO                  = -1765328219  # Replay cache type does not support non-volatile storage
KRB5ERR_RC_PARSE                 = -1765328218  # Replay cache name parse and format error
KRB5ERR_RC_IO_EOF                = -1765328217  # End-of-file on replay cache I/O
KRB5ERR_RC_IO_MALLOC             = -1765328216  # No more memory to allocate in replay cache I/O code
KRB5ERR_RC_IO_PERM               = -1765328215  # Permission denied in replay cache code
KRB5ERR_RC_IO_IO                 = -1765328214  # I/O error in replay cache i/o code
KRB5ERR_RC_IO_UNKNOWN            = -1765328213  # Generic unknown RC/IO error
KRB5ERR_RC_IO_SPACE              = -1765328212  # Insufficient system space to store replay information
KRB5ERR_TRANS_CANTOPEN           = -1765328211  # Can't open/find realm translation file
KRB5ERR_TRANS_BADFORMAT          = -1765328210  # Improper format of realm translation file
KRB5ERR_LNAME_CANTOPEN           = -1765328209  # Can't open or find
KRB5ERR_LNAME_NOTRANS            = -1765328208  # No translation is available for requested principal
KRB5ERR_LNAME_BADFORMAT          = -1765328207  # Improper format of translation database entry
KRB5ERR_CRYPTO_INTERNAL          = -1765328206  # Cryptosystem internal error
KRB5ERR_KT_BADNAME               = -1765328205  # Key table name malformed
KRB5ERR_KT_UNKNOWN_TYPE          = -1765328204  # Unknown Key table type
KRB5ERR_KT_NOTFOUND              = -1765328203  # Key table entry not found
KRB5ERR_KT_END                   = -1765328202  # End of key table reached
KRB5ERR_KT_NOWRITE               = -1765328201  # Cannot write to specified key table
KRB5ERR_KT_IOERR                 = -1765328200  # Error writing to key table
KRB5ERR_NO_TKT_IN_RLM            = -1765328199  # Cannot find ticket for requested realm
KRB5DES_ERR_BAD_KEYPAR           = -1765328198  # DES key has bad parity
KRB5DES_ERR_WEAK_KEY             = -1765328197  # DES key is a weak key
KRB5ERR_BAD_ENCTYPE              = -1765328196  # Bad encryption type
KRB5ERR_BAD_KEYSIZE              = -1765328195  # Key size is incompatible with encryption type
KRB5ERR_BAD_MSIZE                = -1765328194  # Message size is incompatible with encryption type
KRB5ERR_CC_TYPE_EXISTS           = -1765328193  # Credentials cache type is already registered
KRB5ERR_KT_TYPE_EXISTS           = -1765328192  # Key table type is already registered
KRB5ERR_CC_IO                    = -1765328191  # Credentials cache I/O operation failed
KRB5ERR_FCC_PERM                 = -1765328190  # Credentials cache file permissions incorrect
KRB5ERR_FCC_NOFILE               = -1765328189  # No credentials cache file found
KRB5ERR_FCC_INTERNAL             = -1765328188  # Internal file credentials cache error
KRB5ERR_CC_WRITE                 = -1765328187  # Error writing to credentials cache file
KRB5ERR_CC_NOMEM                 = -1765328186  # No more memory to allocate in credentials cache code
KRB5ERR_CC_FORMAT                = -1765328185  # Bad format in credentials cache
KRB5ERR_INVALID_FLAGS            = -1765328184  # Invalid KDC option combination, which is an internal library error
KRB5ERR_NO_2ND_TKT               = -1765328183  # Request missing second ticket
KRB5ERR_NOCREDS_SUPPLIED         = -1765328182  # No credentials supplied to library routine
KRB5ERR_SENDAUTH_BADAUTHVERS     = -1765328181  # Bad sendauth version was sent
KRB5ERR_SENDAUTH_BADAPPLVERS     = -1765328180  # Bad application version was sent by sendauth
KRB5ERR_SENDAUTH_BADRESPONSE     = -1765328179  # Bad response during sendauth exchange
KRB5ERR_SENDAUTH_REJECTED        = -1765328178  # Server rejected authentication during sendauth exchange
KRB5ERR_PREAUTH_BAD_TYPE         = -1765328177  # Unsupported preauthentication type
KRB5ERR_PREAUTH_NO_KEY           = -1765328176  # Required preauthentication key not supplied
KRB5ERR_PREAUTH_FAILED           = -1765328175  # Generic preauthentication failure
KRB5ERR_RCACHE_BADVNO            = -1765328174  # Unsupported format version number for replay cache
KRB5ERR_CCACHE_BADVNO            = -1765328173  # Unsupported credentials cache format version number
KRB5ERR_KEYTAB_BADVNO            = -1765328172  # Unsupported version number for key table format
KRB5ERR_PROG_ATYPE_NOSUPP        = -1765328171  # Program lacks support for address type
KRB5ERR_RC_REQUIRED              = -1765328170  # Message replay detection requires rcache parameter
KRB5_ERR_BAD_HOSTNAME            = -1765328169  # Host name cannot be canonicalized
KRB5_ERR_HOST_REALM_UNKNOWN      = -1765328168  # Cannot determine realm for host
KRB5ERR_SNAME_UNSUPP_NAMETYPE    = -1765328167  # Conversion to service principal is undefined for name type
KRB5KRB_AP_ERR_V4_REPLY          = -1765328166  # Initial Ticket response appears to be Version 4 error
KRB5ERR_REALM_CANT_RESOLVE       = -1765328165  # Cannot resolve KDC for requested realm
KRB5ERR_TKT_NOT_FORWARDABLE      = -1765328164  # The requesting ticket cannot get forwardable tickets
KRB5ERR_FWD_BAD_PRINCIPAL        = -1765328163  # Bad principal name while trying to forward credentials
KRB5ERR_GET_IN_TKT_LOOP          = -1765328162  # Looping detected inside krb5_get_in_tkt
KRB5ERR_CONFIG_NODEFREALM        = -1765328161  # Configuration file /etc/krb5/krb5.conf does not specify default realm
KRB5ERR_SAM_UNSUPPORTED          = -1765328160  # Bad SAM flags in obtain_sam_padata
KRB5ERR_KT_NAME_TOOLONG          = -1765328159  # Keytab name too long
KRB5ERR_KT_KVNONOTFOUND          = -1765328158  # Key version number for principal in key table is incorrect
KRB5ERR_CONF_NOT_CONFIGURED      = -1765328157  # Kerberos /etc/krb5/krb5.conf configuration file not configured

gss_minor_status = {
    -1765328384 : "KRB5KDC_ERR_NONE",
    -1765328383 : "KRB5KDC_ERR_NAME_EXP",
    -1765328382 : "KRB5KDC_ERR_SERVICE_EXP",
    -1765328381 : "KRB5KDC_ERR_BAD_PVNO",
    -1765328380 : "KRB5KDC_ERR_C_OLD_MAST_KVNO",
    -1765328379 : "KRB5KDC_ERR_S_OLD_MAST_KVNO",
    -1765328378 : "KRB5KDC_ERR_C_PRINCIPAL_UNKNOWN",
    -1765328377 : "KRB5KDC_ERR_S_PRINCIPAL_UNKNOWN",
    -1765328376 : "KRB5KDC_ERR_PRINCIPAL_NOT_UNIQUE",
    -1765328375 : "KRB5KDC_ERR_NULL_KEY",
    -1765328374 : "KRB5KDC_ERR_CANNOT_POSTDATE",
    -1765328373 : "KRB5KDC_ERR_NEVER_VALID",
    -1765328372 : "KRB5KDC_ERR_POLICY",
    -1765328371 : "KRB5KDC_ERR_BADOPTION",
    -1765328370 : "KRB5KDC_ERR_ETYPE_NOSUPP",
    -1765328369 : "KRB5KDC_ERR_SUMTYPE_NOSUPP",
    -1765328368 : "KRB5KDC_ERR_PADATA_TYPE_NOSUPP",
    -1765328367 : "KRB5KDC_ERR_TRTYPE_NOSUPP",
    -1765328366 : "KRB5KDC_ERR_CLIENT_REVOKED",
    -1765328365 : "KRB5KDC_ERR_SERVICE_REVOKED",
    -1765328364 : "KRB5KDC_ERR_TGT_REVOKED",
    -1765328363 : "KRB5KDC_ERR_CLIENT_NOTYET",
    -1765328362 : "KRB5KDC_ERR_SERVICE_NOTYET",
    -1765328361 : "KRB5KDC_ERR_KEY_EXP",
    -1765328360 : "KRB5KDC_ERR_PREAUTH_FAILED",
    -1765328359 : "KRB5KDC_ERR_PREAUTH_REQUIRED",
    -1765328358 : "KRB5KDC_ERR_SERVER_NOMATCH",
    -1765328353 : "KRB5KRB_AP_ERR_BAD_INTEGRITY",
    -1765328352 : "KRB5KRB_AP_ERR_TKT_EXPIRED",
    -1765328351 : "KRB5KRB_AP_ERR_TKT_NYV",
    -1765328350 : "KRB5KRB_AP_ERR_REPEAT",
    -1765328349 : "KRB5KRB_AP_ERR_NOT_US",
    -1765328348 : "KRB5KRB_AP_ERR_BADMATCH",
    -1765328347 : "KRB5KRB_AP_ERR_SKEW",
    -1765328346 : "KRB5KRB_AP_ERR_BADADDR",
    -1765328345 : "KRB5KRB_AP_ERR_BADVERSION",
    -1765328344 : "KRB5KRB_AP_ERR_MSG_TYPE",
    -1765328343 : "KRB5KRB_AP_ERR_MODIFIED",
    -1765328342 : "KRB5KRB_AP_ERR_BADORDER",
    -1765328341 : "KRB5KRB_AP_ERR_ILL_CR_TKT",
    -1765328340 : "KRB5KRB_AP_ERR_BADKEYVER",
    -1765328339 : "KRB5KRB_AP_ERR_NOKEY",
    -1765328338 : "KRB5KRB_AP_ERR_MUT_FAIL",
    -1765328337 : "KRB5KRB_AP_ERR_BADDIRECTION",
    -1765328336 : "KRB5KRB_AP_ERR_METHOD",
    -1765328335 : "KRB5KRB_AP_ERR_BADSEQ",
    -1765328334 : "KRB5KRB_AP_ERR_INAPP_CKSUM",
    -1765328324 : "KRB5KRB_ERR_GENERIC",
    -1765328323 : "KRB5KRB_ERR_FIELD_TOOLONG",
    -1765328255 : "KRB5ERR_LIBOS_BADLOCKFLAG",
    -1765328254 : "KRB5ERR_LIBOS_CANTREADPWD",
    -1765328253 : "KRB5ERR_LIBOS_BADPWDMATCH",
    -1765328252 : "KRB5ERR_LIBOS_PWDINTR",
    -1765328251 : "KRB5ERR_PARSE_ILLCHAR",
    -1765328250 : "KRB5ERR_PARSE_MALFORMED",
    -1765328249 : "KRB5ERR_CONFIG_CANTOPEN",
    -1765328248 : "KRB5ERR_CONFIG_BADFORMAT",
    -1765328247 : "KRB5ERR_CONFIG_NOTENUFSPACE",
    -1765328246 : "KRB5ERR_BADMSGTYPE",
    -1765328245 : "KRB5ERR_CC_BADNAME",
    -1765328244 : "KRB5ERR_CC_UNKNOWN_TYPE",
    -1765328243 : "KRB5ERR_CC_NOTFOUND",
    -1765328242 : "KRB5ERR_CC_END",
    -1765328241 : "KRB5ERR_NO_TKT_SUPPLIED",
    -1765328240 : "KRB5KRB_AP_ERR_WRONG_PRINC",
    -1765328239 : "KRB5KRB_AP_ERR_TKT_INVALID",
    -1765328238 : "KRB5ERR_PRINC_NOMATCH",
    -1765328237 : "KRB5ERR_KDCREP_MODIFIED",
    -1765328236 : "KRB5ERR_KDCREP_SKEW",
    -1765328235 : "KRB5ERR_IN_TKT_REALM_MISMATCH",
    -1765328234 : "KRB5ERR_PROG_ETYPE_NOSUPP",
    -1765328233 : "KRB5ERR_PROG_KEYTYPE_NOSUPP",
    -1765328232 : "KRB5ERR_WRONG_ETYPE",
    -1765328231 : "KRB5ERR_PROG_SUMTYPE_NOSUPP",
    -1765328230 : "KRB5ERR_REALM_UNKNOWN",
    -1765328229 : "KRB5ERR_SERVICE_UNKNOWN",
    -1765328228 : "KRB5ERR_KDC_UNREACH",
    -1765328227 : "KRB5ERR_NO_LOCALNAME",
    -1765328226 : "KRB5ERR_MUTUAL_FAILED",
    -1765328225 : "KRB5ERR_RC_TYPE_EXISTS",
    -1765328224 : "KRB5ERR_RC_MALLOC",
    -1765328223 : "KRB5ERR_RC_TYPE_NOTFOUND",
    -1765328222 : "KRB5ERR_RC_UNKNOWN",
    -1765328221 : "KRB5ERR_RC_REPLAY",
    -1765328220 : "KRB5ERR_RC_IO",
    -1765328219 : "KRB5ERR_RC_NOIO",
    -1765328218 : "KRB5ERR_RC_PARSE",
    -1765328217 : "KRB5ERR_RC_IO_EOF",
    -1765328216 : "KRB5ERR_RC_IO_MALLOC",
    -1765328215 : "KRB5ERR_RC_IO_PERM",
    -1765328214 : "KRB5ERR_RC_IO_IO",
    -1765328213 : "KRB5ERR_RC_IO_UNKNOWN",
    -1765328212 : "KRB5ERR_RC_IO_SPACE",
    -1765328211 : "KRB5ERR_TRANS_CANTOPEN",
    -1765328210 : "KRB5ERR_TRANS_BADFORMAT",
    -1765328209 : "KRB5ERR_LNAME_CANTOPEN",
    -1765328208 : "KRB5ERR_LNAME_NOTRANS",
    -1765328207 : "KRB5ERR_LNAME_BADFORMAT",
    -1765328206 : "KRB5ERR_CRYPTO_INTERNAL",
    -1765328205 : "KRB5ERR_KT_BADNAME",
    -1765328204 : "KRB5ERR_KT_UNKNOWN_TYPE",
    -1765328203 : "KRB5ERR_KT_NOTFOUND",
    -1765328202 : "KRB5ERR_KT_END",
    -1765328201 : "KRB5ERR_KT_NOWRITE",
    -1765328200 : "KRB5ERR_KT_IOERR",
    -1765328199 : "KRB5ERR_NO_TKT_IN_RLM",
    -1765328198 : "KRB5DES_ERR_BAD_KEYPAR",
    -1765328197 : "KRB5DES_ERR_WEAK_KEY",
    -1765328196 : "KRB5ERR_BAD_ENCTYPE",
    -1765328195 : "KRB5ERR_BAD_KEYSIZE",
    -1765328194 : "KRB5ERR_BAD_MSIZE",
    -1765328193 : "KRB5ERR_CC_TYPE_EXISTS",
    -1765328192 : "KRB5ERR_KT_TYPE_EXISTS",
    -1765328191 : "KRB5ERR_CC_IO",
    -1765328190 : "KRB5ERR_FCC_PERM",
    -1765328189 : "KRB5ERR_FCC_NOFILE",
    -1765328188 : "KRB5ERR_FCC_INTERNAL",
    -1765328187 : "KRB5ERR_CC_WRITE",
    -1765328186 : "KRB5ERR_CC_NOMEM",
    -1765328185 : "KRB5ERR_CC_FORMAT",
    -1765328184 : "KRB5ERR_INVALID_FLAGS",
    -1765328183 : "KRB5ERR_NO_2ND_TKT",
    -1765328182 : "KRB5ERR_NOCREDS_SUPPLIED",
    -1765328181 : "KRB5ERR_SENDAUTH_BADAUTHVERS",
    -1765328180 : "KRB5ERR_SENDAUTH_BADAPPLVERS",
    -1765328179 : "KRB5ERR_SENDAUTH_BADRESPONSE",
    -1765328178 : "KRB5ERR_SENDAUTH_REJECTED",
    -1765328177 : "KRB5ERR_PREAUTH_BAD_TYPE",
    -1765328176 : "KRB5ERR_PREAUTH_NO_KEY",
    -1765328175 : "KRB5ERR_PREAUTH_FAILED",
    -1765328174 : "KRB5ERR_RCACHE_BADVNO",
    -1765328173 : "KRB5ERR_CCACHE_BADVNO",
    -1765328172 : "KRB5ERR_KEYTAB_BADVNO",
    -1765328171 : "KRB5ERR_PROG_ATYPE_NOSUPP",
    -1765328170 : "KRB5ERR_RC_REQUIRED",
    -1765328169 : "KRB5_ERR_BAD_HOSTNAME",
    -1765328168 : "KRB5_ERR_HOST_REALM_UNKNOWN",
    -1765328167 : "KRB5ERR_SNAME_UNSUPP_NAMETYPE",
    -1765328166 : "KRB5KRB_AP_ERR_V4_REPLY",
    -1765328165 : "KRB5ERR_REALM_CANT_RESOLVE",
    -1765328164 : "KRB5ERR_TKT_NOT_FORWARDABLE",
    -1765328163 : "KRB5ERR_FWD_BAD_PRINCIPAL",
    -1765328162 : "KRB5ERR_GET_IN_TKT_LOOP",
    -1765328161 : "KRB5ERR_CONFIG_NODEFREALM",
    -1765328160 : "KRB5ERR_SAM_UNSUPPORTED",
    -1765328159 : "KRB5ERR_KT_NAME_TOOLONG",
    -1765328158 : "KRB5ERR_KT_KVNONOTFOUND",
    -1765328157 : "KRB5ERR_CONF_NOT_CONFIGURED",
}
