#===============================================================================
# Copyright 2016 NetApp, Inc. All Rights Reserved,
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
ARP constants module

RFC 826 An Ethernet Address Resolution Protocol
"""
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2016 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

# Enum arp_oper
REQUEST = 1
REPLY   = 2
RARP_REQUEST = 3
RARP_REPLY   = 4

arp_oper = {
    1: "REQUEST",
    2: "REPLY",
    3: "REQUEST",
    4: "REPLY",
}

# Hardware types
HTYPE_ETHERNET = 1

# Protocol types
PTYPE_IPV4 = 0x0800
PTYPE_IPV6 = 0x86dd
