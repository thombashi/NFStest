#===============================================================================
# Copyright 2012 NetApp, Inc. All Rights Reserved,
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
IPv6Addr module

Create an object to represent an IPv6 address. An IPv6 address is given either
by a series of hexadecimal numbers or using the ":" notation. It provides
a mechanism for comparing this object with a regular string. It also takes
care of '::' notation and leading zeroes.
"""
import nfstest_config as c

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.1"

class IPv6Addr(str):
    """IPv6Addr address object

       Usage:
           from packet.internet.ipv6addr import IPv6Addr

           ip = IPv6Addr('fe80000000000000020c29fffe5409ef')

       The following expressions are equivalent:
           ip == 0xFE80000000000000020C29FFFE5409EF
           ip == 0xfe80000000000000020c29fffe5409ef
           ip == '0xFE80000000000000020C29FFFE5409EF'
           ip == '0xfe80000000000000020c29fffe5409ef'
           ip == 'FE80000000000000020C29FFFE5409EF'
           ip == 'fe80000000000000020c29fffe5409ef'
           ip == 'FE80:0000:0000:0000:020C:29FF:FE54:09EF'
           ip == 'fe80:0000:0000:0000:020c:29ff:fe54:09ef'
           ip == 'FE80::020C:29FF:FE54:09EF'
           ip == 'fe80::020c:29ff:fe54:09ef'
           ip == 'FE80::20C:29FF:FE54:9EF'
           ip == 'fe80::20c:29ff:fe54:9ef'
    """
    @staticmethod
    def _convert(ip):
        """Convert int/string into a persistent representation of an
           IPv6 address.
        """
        if ip != None:
            if type(ip) != str:
                # Convert IP address to a string
                ip = hex(ip)
            ip = ip.rstrip('Ll').replace('0x', '')
            ip = ip.lower()
            if ip.find(':') >= 0:
                # Given format contains ':', so remove ':' and expand all octets
                ol = ip.split(':')
                olen = 8 - len(ol)
                olist = []
                for item in ol:
                    if olen and item == '':
                        # Expand first occurrence '::'
                        item = '0000' * (olen+1)
                        olen = 0
                    elif item == '':
                        item = '0000'
                    else:
                        # Add leading zeroes
                        item = "%04x" % int(item, 16)
                    olist.append(item)
                ip = ''.join(olist)
            # Given format is a string of hex digits only
            if int(ip, 16) > 0xffffffffffffffffffffffffffffffff:
                raise ValueError("IPv6 addresses cannot be larger than 0xffffffffffffffffffffffffffffffff: %s" % ip)
            # Convert address into an array of 8 integers
            olist = [int(ip[i:i+4], 16) for i in range(0, len(ip), 4)]
            count, index = 0, 0
            zlist = {}
            for wd in olist:
                if wd == 0:
                    count += 1
                else:
                    if count > 1:
                        # Found largest set of consecutive zeroes
                        # save index of first zero
                        zlist[index - count] = count
                    count = 0
                index += 1
            if count > 1:
                zlist[8 - count] = count
            # Convert list of integers to list of hex strings
            olist = ["%x"%x for x in olist]
            for index in sorted(zlist, key=zlist.get, reverse=True):
                count = zlist[index]
                if count > 1:
                    # Compress largest set of consecutive zeroes by replacing
                    # all consecutive zeroes by an empty string
                    for i in range(count):
                        olist.pop(index)
                    olist.insert(index, "")
                    break
            # Process special cases where consecutive zeroes
            # are at the start or at the end
            if olist[0] == "":
                olist.insert(0, "")
            if olist[-1] == "":
                olist.append("")
            ip = ":".join(olist)
        return ip

    def __new__(cls, ip):
        """Create new instance by converting input int/string into a persistent
           representation of an IPv6 address.
        """
        return super(IPv6Addr, cls).__new__(cls, IPv6Addr._convert(ip))

    def __eq__(self, other):
        """Compare two IPv6 addresses and return True if both are equal."""
        return str(self) == self._convert(other)

    def __ne__(self, other):
        """Compare two IPv6 addresses and return False if both are equal."""
        return not self.__eq__(other)

if __name__ == '__main__':
    # Self test of module
    ip = IPv6Addr('fe80000000000000020c29fffe5409ef')
    ipstr = "%s" % ip
    iprpr = "%r" % ip
    ntests = 22

    tcount = 0
    if ip == 0xFE80000000000000020C29FFFE5409EF:
        tcount += 1
    if ip == 0xfe80000000000000020c29fffe5409ef:
        tcount += 1
    if ip == '0xFE80000000000000020C29FFFE5409EF':
        tcount += 1
    if ip == '0xfe80000000000000020c29fffe5409ef':
        tcount += 1
    if ip == 'FE80000000000000020C29FFFE5409EF':
        tcount += 1
    if ip == 'fe80000000000000020c29fffe5409ef':
        tcount += 1
    if ip == 'FE80:0000:0000:0000:020C:29FF:FE54:09EF':
        tcount += 1
    if ip == 'fe80:0000:0000:0000:020c:29ff:fe54:09ef':
        tcount += 1
    if ip == 'FE80::020C:29FF:FE54:09EF':
        tcount += 1
    if ip == 'fe80::020c:29ff:fe54:09ef':
        tcount += 1
    if ip == 'FE80::20C:29FF:FE54:9EF':
        tcount += 1
    if ip == 'fe80::20c:29ff:fe54:9ef':
        tcount += 1
    if ipstr == 'fe80::20c:29ff:fe54:9ef':
        tcount += 1
    if iprpr == "'fe80::20c:29ff:fe54:9ef'":
        tcount += 1

    ip = IPv6Addr(0xffffffffffffffffffffffffffffffff)
    if ip == 'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff':
        tcount += 1

    try:
        ip = IPv6Addr(0xffffffffffffffffffffffffffffffff + 1)
    except ValueError:
        tcount += 1

    if IPv6Addr("200104f800000002000000000000000d") == "2001:4f8:0:2::d":
        tcount += 1
    if IPv6Addr("200104f800000000000200000000000d") == "2001:4f8::2:0:0:d":
        tcount += 1
    if IPv6Addr("0:0:0:0:0:0:0:1") == "::1":
        tcount += 1
    if IPv6Addr("0:0:0:0:0:0:0:0") == "::":
        tcount += 1
    if IPv6Addr("1:0:0:0:0:0:0:0") == "1::":
        tcount += 1
    if IPv6Addr("1:0:0:2:0:0:0:0") == "1:0:0:2::":
        tcount += 1

    if tcount == ntests:
        print "All tests passed!"
        exit(0)
    else:
        print "%d tests failed" % (ntests-tcount)
        exit(1)
