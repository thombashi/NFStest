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
String Formatter object

Object used to format base objects into strings. It extends the functionality
of the string Formatter object to include new modifiers for different objects.
Some of these new modifiers include conversion of strings into a sequence
of hex characters, conversion of strings to their corresponding CRC32 or
CRC16 representation.
"""
import re
import time
import binascii
import nfstest_config as c
from string import Formatter

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.5"

# Display variables
CRC16 = True
CRC32 = True

# Maximum integer map
_max_map = {
    "max32":{
                0x7fffffff:  "max32",
               -0x80000000: "-max32",
    },
    "umax32":{
                0xffffffff: "umax32",
    },
    "max64":{
        0x7fffffffffffffff:  "max64",
       -0x8000000000000000: "-max64",
    },
    "umax64":{
        0xffffffffffffffff: "umax64",
    },
}

# Unit modifiers
UNIT_NAME = 0
UNIT_BYTE = "B"
UNIT_SEP  = ""

# Short name unit suffixes
UNIT_SUFFIXES = ["","K","M","G","T","P","E","Z"]
# Long name unit suffixes
UNIT_SUFFIX_NAME = ["", "Kilo", "Mega", "Giga", "Tera", "Peta", "Exa", "Zetta"]

def str_units(value, precision=2):
    """Convert number to a string value with units

       value:
           Number to convert
       precision:
           Return string value with the following floating point
           precision. By default no trailing zeros are returned
           but if the precision is given as a negative number
           the precision is enforced [default: 2]
    """
    # Get index to unit name
    idx = 0
    while value >= 1024:
        idx += 1
        value = value/1024.0

    if precision > 0 and round(value,precision) == int(value):
        # Remove trailing zeros when value is exact or within precision limits
        precision = 0
    if UNIT_NAME:
        suffix = UNIT_SUFFIX_NAME[idx]
    else:
        suffix = UNIT_SUFFIXES[idx]
    if len(suffix):
        suffix += UNIT_BYTE
    return "%.*f%s%s" % (abs(precision), value, UNIT_SEP, suffix)

def int_units(value):
    """Convert string value with units to an integer

       value:
           String to convert

       Examples:
           out = num_units("1MB") # out = 1048576
    """
    if type(value) == str:
        v, m = re.search(r"([-\+\.\d]+)\s*(\w?)", value).groups()
        value = int(float(v) * (1<<(10*UNIT_SUFFIXES.index(m.upper()))))
    return value

def str_time(value):
    """Convert the number of seconds to a string with a format of "[h:]mm:ss"

       value:
           Time value to convert (in seconds)

       Examples:
           out = str_time(123.0) # out = "02:03"
           out = str_time(12345) # out = "3:25:45"
    """
    ret = ""
    value = int(value)
    hh = value/3600
    mm = (value-3600*hh)/60
    ss = value%60
    if hh > 0:
        ret += "%d:" % hh
    return ret + "%02d:%02d" % (mm, ss)

def crc32(value):
    """Convert string to its crc32 representation"""
    return binascii.crc32(value) & 0xffffffff

def crc16(value):
    """Convert string to its crc16 representation"""
    return binascii.crc_hqx(value, 0xa5a5) & 0xffff

def hexstr(value):
    """Convert string to its hex representation"""
    return "0x" + value.encode("hex")

class FormatStr(Formatter):
    """String Formatter object

       FormatStr() -> New string formatter object

       Usage:
           from formatstr import FormatStr

           x = FormatStr()

           out = x.format(fmt_spec, *args, **kwargs)
           out = x.vformat(fmt_spec, args, kwargs)

           Arguments should be surrounded by curly braces {}, anything that is
           not contained in curly braces is considered literal text which is
           copied unchanged to the output.
           Positional arguments to be used in the format spec are specified
           by their index: {0}, {1}, etc.
           Named arguments to be used in the format spec are specified by
           their name: {name1}, {name2}, etc.

           Modifiers are specified after the positional index or name preceded
           by a ":", "{0:#x}" -- display first positional argument in hex

       Examples:
           # Format string using positional arguments
           out = x.format("{0} -> {1}", a, b)

           # Format string using named arguments
           out = x.format("{key}: {value}", key="id", value=32)

           # Format string using both positional and named arguments
           out = x.format("{key}: {value}, {0}, {1}", a, b, key="id", value=32)

           # Use vformat() method instead when positional arguments are given
           # as a list and named arguments are given as a dictionary
           # The following examples show the same as above
           pos_args = [a, b]
           named_args = {"key":"id", "value":32}
           out = x.vformat("{0} -> {1}", pos_args)
           out = x.vformat("{key}: {value}", named_args)
           out = x.vformat("{key}: {value}, {0}, {1}", pos_args, named_args)

           # Display string in hex
           out = x.format("{0:x}", "hello")  # out = "68656c6c6f"

           # Display string in hex with leading 0x
           out = x.format("{0:#x}", "hello") # out = "0x68656c6c6f"

           # Display string in crc32
           out = x.format("{0:crc32}", "hello") # out = "0x3610a686"

           # Display string in crc16
           out = x.format("{0:crc16}", "hello") # out = "0x9c62"

           # Substring using "@" format modifier
           # Format {0:@sindex[,eindex]} is like value[sindex:eindex]
           #   {0:@3} is like value[3:]
           #   {0:@3,5} is like value[3:5]
           #   {0:.5} is like value[:5]
           out = x.format("{0:@3}", "hello") # out = "lo"
           out = x.format("{0:.2}", "hello") # out = "he"

           # Conditionally display the first format if argument is not None,
           # else the second format is displayed
           # Format: {0:?format1:format2}
           out = x.format("{0:?tuple({0}, {1})}", 1, 2)    # out = "tuple(1, 2)"
           out = x.format("{0:?tuple({0}, {1})}", None, 2) # out = ""
           # Using 'else' format (including the escaping of else character):
           out = x.format("{0:?sid\:{0}:NONE}", 5)    # out = "sid:5"
           out = x.format("{0:?sid\:{0}:NONE}", None) # out = "NONE"

           # Nested formatting for strings, where processing is done in
           # reversed order -- process the last format first
           # Format: {0:fmtN:...:fmt2:fmt1}
           #   Display substring of 4 bytes as hex (substring then hex)
           out = x.format("{0:#x:.4}", "hello") # out = "0x68656c6c"
           #   Display first 4 bytes of string in hex (hex then substring)
           out = x.format("{0:.4:#x}", "hello") # out = "0x68"

           # Integer extension to display umax name instead of the value
           # Format: {0:max32|umax32|max64|umax64}
           # Output: if value matches the largest number in format given,
           #         the max name is displayed, else the value is displayed
           out = x.format("{0:max32}", 0x7fffffff) # out = "max32"
           out = x.format("{0:max32}", 35)         # out = "35"

           # Number extension to display the value with units
           # Format: {0:units[.precision]}
           # Output: display value as a string with units, by default
           #         precision=2 and all trailing zeros are removed.
           #         To force the precision use a negative number.
           out = x.format("{0:units}", 1024)    # out = "1KB"
           out = x.format("{0:units.4}", 2000)  # out = "1.9531KB"
           out = x.format("{0:units.-2}", 1024) # out = "1.00KB"

           # Date extension for int, long or float
           # Format: {0:date[:datefmt]}
           #         The spec given by datefmt is converted using strftime()
           #         The conversion spec "%q" is used to display microseconds
           # Output: display value as a date
           stime = 1416846041.521868
           out = x.format("{0:date}", stime) # out = "Mon Nov 24 09:20:41 2014"
           out = x.format("{0:date:%Y-%m-%d}", stime) # out = "2014-11-24"

           # List format specification
           # Format: {0[[:listfmt]:itemfmt]}
           #   If one format spec, it is applied to each item in the list
           #   If two format specs, the first is the item separator and
           #   the second is the spec applied to each item in the list
           alist = [1, 2, 3, 0xffffffff]
           out = x.format("{0:umax32}", alist)    # out = "[1, 2, 3, umax32]"
           out = x.format("{0:--:umax32}", alist) # out = "1--2--3--umax32"
    """
    def format_field(self, value, format_spec):
        """Override original method to include modifier extensions"""
        if len(format_spec) > 1 and format_spec[0] == "?":
            # Conditional directive
            # Format {0:?format1:format2}
            data = re.split(r"(?<!\\):", format_spec)
            if value is not None:
                return data[0][1:].replace("\\:", ":")
            elif len(data) > 1:
                return data[1].replace("\\:", ":")
        if value is None:
            # No value is given
            return ""
        # Process format spec
        match = re.search(r"([#@]?)(\d*)(.*)", format_spec)
        xmod, num, fmt = match.groups()
        if isinstance(value, int) and type(value) != int:
            # This is an object derived from int, convert it to string
            value = str(value)
        if isinstance(value, str):
            fmtlist = (xmod+fmt).split(":")
            if len(fmtlist) > 1:
                # Nested format, process in reversed order
                for sfmt in reversed(fmtlist):
                    value = self.format_field(value, sfmt)
                return value
            if fmt == "x":
                # Display string in hex
                xprefix = ""
                if xmod == "#":
                    xprefix = "0x"
                return xprefix + value.encode("hex")
            elif fmt == "crc32":
                if CRC32:
                    return "{0:#010x}".format(crc32(value))
                else:
                    return str(value)
            elif fmt == "crc16":
                if CRC16:
                    return "{0:#06x}".format(crc16(value))
                else:
                    return str(value)
            elif xmod == "@":
                # Format {0:@starindex[,endindex]} is like value[starindex:endindex]
                #   {0:@3} is like value[3:]
                #   {0:@3,5} is like value[3:5]
                #   {0:.5} is like value[:5]
                end = 0
                if len(fmt) > 2 and fmt[0] == ",":
                    end = int(fmt[1:])
                    return value[int(num):end]
                else:
                    return value[int(num):]
        elif isinstance(value, list):
            # Format: {0[[:listfmt]:itemfmt]}
            fmts = format_spec.split(":", 1)
            ifmt = "{0:" + fmts[-1] + "}"
            vlist = [self.format(ifmt, x) for x in value]
            if len(fmts) == 2:
                # Two format specs, use the first one for the list itself
                # and the second spec is for each item in the list
                return fmts[0].join(vlist)

            # Only one format spec is given, display list with format spec
            # applied to each item in the list
            return "[" + ", ".join(vlist) + "]"
        elif isinstance(value, int) or isinstance(value, long) or isinstance(value, float):
            if _max_map.get(fmt):
                # Format: {0:max32|umax32|max64|umax64}
                # Output: if value matches the largest number in format given,
                #         the max name is displayed, else the value is displayed
                #         {0:max32}: value:0x7fffffff then "max32" is displayed
                #         {0:max32}: value:35 then 35 is displayed
                return _max_map[fmt].get(value, str(value))
            elif fmt[:5] == "units":
                # Format: {0:units[.precision]}
                # Output: convert value to a string with units
                #         (default precision is 2)
                #         {0:units}: value:1024 then "1KB" is displayed
                #         {0:units}: value:2000 then "1.95KB is displayed
                fmts = fmt.split(".", 1)
                uargs = {}
                if len(fmts) == 2:
                    uargs["precision"] = int(fmts[1])
                return str_units(value, **uargs)
            elif fmt[:4] == "date":
                # Format: {0:date[:datefmt]}
                # Output: display value as a date
                #         value: 1416846041.521868
                #         display: 'Mon Nov 24 09:20:41 2014'
                dfmt = "%c" # Default date spec when datefmt is not given
                fmts = fmt.split(":", 1)
                if len(fmts) == 2:
                    dfmt = fmts[1]
                    if dfmt.find("%q"):
                        # Replace all instances of %q with the microseconds
                        usec = "%06d" % (1000000 * (value - int(value)))
                        dfmt = dfmt.replace("%q", usec)
                return time.strftime(dfmt, time.localtime(value))
        return format(value, format_spec)

    def get_value(self, key, args, kwargs):
        """Override original method to return "" when the positional argument
           or named argument does not exist:
             x.format("0:{0}, 1:{1}, arg1:{arg1}, arg2:{arg2}", a, arg1=11)
             the {1} will return "" since there is only one positional argument
             the {arg2} will return "" since arg2 is not a named argument
        """
        try:
            return super(FormatStr, self).get_value(key, args, kwargs)
        except (IndexError, KeyError):
            return ""
