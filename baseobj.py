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
Base object

Base class so objects will inherit the methods providing the string
representation of the object and methods to change the verbosity of such
string representation. It also includes a simple debug printing and logging
mechanism including methods to change the debug verbosity level and methods
to add debug levels.
"""
import re
import time
import nfstest_config as c
from pprint import pformat
from formatstr import FormatStr

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

# Module variables
_dindent = ""
_sindent = "    "
_dlevel = 0
_rlevel = 1
_dcount = 0
_strsize = 0
_logfh = None
_tstamp = True
_tstampfmt = "{0:date:%H:%M:%S.%q - }"

# Simple verbose level names
_debug_map = {
    'none':  0,
    'info':  1,    # Display info only
    'debug': 0xFF, # Display info and all debug messages 0x02-0x80
    'all':   0xFFFFFFFF, # Display all messages
}
# Debug display prefixes
_debug_prefix = {
    0x001: 'INFO: ',
}

def _init_debug():
    """Define all debug flags"""
    for i in xrange(7):
        dbg = 'dbg%d' % (i+1)
        _debug_map[dbg] = (2 << i)
        _debug_prefix[(2 << i)] = dbg.upper() + ': '
_init_debug()

# Instantiate FormatStr object
fstrobj = FormatStr()

class BaseObj(object):
    """Base class so objects will inherit the methods providing the string
       representation of the object and a simple debug printing and logging
       mechanism.

       Usage:
           from baseobj import BaseObj

           # Named arguments
           x = BaseObj(a=1, b=2)

           # Dictionary argument
           x = BaseObj({'a':1, 'b':2})

           # Tuple arguments: first for keys and second for the values
           x = BaseObj(['a', 'b'], [1, 2])

           # All of the above will create an object having two attributes:
           x.a = 1 and x.b = 2

           # Add attribute name, this will be the only attribute to be displayed
           x.set_attrlist("a")

           # Add list of attribute names to be displayed in that order
           x.set_attrlist(["a", "b"])

           # Set attribute with ordered display rights
           x.set_attr("a", 1)
           # This is the same as
           setattr(x, "a", 1) or x.a = 1
           x.set_attrlist("a")

           # Set attribute with switch duplicate
           # The following creates an extra attribute "switch" with
           # the same value as attribute "a":
           #   x.a == x.switch
           #   x.a is x.switch
           x.set_attr("a", 1, switch=True)

           # Make the current object flat by allowing all the attributes
           # for the new attribute to be accessed directly by the current
           # object so the following is True:
           #   x.d == x.c.d
           x.set_attr("c", BaseObj(d=11, e=22), switch=True)

           # Set the comparison attribute so x == x.a is True
           x.set_eqattr("a")

           # Set verbose level of object's string representation
           x.debug_repr(level)

           # Set string format for verbose level 1
           x.set_strfmt(1, "arg1:{0}")
           # In the above example the first positional argument is "a"
           # so the str(x) gives "arg1:1"

           # Set attribute shared by all instances
           # If a global or shared attribute is set on one instance,
           # all other instances will have access to it:
           #   y = BaseObj(d=2, e=3)
           # then the following is true
           #   x.g == y.g
           #   x.g is y.g
           x.set_global("g", 5)

           # Set level mask to display all debug messages matching mask
           x.debug_level(0xFF)

           # Add a debug mapping for mask 0x100
           x.debug_map(0x100, 'opts', "OPTS: ")

           # Set global indentation to 4 spaces for dprint
           x.dindent(4)

           # Set global indentation to 4 spaces for displaying objects
           x.sindent(4)

           # Set global truncation to 64 for displaying string objects
           x.strsize(64)

           # Do not display timestamp for dprint messages
           x.tstamp(enable=False)

           # Change timestamp format to include the date
           x.tstamp(fmt="{0:date:%Y-%m-%d %H:%M:%S.%q} ")

           # Get timestamp if enabled, else return an empty string
           out = x.timestamp()

           # Open log file
           x.open_log(logfile)

           # Close log file
           x.close_log()

           # Write data to log file
           x.write_log(data)

           # Format the given arguments
           out = x.format("{0:x} - {1}", 1, "hello")

           # Format the object attributes set by set_attrlist()
           out = x.format("{0:x} - {1}")

           # Print debug message only if OPTS bitmap matches the current
           # debug level mask
           x.dprint("OPTS", "This is an OPTS debug message")
    """
    # Class attributes
    _attrlist = None # List of attributes to display in order
    _eqattr   = None # Comparison attribute
    _attrs    = None # Dictionary where the key becomes an attribute which is
                     # a reference to another attribute given by its value
    _fattrs   = None # Make the object attributes of each of the attributes
                     # listed part of the attributes of the current object
    _strfmt1  = None # String format for verbose level 1
    _strfmt2  = None # String format for verbose level 2
    _globals  = {}   # Attributes share by all instances

    def __init__(self, *kwts, **kwds):
        """Constructor

           Initialize object's private data according to the arguments given.
           Arguments can be given as positional, named arguments or a
           combination of both.
        """
        keys = None
        for item in kwts:
            if type(item) == dict:
                self.__dict__.update(item)
            elif type(item) == list or type(item) == tuple:
                if keys is None:
                    keys = item
                else:
                    self.__dict__.update(zip(keys,item))
                    keys = None
        # Process named arguments: x = BaseObj(a=1, b=2)
        self.__dict__.update(kwds)

    def __getattr__(self, attr):
        """Return the attribute value for which the lookup has not found
           the attribute in the usual places. It checks the internal
           dictionary for any attribute references, it checks if this
           is a flat object and returns the appropriate attribute.
           And finally, if any of the attributes listed in _attrlist
           does not exist it returns None as if they exist but not
           defined
        """
        if self._globals.has_key(attr):
            # Shared attribute
            return self._globals[attr]
        if self._attrs is not None:
            # Check if attribute is a reference to another attribute
            name = self._attrs.get(attr)
            if name is not None:
                return getattr(self, name)
        if self._fattrs is not None:
            # Check if this is defined as a flat object so any attributes
            # of sub-objects pointed to by _fattrs are treated like
            # attributes of this object
            for item in self._fattrs:
                obj = getattr(self, item, None)
                if obj is not None and hasattr(obj, attr):
                    # Flat object: sub-object attributes as object attribute
                    return getattr(obj, attr)
        if self._attrlist is not None and attr in self._attrlist:
            # Make all attributes listed in _attrlist available even if they
            # haven't been defined
            return None
        raise AttributeError("'%s' object has no attribute '%s'" % (self.__class__.__name__, attr))

    def __eq__(self, other):
        """Comparison method: this object is treated like the attribute
           defined by set_eqattr()
        """
        if self._eqattr is None:
            # Compare object
            return id(other) == id(self)
        else:
            # Compare defined attribute
            return other == getattr(self, self._eqattr)

    def __ne__(self, other):
        """Comparison method: this object is treated like the attribute
           defined by set_eqattr()
        """
        return not self.__eq__(other)

    def __repr__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned, else
           the representation of the object includes all object attributes
           and their values with proper indentation.
        """
        return self._str_repr(True)

    def __str__(self):
        """Informal string representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned, else
           the representation of the object includes all object attributes
           and their values.
        """
        return self._str_repr()

    def _str_repr(self, isrepr=False):
        """String representation of object"""
        global _rlevel
        if _rlevel == 0:
            # Return generic object representation
            if isrepr:
                return super(BaseObj, self).__repr__()
            else:
                return super(BaseObj, self).__str__()
        elif not isrepr:
            if _rlevel == 1 and self._strfmt1 is not None:
                return self.format(self._strfmt1)
            elif _rlevel == 2 and self._strfmt2 is not None:
                return self.format(self._strfmt2)

        # Representation of object with proper indentation
        out = []
        if self._attrlist is None:
            attrlist = sorted(self.__dict__.keys())
        else:
            attrlist = self._attrlist
        for key in attrlist:
            if key[0] != '_':
                val = getattr(self, key, None)
                if val != None:
                    if isrepr:
                        value = pformat(val, indent=0)
                        if (isinstance(val, list) or isinstance(val, dict)) and value.find("\n") > 0:
                            # If list or dictionary have more than one line as
                            # returned from pformat, add an extra new line
                            # between opening and closing brackets and add
                            # another indentation to the body
                            value = (value[0] + "\n" + value[1:-1]).replace("\n", "\n"+_sindent) + "\n" + value[-1]
                        out.append("%s%s = %s,\n" % (_sindent, key, value.replace("\n", "\n"+_sindent)))
                    else:
                        out.append("%s=%s" % (key, self._str_value(val)))
        name = self.__class__.__name__
        if isrepr:
            joinstr = ""
            if len(out) > 0:
                out.insert(0, "\n")
        else:
            joinstr = ", "
        return "%s(%s)" % (name, joinstr.join(out))

    def _str_value(self, value):
        """Format value"""
        if isinstance(value, list) or isinstance(value, tuple):
            # Display list or tuple
            out = []
            for item in value:
                out.append(self._str_value(item))
            return '[' + ', '.join(out) + ']'
        elif isinstance(value, dict):
            # Display dictionary
            out = []
            for key,val in value.iteritems():
                out.append(str(key) + ": " + self._str_value(val))
            return '{' + ', '.join(out) + '}'
        elif type(value) == int or type(value) == long or type(value) == str:
            if _strsize > 0 and type(value) == str:
                return repr(value[:_strsize])
            return repr(value)
        else:
            return str(value)

    def set_attrlist(self, attr):
        """Add list of attribute names in object to display by str() or repr()

           attr:
               Name or list of names to add to the list of attribute names
               to display
        """
        if self._attrlist is None:
            self._attrlist = []
        if isinstance(attr, list):
            # Add given list of items
            self._attrlist += attr
        else:
            # Add a single item
            self._attrlist.append(attr)

    def set_attr(self, name, value, switch=False):
        """Add name/value as an object attribute and add the name to the
           list of attributes to display

           name:
               Attribute name
           value:
               Attribute value
        """
        setattr(self, name, value)
        self.set_attrlist(name)
        if switch:
            if self._attrs is None:
                self._attrs = {}
            # Make a reference to name
            self._attrs["switch"] = name
            if self._fattrs is None:
                self._fattrs = []
            # Make it a flat object
            self._fattrs.append(name)

    def set_eqattr(self, attr):
        """Set the comparison attribute

           attr:
               Attribute to use for object comparison

           Examples:
               x = BaseObj(a=1, b=2)
               x.set_eqattr("a")
               x == 1 will return True, the same as x.a == 1
        """
        self._eqattr = attr

    def set_strfmt(self, level, format):
        """Save format for given display level

           level:
               Display level given as a first argument
           format:
               String format for given display level, given as a second argument
        """
        if level == 1:
            self._strfmt1 = format
        elif level == 2:
            self._strfmt2 = format
        else:
            raise Exception("Invalid string format level [%d]" % level)

    def set_global(self, name, value):
        """Set global variable."""
        self._globals[name] = value

    @staticmethod
    def debug_repr(level=None):
        """Return or set verbose level of object's string representation.
           When setting the verbose level, return the verbose level before
           setting it.

           level:
               Level of verbosity to set

           Examples:
               # Set verbose level to its minimal object representation
               x.debug_repr(0)

               # Object representation is a bit more verbose
               x.debug_repr(1)

               # Object representation is a lot more verbose
               x.debug_repr(2)
        """
        global _rlevel
        ret = _rlevel
        if level is not None:
            _rlevel = level
        return ret

    def debug_level(self, level=0):
        """Set debug level mask.

           level:
               Level to set. This could be a number or a string expression
               of names defined by debug_map()

           Examples:
               # Set level
               x.debug_level(0xFF)

               # Set level using expression
               x.debug_level('all')
               x.debug_level('debug ^ 1')
        """
        global _dlevel
        if type(level) == str:
            # Convert named verbose levels to a number
            # -- Get a list of all named verbose levels
            for item in sorted(set(re.split('\W+', level))):
                if len(item) > 0:
                    if item in _debug_map:
                        # Replace all occurrences of named verbose level
                        # to its corresponding numeric value
                        level = re.sub(r'\b' + item + r'\b', hex(_debug_map[item]), level)
                    else:
                        try:
                            # Find out if verbose is a number
                            # (decimal, hex, octal, ...)
                            tmp = int(item, 0)
                        except:
                            raise Exception("Unknown debug level [%s]" % item)
            # Evaluate the whole expression
            _dlevel = eval(level)
        else:
            # Already a number
            _dlevel = level
        return _dlevel

    @staticmethod
    def debug_map(bitmap, name='', disp=''):
        """Add a debug mapping.

           Generic debug levels map
             <bitmap>  <name>  <disp prefix>
              0x000    'none'
              0x001    'info'  'INFO: ' # Display info messages only
              0x0FF    'debug' 'DBG:  ' # Display info and all debug messages (0x02-0x80)
             >0x100    user defined verbose levels
        """
        if name:
            _debug_map[name] = bitmap
        if disp:
            _debug_prefix[bitmap] = disp

    @staticmethod
    def dindent(indent=None):
        """Set global dprint indentation."""
        global _dindent
        if indent is not None:
            _dindent = " " * indent
        return _dindent

    @staticmethod
    def sindent(indent=None):
        """Set global object indentation."""
        global _sindent
        if indent is not None:
            _sindent = " " * indent
        return _sindent

    @staticmethod
    def strsize(size):
        """Set global string truncation."""
        global _strsize
        _strsize = size

    @staticmethod
    def tstamp(enable=None, fmt=None):
        """Enable/disable timestamps on dprint messages and/or
           set the default format for timestamps

           enable:
               Boolean to enable/disable timestamps
           fmt:
               Set timestamp format
        """
        global _tstamp,_tstampfmt
        if enable is not None:
            _tstamp = enable
        if fmt is not None:
            _tstampfmt = fmt

    @staticmethod
    def timestamp(fmt=None):
        """Return the timestamp if it is enabled.

           fmt:
               Timestamp format, default is given by the format
               set by tstamp()
        """
        if _tstamp:
            if fmt is None:
                fmt = _tstampfmt
            return fstrobj.format(fmt, time.time())
        return ""

    def open_log(self, logfile):
        """Open log file."""
        global _logfh
        self.close_log()
        _logfh = open(logfile, "w")

    def close_log(self):
        """Close log file."""
        global _logfh
        if _logfh != None:
            _logfh.close()
            _logfh = None

    @staticmethod
    def write_log(data):
        """Write data to log file."""
        if _logfh != None:
            _logfh.write(data + "\n")

    @staticmethod
    def flush_log():
        """Flush data to log file."""
        if _logfh != None:
            _logfh.flush()

    @staticmethod
    def dprint_count():
        """Return the number of dprint messages actually displayed."""
        return _dcount

    def format(self, fmt, *kwts, **kwds):
        """Format the arguments and return the string using the format given.
           If no arguments are given either positional or named then object
           attributes set by set_attrlist() are used as positional arguments
           and all object attributes are used as named arguments

           fmt:
               String format to use for the arguments, where {0}, {1}, etc.
               are used for positional arguments and {name1}, {name2}, etc.
               are used for named arguments given after fmt.
        """
        if len(kwts) == 0 and len(kwds) == 0:
            # Use object attributes, both positional using _attrlist and
            # named arguments using object's own dictionary
            if self._attrlist is not None:
                kwts = (getattr(self, attr) for attr in self._attrlist)
            kwds = self.__dict__.copy()
            if self._globals:
                # Include the shared attributes as named attributes
                kwds.update(self._globals)
        return fstrobj.format(fmt, *kwts, **kwds)

    def dprint(self, level, msg, indent=0):
        """Print debug message if level is allowed by the verbose level
           given in debug_level().
        """
        ret = ''
        if level is None:
            return
        if type(level) == str:
            level = _debug_map[level.lower()]
        if level & _dlevel:
            # Add display prefix only if msg is not an empty string
            if len(msg):
                # Find the right display prefix
                prefix = _dindent
                for bitmap in sorted(_debug_prefix):
                    if level & bitmap:
                        prefix += _debug_prefix[bitmap]
                        break
                # Add display prefix to the message
                ret = prefix + self.timestamp()
                if indent > 0:
                    ret += " " * indent
                ret += msg
                indent += len(prefix)
            if indent > 0:
                sp = ' ' * indent
                ret = ret.replace("\n", "\n"+sp)
            print ret
            self.write_log(ret)
            global _dcount
            _dcount += 1
