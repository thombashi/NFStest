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
Remote procedure module

Provides a set of tools for executing a wide range commands, statements,
expressions or functions on a remote host by running a server process
on the remote host serving requests without disconnecting. This allows
for a sequence of operations to be done remotely and not losing state.
A file could be opened remotely, do some other things and then write
to the same opened file without opening the file again.

The remote server can be executed as a different user by using the sudo
option and sending seteuid. The server can be executed locally as well
using fork when running as the same user or using the shell when the
sudo option is used.

In order to use this module the user id must be able to 'ssh' to the
remote host without the need for a password.
"""
import os
import time
import types
import inspect
import nfstest_config as c
from baseobj import BaseObj
from subprocess import Popen, PIPE
from multiprocessing.connection import Client, Listener

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2013 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

# Constants
PORT = 9900

# Imports needed for RemoteServer class
IMPORTS = """
import time
import types
from multiprocessing.connection import Listener
"""

class RemoteServer:
    def __init__(self, port, logfile=None):
        """Remote procedure server"""
        self.port     = port
        self.logfile  = logfile
        self.fd       = None
        self.conn     = None
        self.listener = None

    def __del__(self):
        """Destructor"""
        if self.fd is not None:
            self.fd.close()
        if self.listener is not None:
            self.listener.close()

    def log(self, msg):
        """Write message to log file"""
        if self.fd is None:
            return
        curtime = time.time()
        msec = "%06d" % (1000000 * (curtime - int(curtime)))
        tstamp = time.strftime("%H:%M:%S.", time.localtime(curtime)) + msec
        self.fd.write(tstamp + " - " + msg + "\n")
        self.fd.flush()

    def start(self):
        if self.logfile is not None:
            self.fd = open(self.logfile, "w", 0)
        self.listener = Listener(("", self.port))
        self.conn = self.listener.accept()
        self.log("Connection accepted\n")

        while True:
            msg = self.conn.recv()
            self.log("RECEIVED: %r" % msg)
            if type(msg) is dict:
                try:
                    # Get command
                    cmd  = msg.get("cmd")
                    # Get function/statement/expression and positional arguments
                    kwts = msg.get("kwts", ())
                    fstr = kwts[0]
                    kwts = kwts[1:]
                    # Get named arguments
                    kwds = msg.get("kwds", {})

                    if cmd == "run":
                        # Find if function is defined
                        if type(fstr) in [types.FunctionType, types.BuiltinFunctionType, types.MethodType]:
                            # This is a function
                            func = fstr
                        else:
                            # Find symbol in locals then in globals
                            func = locals().get(fstr)
                            if func is None:
                                func = globals().get(fstr)
                        if func is None:
                            raise Exception("function not found")
                        # Run function with all its arguments
                        out = func(*kwts, **kwds)
                        self.log("RESULT: " + repr(out))
                        self.conn.send(out)
                    elif cmd == "eval":
                        # Evaluate expression
                        out = eval(fstr)
                        self.log("RESULT: " + repr(out))
                        self.conn.send(out)
                    elif cmd == "exec":
                        # Execute statement
                        exec(fstr)
                        self.log("EXEC done")
                        self.conn.send(None)
                    else:
                        emsg = "Unknown procedure"
                        self.log("ERROR: %s" % emsg)
                        self.conn.send(Exception(emsg))
                except Exception as e:
                    self.log("ERROR: %r" % e)
                    self.conn.send(e)
            if msg == "close":
                # Request to close the connection,
                # exit the loop and terminate the server
                self.conn.close()
                break

class Rexec(BaseObj):
    """Rexec object

       Rexec() -> New remote procedure object

       Arguments:
           servername:
               Name or IP address of remote server
           logfile:
               Name of logfile to create on remote server
           sudo:
               Run remote server as root

       Usage:
           from nfstest.rexec import Rexec

           # Function to be defined at remote host
           def add_one(n):
               return n + 1

           # Function to be defined at remote host
           def get_time(delay=0):
               time.sleep(delay)
               return time.time()

           # Create remote procedure object
           x = Rexec("192.168.0.85")

           # Define function at remote host
           x.rcode(add_one)

           # Evaluate the expression calling add_one()
           out = x.reval("add_one(67)")

           # Run the function with the given argument
           out = x.run("add_one", 7)

           # Run built-in functions
           import time
           out = x.run(time.time)

           # Import libraries and symbols
           x.rimport("time", ["sleep"])
           x.run("sleep", 2)

           # Define function at remote host -- since function uses the
           # time module, this module must be first imported
           x.rimport("time")
           x.rcode(get_time)

           # Evaluate the expression calling get_time()
           out = x.reval("get_time()")

           # Run the function with the given argument
           out = x.run("get_time", 10)

           # Open file on remote host
           fd = x.run(os.open, "/tmp/testfile", os.O_WRONLY|os.O_CREAT|os.O_TRUNC)
           count = x.run(os.write, fd, "hello there\n")
           x.run(os.close, fd)

           # Use of positional arguments
           out = x.run("get_time", 2)

           # Use of named arguments
           out = x.run("get_time", delay=2)

           # Use of NOWAIT option for long running functions so other things
           # can be done while waiting
           x.run("get_time", 2, NOWAIT=True)
           while True:
               # Poll every 0.1 secs to see if function has finished
               if x.poll(0.1):
                   # Get results
                   out = x.results()
                   break

           # Create remote procedure object as a different user
           # First, run the remote server as root
           x = Rexec("192.168.0.85", sudo=True)
           # Then set the effective user id
           x.run(os.seteuid, 1000)
    """
    def __init__(self, servername=None, logfile=None, sudo=False, sync_timeout=0.1):
        """Constructor

           Initialize object's private data.

           servername:
               Host name or IP address of host where remote server will run
               [Default: None (run locally)]
           logfile:
               Pathname of log file to be created on remote host
               [Default: None]
           sudo:
               Run remote procedure server as root
               [Default: False]
           sync_timeout:
               Timeout used for synchronizing the connection stream
               [Default: 0.1]
        """
        global PORT
        self.pid     = None
        self.conn    = None
        self.process = None
        self.remote  = False
        self.servername   = servername
        self.logfile      = logfile
        self.sudo         = sudo
        self.sync_timeout = sync_timeout
        if os.getuid() == 0:
            # Already running as root
            self.sudo = True
            sudo = False

        if not sudo and servername in [None, "", "localhost", "127.0.0.1"]:
            # Start remote server locally via fork when sudo is not set
            servername = ""
            self.pid = os.fork()
            if self.pid == 0:
                # This is the child process
                RemoteServer(PORT, self.logfile).start()
                os._exit(0)
        else:
            # Start server on remote host or locally if sudo is set
            server_code  = IMPORTS
            server_code += "".join(inspect.getsourcelines(RemoteServer)[0])
            server_code += "RemoteServer(%d, %r).start()\n" % (PORT, self.logfile)
            # Execute minimal python script to execute the source code
            # given in standard input
            pysrc = "import sys; exec(sys.stdin.read(%d))" % len(server_code)
            cmdlist = ["python", "-c", repr(pysrc)]

            if sudo:
                cmdlist.insert(0, "sudo")

            if servername not in [None, "", "localhost", "127.0.0.1"]:
                # Run remote process via ssh
                cmdlist = ["ssh", servername] + cmdlist
                self.process = Popen(cmdlist, shell=False, stdin=PIPE)
                self.remote = True
            else:
                # Run local process via the shell
                servername = ""
                self.process = Popen(" ".join(cmdlist), shell=True, stdin=PIPE)

            # Send the server code to be executed via standard input
            self.process.stdin.write(server_code)

        # Connect to remote server
        address = (servername, PORT)
        self.conn = Client(address)
        PORT += 1

    def __del__(self):
        """Destructor"""
        self.close()

    def close(self):
        """Close connection to remote server"""
        if self.conn:
            # Send command to exit main loop
            self.conn.send("close")
            self.conn.close()
            self.conn = None
        # Wait for remote server to finish
        if self.pid:
            os.waitpid(self.pid, 0)
            self.pid = None
        elif self.process:
            self.process.wait()
            self.process = None

    def _send_cmd(self, cmd, *kwts, **kwds):
        """Internal method to send commands to remote server"""
        nowait = kwds.pop("NOWAIT", False)
        self.conn.send({"cmd": cmd, "kwts": kwts, "kwds": kwds})
        if nowait:
            # NOWAIT option is specified, so return immediately
            # Use poll() method to check if any data is available
            # Use results() method to get pending results from function
            return
        return self.results()

    def wait(self, objlist=None, timeout=0):
        """Return a list of Rexec objects where data is available to be read

           objlist:
               List of Rexec objects to poll, if not given use current object
           timeout:
               Maximum time in seconds to block, if timeout is None then
               an infinite timeout is used
        """
        ret = []
        if objlist is None:
            # Use current object as default
            objlist = [self]

        for obj in objlist:
            if obj.poll(timeout):
                ret.append(obj)
            # Just check all other objects if they are ready now
            timeout = 0
        return ret if len(ret) else None

    def poll(self, timeout=0):
        """Return whether there is any data available to be read

           timeout:
               Maximum time in seconds to block, if timeout is None then
               an infinite timeout is used
        """
        return self.conn.poll(timeout)

    def results(self):
        """Return pending results"""
        while True:
            out = self.conn.recv()
            if isinstance(out, Exception):
                raise out
            elif out is None and self.poll(self.sync_timeout):
                # Try to re-sync when recv() returns None and there is
                # still data in the buffer
                continue
            return out

    def rexec(self, expr):
        """Execute statement on remote server"""
        return self._send_cmd("exec", expr)

    def reval(self, expr):
        """Evaluate expression on remote server"""
        return self._send_cmd("eval", expr)

    def run(self, *kwts, **kwds):
        """Run function on remote server

           The first positional argument is the function to be executed.
           All other positional arguments and any named arguments are treated
           as arguments to the function
        """
        return self._send_cmd("run", *kwts, **kwds)

    def rcode(self, code):
        """Define function on remote server"""
        codesrc = "".join(inspect.getsourcelines(code)[0])
        self.rexec(codesrc)

    def rimport(self, module, symbols=[]):
        """Import module on remote server

           module:
               Module to import in the remote server
           symbols:
               If given, import only these symbols from the module
        """
        # Import module
        if len(symbols) == 0:
            self.rexec("import %s" % module)
            symbols = [module]
        else:
            self.rexec("from %s import %s" % (module, ",".join(symbols)))
        # Make all symbols global
        for item in symbols:
            self.rexec("globals()['%s']=locals()['%s']" % (item, item))
