"""
This module defines common test stuff

Copyright 2011 Red Hat, Inc.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
jpirko@redhat.com (Jiri Pirko)
"""

import re
import logging
import os
import signal
import time
from lnst.Common.NetTestCommand import NetTestCommandGeneric
from lnst.Common.LnstError import LnstError

class testLogger(logging.Logger):
    def __init__(self, name, level=logging.NOTSET):
        logging.Logger.__init__(self, name, level)

    def findCaller(self):
        """
        Find the stack frame of the caller so that we can note the source
        file name, line number and function name.
        """
        f = logging.currentframe()
        #On some versions of IronPython, currentframe() returns None if
        #IronPython isn't run with -X:Frames.
        if f is not None:
            f = f.f_back.f_back
        rv = "(unknown file)", 0, "(unknown function)"
        while hasattr(f, "f_code"):
            co = f.f_code
            filename = os.path.normcase(co.co_filename)
            if filename == logging._srcfile:
                f = f.f_back.f_back
                continue
            rv = (filename, f.f_lineno, co.co_name)
            break
        return rv

logging._acquireLock()
try:
    logging.setLoggerClass(testLogger)
    logging.getLogger("root.testLogger")
    logging.setLoggerClass(logging.Logger)
finally:
    logging._releaseLock()

class TestOptionMissing(LnstError):
    pass

class TestGeneric(NetTestCommandGeneric):
    def __init__(self, command):
        self._testLogger = logging.getLogger("root.testLogger")
        NetTestCommandGeneric.__init__(self, command)

    def wait_on_interrupt(self):
        '''
        Should be used by test implementation for waiting on SIGINT
        '''
        try:
            handler = signal.getsignal(signal.SIGINT)
            signal.signal(signal.SIGINT, signal.default_int_handler)
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass
        finally:
            signal.signal(signal.SIGINT, handler)

    def _get_val(self, value, opt_type, default):
        if opt_type == "addr":
            '''
            If address type is specified do "slashcut"
            '''
            return re.sub(r'/.*', r'', value)

        if default != None and default != []:
            '''
            In case a default value is passed, retype value
            by the default value type.
            '''
            return (type(default))(value)

        return value

    def get_opt(self, name, multi=False, mandatory=False, opt_type="", default=None):
        try:
            option = self._command["options"][name]
        except KeyError:
            if mandatory:
                raise TestOptionMissing("Missing option '%s'!" % name)
            return default

        if multi:
            value = []
            for op in option:
                value.append(self._get_val(op["value"], opt_type, default))
        else:
            value = self._get_val(option[0]["value"], opt_type, default)

        return value

    def get_mopt(self, name, opt_type=""):
        '''
        This should be used to get mandatory options
        '''
        return self.get_opt(name, mandatory=True, opt_type=opt_type)

    def get_multi_opt(self, name, mandatory=False, opt_type="", default=[]):
        '''
        This should be used to get multi options (array of values)
        '''
        return self.get_opt(name, multi=True, mandatory=mandatory,
                            opt_type=opt_type, default=default)

    def get_multi_mopt(self, name, opt_type=""):
        '''
        This should be used to get mandatory multi options (array of values)
        '''
        return self.get_multi_opt(name, mandatory=True, opt_type=opt_type)

    def get_single_opts(self):
        opts = {}
        for key in self._command["options"]:
            item = self._command["options"][key]
            if len(item) == 1:
                opts[key] = item[0]["value"]
        return opts

    def _format_cmd_res_header(self):
        cmd_val = self._command["module"]
        cmd_type = self._command["type"]
        if "bg_id" in self._command:
            bg_id = " bg_id: %s" % self._command["bg_id"]
        else:
            bg_id = ""
        cmd = "%-9s%s%s" %(cmd_type, cmd_val, bg_id)
        return cmd
