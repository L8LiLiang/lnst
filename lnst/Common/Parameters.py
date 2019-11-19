"""
This module defines the Param class, it's type specific derivatives
(IntParam, StrParam) and the Parameters class which serves as a container for
Param instances. This can be used by a BaseRecipe class to specify
optional/mandatory parameters for the entire test, or by HostReq and DeviceReq
classes to define specific parameters needed for the matching algorithm.

Copyright 2017 Red Hat, Inc.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
olichtne@redhat.com (Ondrej Lichtner)
"""

import copy
import re
from lnst.Common.DeviceRef import DeviceRef
from lnst.Common.IpAddress import BaseIpAddress, ipaddress
from lnst.Common.LnstError import LnstError

class ParamError(LnstError):
    pass

class Param(object):
    def __init__(self, mandatory=False, **kwargs):
        self.mandatory = mandatory
        if "default" in kwargs:
            self.default = kwargs["default"]

    def type_check(self, value):
        return value

class IntParam(Param):
    def type_check(self, value):
        try:
            return int(value)
        except ValueError:
            raise ParamError("Value must be a valid integer")

class FloatParam(Param):
    def type_check(self, value):
        try:
            return float(value)
        except ValueError:
            raise ParamError("Value must be a valid float")

class StrParam(Param):
    def type_check(self, value):
        try:
            return str(value)
        except ValueError:
            raise ParamError("Value must be a string")

class BoolParam(Param):
    def type_check(self, value):
        if isinstance(value, bool):
            return value
        else:
            raise ParamError("Value must be a boolean")

class IpParam(Param):
    def type_check(self, value):
        try:
            return ipaddress(value)
        except LnstError:
            raise ParamError("Value must be a BaseIpAddress object")

class HostnameParam(Param):
    def type_check(self, value):
        if not isinstance(value, str) or len(value) > 255:
            raise ParamError("Value must be a valid hostname string")

        hostname_re = ("^([A-Z0-9]|[A-Z0-9][A-Z0-9\-]{0,61}[A-Z0-9])"
                       "(\.([A-Z0-9]|[A-Z0-9][A-Z0-9\-]{0,61}[A-Z0-9]))*$")
        if re.match(hostname_re, value, re.IGNORECASE):
            return value
        else:
            raise ParamError("Value must be a valid hostname string")

class HostnameOrIpParam(IpParam, HostnameParam):
    def type_check(self, value):
        try:
            return IpParam.type_check(self, value)
        except:
            try:
                return HostnameParam.type_check(self, value)
            except:
                raise ParamError("Value must be a valid hostname string, ipaddress string or a BaseIpAddress object.")

class DeviceParam(Param):
    def type_check(self, value):
        #runtime import this because the Device class arrives on the Slave
        #during recipe execution, not during Slave init
        from lnst.Devices.Device import Device
        if isinstance(value, Device) or isinstance(value, DeviceRef):
            return value
        else:
            raise ParamError("Value must be a Device or DeviceRef object."
                             " Not {}".format(type(value)))

class DeviceOrIpParam(Param):
    def type_check(self, value):
        #runtime import this because the Device class arrives on the Slave
        #during recipe execution, not during Slave init
        from lnst.Devices.Device import Device
        if (isinstance(value, Device) or isinstance(value, DeviceRef) or
            isinstance(value, BaseIpAddress)):
            return value
        else:
            raise ParamError("Value must be a Device, DeviceRef or BaseIpAddress object."
                             " Not {}".format(type(value)))

class DictParam(Param):
    def type_check(self, value):
        if not isinstance(value, dict):
            raise ParamError("Value must be a Dictionary. Not {}"
                             .format(type(value)))
        else:
            return value

class ListParam(Param):
    def __init__(self, type=None, **kwargs):
        self._type = type
        super(ListParam, self).__init__(**kwargs)

    def type_check(self, value):
        if not isinstance(value, list):
            raise ParamError("Value must be a List. Not {}".format(type(value)))

        if self._type is not None:
            for item in value:
                try:
                    self._type.type_check(item)
                except ParamError as e:
                    raise ParamError("Value {} failed type check:\n{}"
                                     .format(str(e)))
        return value

class Parameters(object):
    def __init__(self):
        self._attrs = {}

    def __getattr__(self, name):
        if name == "_attrs":
            return object.__getattribute__(self, name)

        try:
            return self._attrs[name]
        except KeyError:
            return object.__getattribute__(self, name)

    def __setattr__(self, name, val):
        if name == "_attrs":
            super(Parameters, self).__setattr__(name, val)
        else:
            self._attrs[name] = val

    def __delattr__(self, name):
        del self._attrs[name]

    def __contains__(self, name):
        return name in self._attrs

    def __iter__(self):
        for attr, val in list(self._attrs.items()):
            yield (attr, val)

    def _to_dict(self):
        return copy.deepcopy(self._attrs)

    def _from_dict(self, d):
        for name, val in list(d.items()):
            setattr(self, name, copy.deepcopy(val))

    def __str__(self):
        result = ""
        for attr, val in list(self._attrs.items()):
            result += "%s = %s\n" % (attr, str(val))
        return result
