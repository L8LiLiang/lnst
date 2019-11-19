"""
Module implementing the BaseRecipe class.

Copyright 2017 Red Hat, Inc.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
olichtne@redhat.com (Ondrej Lichtner)
"""

import copy
import logging
from lnst.Common.Parameters import Parameters, Param
from lnst.Common.Colours import decorate_with_preset
from lnst.Controller.Requirements import _Requirements, HostReq
from lnst.Controller.Common import ControllerError
from lnst.Controller.RecipeResults import BaseResult, Result

class RecipeError(ControllerError):
    """Exception thrown by the BaseRecipe class"""
    pass

class BaseRecipe(object):
    """BaseRecipe class

    Every LNST Recipe written by testers should be inherited from this class.
    An LNST Recipe is composed of several parts:
    * Requirements definition - you define recipe requirements in a derived
        class by defining class attributes of the HostReq type. You can further
        specify Ethernet Device requirements by defining DeviceReq attributes
        of the HostReq object.
        Example:
        m1 = HostReq(arch="x86_64")
        m1.eth0 = DeviceReq(driver="ixgbe")
    * Parameter definition (optional) - you can define paramaters of your Recipe
        by defining class attributes of the Param type (or inherited). These
        parameters can then be accessed from the test() method to change it's
        behaviour. Parameter validity (type) is checked during the
        instantiation of the Recipe object by the base __init__ method.
        You can define your own __init__ method to implement more complex
        Parameter checking if needed, but you MUST call the base __init__
        method first.
        Example:
        MyRecipe(BaseRecipe):
            int_param = IntParam(mandatory=True)
            optional_param = IntParam()

            def test(self):
                x = self.params.int_param
                if "optional_param" in self.params:
                    x += self.params.optional_param

        MyRecipe(int_param = 2, optional_param = 3)

    * Test definition - this is done by defining the test() method, in this
        method the tester has direct access to mapped LNST slave Hosts, can
        manipulate them and implement his tests.

    Attributes:
        matched -- when running the Recipe the Controller will fill this
            attribute with a Hosts object after the Mapper finds suitable slave
            hosts.
        req -- instantiated Requirements object, you can optionally change the
            Recipe requirements through this object during runtime (e.g.
            variable number of hosts or devices of a host based on a Parameter)
        params -- instantiated Parameters object, can be used to access the
            calculated parameters during Recipe initialization/execution
    """
    def __init__(self, **kwargs):
        """
        The __init__ method does 2 things:
        * copies Requirements -- since Requirements are defined as class
            attributes, we need to copy the objects to avoid conflicts with
            multiple instances of the same class etc...
            The copied objects are stored under a Requirements object available
            through the 'req' attribute. This way you can optionally change the
            Requirements of an instantiated Recipe.
        * copies and instantiates Parameters -- Parameters are also class
            attributes so they need to be copied into a Parameters() object
            (accessible in the 'params' attribute).
            Next, the copied objects are loaded with values from kwargs
            and checked if mandatory Parameters have values.
        """
        self._ctl = None
        self.runs = []
        self.req = _Requirements()
        self.params = Parameters()

        attrs = {name: getattr(type(self), name) for name in dir(type(self))}

        params = ((name, val) for name, val in attrs.items() if isinstance(val, Param))
        for name, val in params:
            if name in kwargs:
                param_val = kwargs.pop(name)
                param_val = val.type_check(param_val)
                setattr(self.params, name, param_val)
            else:
                try:
                    param_val = copy.deepcopy(val.default)
                    setattr(self.params, name, param_val)
                except AttributeError:
                    if val.mandatory:
                        raise RecipeError("Parameter {} is mandatory".format(name))

        reqs = ((name, val) for name, val in attrs.items() if isinstance(val, HostReq))
        for name, val in reqs:
            new_val = copy.deepcopy(val)
            new_val.reinit_with_params(self.params)
            setattr(self.req, name, new_val)

        if len(kwargs):
            for key in list(kwargs.keys()):
                raise RecipeError("Unknown parameter {}".format(key))

    @property
    def ctl(self):
        return self._ctl

    def _set_ctl(self, ctl):
        self._ctl = ctl

    @property
    def matched(self):
        if self.ctl is None:
            return None
        return self.ctl.hosts

    def test(self):
        """Method to be implemented by the Tester"""
        raise NotImplementedError("Method test must be defined by a child class.")

    def _init_run(self, run):
        self.runs.append(run)

    @property
    def current_run(self):
        if len(self.runs) > 0:
            return self.runs[-1]
        else:
            return None

    def add_result(self, success, description="", data=None,
                   level=None, data_level=None):
        self.current_run.add_result(Result(success, description, data,
                                           level, data_level))

class RecipeRun(object):
    def __init__(self, match, desc=None):
        self._match = match
        self._desc = desc
        self._results = []

    def add_result(self, result):
        if not isinstance(result, BaseResult):
            raise RecipeError("result must be a BaseActionResult instance.")

        self._results.append(result)

        result_str = (
            decorate_with_preset("PASS", "pass")
            if result.success
            else decorate_with_preset("FAIL", "fail")
        )
        if len(result.description.split("\n")) == 1:
            logging.info(
                "Result: {}, What: {}".format(result_str, result.description)
            )
        else:
            logging.info("Result: {}, What:".format(result_str))
            logging.info("{}".format(result.description))

    @property
    def match(self):
        return self._match

    @property
    def description(self):
        return self._desc

    @property
    def results(self):
        return self._results

    @property
    def overall_result(self):
        return all([i.success for i in self.results])
