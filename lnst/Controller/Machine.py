"""
This file containst classes for representing and handling
a Machine and an Interface in LNST

Copyright 2013 Red Hat, Inc.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
rpazdera@redhat.com (Radek Pazdera)
"""

import logging
import socket
import sys
import signal
from lnst.Common.Utils import sha256sum
from lnst.Common.Utils import check_process_running
from lnst.Common.Version import lnst_version
from lnst.Controller.Common import ControllerError
from lnst.Controller.CtlSecSocket import CtlSecSocket
from lnst.Controller.RecipeResults import JobStartResult, JobFinishResult, DeviceCreateResult, DeviceMethodCallResult, DeviceAttrSetResult
from lnst.Controller.SlaveObject import SlaveObject
from lnst.Devices import device_classes
from lnst.Devices.Device import Device
from lnst.Devices.RemoteDevice import RemoteDevice

# conditional support for libvirt
if check_process_running("libvirtd"):
    from lnst.Controller.VirtDomainCtl import VirtDomainCtl

class MachineError(ControllerError):
    pass

class PrefixMissingError(ControllerError):
    pass

class Machine(object):
    """ Slave machine abstraction

        A machine object represents a handle using which the controller can
        manipulate the machine. This includes tasks such as, configuration,
        deconfiguration, and running commands.
    """

    def __init__(self, m_id, hostname, msg_dispatcher, ctl_config,
                 libvirt_domain=None, rpcport=None, security=None):
        self._id = m_id
        self._hostname = hostname
        self._mapped = False
        self._ctl_config = ctl_config
        self._slave_desc = None
        self._connection = None
        self._system_config = {}
        self._security = security
        self._security["identity"] = ctl_config.get_option("security",
                                                           "identity")
        self._security["privkey"] = ctl_config.get_option("security",
                                                           "privkey")

        self._domain_ctl = None
        self._network_bridges = None
        self._libvirt_domain = libvirt_domain
        if libvirt_domain:
            self._domain_ctl = VirtDomainCtl(libvirt_domain)

        if rpcport:
            self._port = rpcport
        else:
            self._port = ctl_config.get_option('environment', 'rpcport')

        self._msg_dispatcher = msg_dispatcher

        self._recipe = None
        self._mac_pool = None

        self._interfaces = []
        self._namespaces = []
        self._services = []
        self._bg_cmds = {}
        self._jobs = {}
        self._job_id_seq = 0

        self._device_database = {}
        self._tmp_device_database = []

        self._initns = None

    def set_id(self, new_id):
        self._id = new_id

    def set_initns(self, ns):
        self._initns = ns

    def get_id(self):
        return self._id

    def set_mapped(self, new_value):
        self._mapped = new_value

    def get_mapped(self):
        return self._mapped

    def get_configuration(self):
        configuration = {}
        configuration["id"] = self._id
        configuration["hostname"] = self._hostname
        configuration["kernel_release"] = self._slave_desc["kernel_release"]
        configuration["redhat_release"] = self._slave_desc["redhat_release"]

        configuration["interfaces"] = {}
        for dev in list(self._device_database.items()):
            configuration["device_"+dev.name] = dev.get_config()
        return configuration

    def add_tmp_device(self, dev):
        self._tmp_device_database.append(dev)
        dev._machine = self

    def remote_device_create(self, dev, netns=None):
        dev_clsname = dev._dev_cls.__name__
        dev_args = dev._dev_args
        dev_kwargs = dev._dev_kwargs

        self._add_recipe_result(
            DeviceCreateResult(
                success=True,
                device=dev,
            )
        )

        ret = self.rpc_call("create_device", clsname=dev_clsname,
                                             args=dev_args,
                                             kwargs=dev_kwargs,
                                             netns=netns)
        dev._machine = self
        dev.ifindex = ret["ifindex"]
        self._device_database[ret["ifindex"]] = dev

    def remote_device_set_netns(self, dev, dst, src):
        self.rpc_call("set_dev_netns", dev, dst.name, netns=src)

    def remote_device_method(self, index, method_name, args, kwargs, netns):
        config_res = DeviceMethodCallResult(
            success=True,
            device=self._device_database[index],
            method_name=method_name,
            args=args,
            kwargs=kwargs,
        )

        try:
            res = self.rpc_call("dev_method", index, method_name, args, kwargs,
                                netns=netns)
        except:
            config_res.success = False
            raise
        finally:
            self._add_recipe_result(config_res)
        return res

    def remote_device_setattr(self, index, attr_name, value, netns):
        config_res = DeviceAttrSetResult(
            success=True,
            device=self._device_database[index],
            attr_name=attr_name,
            value=value,
            old_value=getattr(self._device_database[index], attr_name),
        )
        self._add_recipe_result(config_res)

        try:
            res = self.rpc_call("dev_setattr", index, attr_name, value, netns=netns)
        except:
            config_res.success = False
            raise
        return res

    def remote_device_getattr(self, index, attr_name, netns):
        return self.rpc_call("dev_getattr", index, attr_name, netns=netns)

    def device_created(self, dev_data):
        ifindex = dev_data["ifindex"]
        if ifindex not in self._device_database:
            new_dev = None
            if len(self._tmp_device_database) > 0:
                for dev in self._tmp_device_database:
                    if dev._match_update_data(dev_data):
                        new_dev = dev
                        break

            if new_dev is None:
                new_dev = RemoteDevice(Device)
                new_dev._machine = self
                new_dev.ifindex = ifindex
                new_dev.netns = self._initns
            else:
                self._tmp_device_database.remove(new_dev)

                new_dev.ifindex = dev_data["ifindex"]

            self._device_database[ifindex] = new_dev

    def device_delete(self, dev_data):
        if dev_data["ifindex"] in self._device_database:
            self._device_database[dev_data["ifindex"]].deleted = True

    def dev_db_get_ifindex(self, ifindex):
        if ifindex in self._device_database:
            return self._device_database[ifindex]
        else:
            return None

    def dev_db_get_name(self, dev_name):
        #TODO move these to Slave to optimize quering for each device
        for dev in list(self._device_database.values()):
            if dev.get_name() == dev_name:
                return dev
        return None

<<<<<<< HEAD
    def mroute_init(self, table_id):
        return self._rpc_call("mroute_init", table_id)

    def mroute_finish(self, table_id):
        return self._rpc_call("mroute_finish", table_id)

    def mroute_pim_init(self, table_id):
        return self._rpc_call("mroute_pim_init", table_id)

    def mroute_pim_finish(self, table_id):
        return self._rpc_call("mroute_pim_init", True, table_id)

    def mroute_add_vif_reg(self, vif_id, table_id):
        return self._rpc_call("mroute_add_vif_reg", vif_id, table_id)

    def mroute_del_vif_reg(self, vif_id, table_id):
        return self._rpc_call("mroute_del_vif_reg", vif_id, table_id)

    def mroute_add_mfc(self, group, source, source_vif, out_vifs, table_id):
        return self._rpc_call("mroute_add_mfc",  group, source, source_vif,
                              out_vifs, table_id)

    def mroute_add_mfc_proxy(self, group, source, source_vif, out_vifs,
                             table_id):
        return self._rpc_call("mroute_add_mfc",  group, source, source_vif,
                              out_vifs, True, table_id)

    def mroute_del_mfc(self, group, source, source_vif, table_id):
        return self._rpc_call("mroute_del_mfc",  group, source, source_vif,
                              table_id)

    def mroute_del_mfc_proxy(self, group, source, source_vif, table_id):
        return self._rpc_call("mroute_del_mfc",  group, source, source_vif,
                              True, table_id)

    def mroute_get_notif(self, table_id):
        return self._rpc_call("mroute_get_notif", table_id)

    def mroute_table(self, index):
        return self._rpc_call("mroute_table", index)

    #
    # Factory methods for constructing interfaces on this machine. The
    # types of interfaces are explained with the classes below.
    #
    def new_static_interface(self, if_id, if_type):
        return self._add_interface(if_id, if_type, StaticInterface)

    def new_unused_interface(self, if_type):
        return self._add_interface(None, if_type, UnusedInterface)

    def new_virtual_interface(self, if_id, if_type):
        return self._add_interface(if_id, if_type, VirtualInterface)

    def new_soft_interface(self, if_id, if_type):
        return self._add_interface(if_id, if_type, SoftInterface)

    def new_loopback_interface(self, if_id):
        return self._add_interface(if_id, 'lo', LoopbackInterface)

    def get_interface(self, if_id):
        for iface in self._interfaces:
            if iface.get_id != None and if_id == iface.get_id():
                return iface

        msg = "Interface '%s' not found on machine '%s'" % (if_id, self._id)
        raise MachineError(msg)

    def get_interfaces(self):
        return self._interfaces

    def get_ordered_interfaces(self):
        ordered_list = list(self._interfaces)
        change = True
        while change:
            change = False
            swap = False
            ind1 = 0
            ind2 = 0
            for i in ordered_list:
                master = i.get_primary_master()
                if master != None:
                    ind1 = ordered_list.index(i)
                    ind2 = ordered_list.index(master)
                    if ind1 > ind2:
                        swap = True
                        break
            if swap:
                change = True
                tmp = ordered_list[ind1]
                ordered_list[ind1] = ordered_list[ind2]
                ordered_list[ind2] = tmp
        return ordered_list

    def _rpc_call(self, method_name, *args):
        data = {"type": "command", "method_name": method_name, "args": args}

        self._msg_dispatcher.send_message(self._id, data)
        result = self._msg_dispatcher.wait_for_result(self._id)

        return result

    def _rpc_call_to_netns(self, netns, method_name, *args):
        data = {"type": "command", "method_name": method_name, "args": args}
        msg = {"type": "to_netns", "netns": netns, "data": data}

        self._msg_dispatcher.send_message(self._id, msg)
        result = self._msg_dispatcher.wait_for_result(self._id)
=======
    def get_dev_by_hwaddr(self, hwaddr):
        #TODO move these to Slave to optimize quering for each device
        for dev in list(self._device_database.values()):
            if dev.hwaddr == hwaddr:
                return dev
        return None
>>>>>>> jpirko/master

    def rpc_call(self, method_name, *args, **kwargs):
        if kwargs.get("netns") in self._namespaces:
            netns = kwargs["netns"]
            del kwargs["netns"]
            msg = {"type": "to_netns",
                   "netns": netns.name,
                   "data": {"type": "command",
                            "method_name": method_name,
                            "args": args,
                            "kwargs": kwargs}}
        else:
            if "netns" in kwargs:
                del kwargs["netns"]
            msg = {"type": "command",
                   "method_name": method_name,
                   "args": args,
                   "kwargs": kwargs}

        return self._msg_dispatcher.send_message(self, msg)

    def init_connection(self, timeout=None):
        """ Initialize the slave connection

        This will connect to the Slave, get it's description (should be
        usable for matching), and checks version compatibility
        """
        hostname = self._hostname
        port = self._port
        m_id = self._id

        logging.info("Connecting to RPC on machine %s (%s)", m_id, hostname)
        connection = CtlSecSocket(socket.create_connection((hostname, port),
                                                           timeout))
        connection.handshake(self._security)

        self._msg_dispatcher.add_slave(self, connection)

        hello, slave_desc = self.rpc_call("hello")
        if hello != "hello":
            msg = "Unable to establish RPC connection " \
                  "to machine %s, handshake failed!" % hostname
            raise MachineError(msg)

        slave_version = slave_desc["lnst_version"]

        if lnst_version != slave_version:
            if lnst_version.is_git_version:
                msg = ("Controller ({}) and Slave '{}' ({}) versions "
                       "are different".format(lnst_version, hostname,
                                              slave_version))
                logging.warning(len(msg)*"=")
                logging.warning(msg)
                logging.warning(len(msg)*"=")
            else:
                msg = ("Controller ({}) and Slave '{}' ({}) versions "
                       "are not compatible!".format(lnst_version, hostname,
                                                    slave_version))
                raise MachineError(msg)

        self._slave_desc = slave_desc

    def prepare_machine(self):
        self.rpc_call("prepare_machine")
        self._send_device_classes()
        self.rpc_call("init_if_manager")

        self._device_database = {}

        devices = self.rpc_call("get_devices")
        for ifindex, dev in list(devices.items()):
            remote_dev = RemoteDevice(Device)
            remote_dev._machine = self
            remote_dev.ifindex = ifindex
            remote_dev.netns = self._initns

            self._device_database[ifindex] = remote_dev

    def start_recipe(self, recipe):
        self._recipe = recipe
        recipe_name = recipe.__class__.__name__
        self.rpc_call("start_recipe", recipe_name)

    def stop_recipe(self):
        self._recipe = None

    def _add_recipe_result(self, result):
        if self._recipe:
            self._recipe.current_run.add_result(result)

    def _send_device_classes(self):
        for cls_name, cls in device_classes:
            self.send_class(cls)

        for cls_name, cls in device_classes:
            module_name = cls.__module__
            self.rpc_call("map_device_class", cls_name, module_name)

    def send_class(self, cls):
        classes = [cls]
        classes.extend(self._get_base_classes(cls))

        for cls in reversed(classes):
            module_name = cls.__module__

            if module_name == "builtins":
                continue

            module = sys.modules[module_name]
            filename = module.__file__

            if filename[-3:] == "pyc":
                filename = filename[:-1]

            res_hash = self.sync_resource(module_name, filename)
            self.rpc_call("load_cached_module", module_name, res_hash)

    def is_git_version(self, version):
        try:
            int(version)
            return False
        except ValueError:
            return True

    def cleanup_devices(self):
        for netns in self._namespaces:
            self.rpc_call("destroy_devices", netns=netns)
        self.rpc_call("destroy_devices")

    def cleanup(self):
        """ Clean the machine up

            This is the counterpart of the configure() method. It will
            stop any still active commands on the machine, deconfigure
            all the interfaces that have been configured on the machine,
            and finalize and close the rpc connection to the machine.
        """
        #connection to the slave was closed
        if not self._msg_dispatcher.get_connection(self):
            return

        try:
<<<<<<< HEAD
            #dump statistics
            for iface in self._interfaces:
                # Getting stats only from real interfaces
                if isinstance(iface, UnusedInterface):
                    continue
                stats = iface.link_stats()
                if stats:
                    logging.debug("%s:%s:%s: RX:\t bytes: %d\t packets: %d\t dropped: %d" %
                                  (iface.get_netns(), iface.get_host(),
                                   iface.get_id(), stats["rx_bytes"],
                                   stats["rx_packets"], stats["rx_dropped"]))
                    logging.debug("%s:%s:%s: TX:\t bytes: %d\t packets: %d\t dropped: %d" %
                                  (iface.get_netns(), iface.get_host(),
                                   iface.get_id(), stats["tx_bytes"],
                                   stats["tx_packets"], stats["tx_dropped"]))

            self._rpc_call("kill_cmds")
=======
>>>>>>> jpirko/master
            for netns in self._namespaces:
                self.rpc_call("kill_jobs", netns=netns)
            self.rpc_call("kill_jobs")

            self.restore_system_config()
<<<<<<< HEAD

            if deconfigure:
                ordered_ifaces.reverse()
                for iface in ordered_ifaces:
                    iface.deconfigure()
                for iface in ordered_ifaces:
                    iface.cleanup()

                self.disable_services()
                self.del_namespaces()

            self.restore_nm_option()
            self._rpc_call("bye")
=======
            self.cleanup_devices()
            self.del_namespaces()
            # self.restore_nm_option()
            self.rpc_call("bye")
>>>>>>> jpirko/master
        except:
            #cleanup is only meaningful on dynamic interfaces, and should
            #always be called when deconfiguration happens- especially
            #when something on the slave breaks during deconfiguration
            self.cleanup_devices()
            raise

    def _get_base_classes(self, cls):
        new_bases = [cls] + list(cls.__bases__)
        bases = []
        while len(new_bases) != len(bases):
            bases = new_bases
            new_bases = list(bases)
            for b in bases:
                for bs in b.__bases__:
                    if bs not in new_bases:
                        new_bases.append(bs)
        return new_bases

    def run_job(self, job):
        job.id = self._job_id_seq
        self._job_id_seq += 1
        self._jobs[job.id] = job

        if job.type == "module":
            self.send_class(job._what.__class__)

        logging.debug("Host %s executing job %d: %s" %
                     (self._id, job.id, str(job)))
        logging.debug("Job.what = {}".format(repr(job.what)))
        if job._desc is not None:
            logging.info("Job description: %s" % job._desc)

        job_result = JobStartResult(job, True)
        self._add_recipe_result(job_result)
        job_result.success = self.rpc_call("run_job", job._to_dict(),
                                           netns=job.netns)

        return job_result.success

    def wait_for_job(self, job, timeout):
        if job.id not in self._jobs:
            raise MachineError("No job '%s' running on Machine %s" %
                               (job.id, self._id))

        if timeout > 0:
            logging.debug("Waiting for Job %d on Host %s for %d seconds." %
                         (job.id, self._id, timeout))
        elif timeout == 0:
            logging.debug("Waiting for Job %d on Host %s." %
                         (job.id, self._id))

        def condition():
            return job.finished

        return self._msg_dispatcher.wait_for_condition(condition, timeout)

    def wait_for_tmp_devices(self, timeout):
        if timeout > 0:
            logging.info("Waiting for Device creation Host %s for %d seconds." %
                         (self._id, timeout))
        elif timeout == 0:
            logging.info("Waiting for Device creation on Host %s." %
                         (self._id))

        def condition():
            return len(self._tmp_device_database) <= 0

        return self._msg_dispatcher.wait_for_condition(condition, timeout)

    def job_finished(self, msg):
        job_id = msg["job_id"]
        job = self._jobs[job_id]
        job._res = msg["result"]
        self._add_recipe_result(JobFinishResult(job))

    def kill(self, job, signal):
        if job.id not in self._jobs:
            raise MachineError("No job '%s' running on Machine %s" %
                               (job.id(), self._id))
        return self.rpc_call("kill_job", job.id, signal, netns=job.netns)

    def get_hostname(self):
        """ Get hostname/ip of the machine

            This will return the hostname/ip of the machine's controller
            interface.
        """
        return self._hostname

    def get_libvirt_domain(self):
        return self._libvirt_domain

    def get_mac_pool(self):
        if self._mac_pool:
            return self._mac_pool
        else:
            raise MachineError("Mac pool not available.")

    def set_mac_pool(self, mac_pool):
        self._mac_pool = mac_pool

    def restore_system_config(self):
        self.rpc_call("restore_system_config")
        for netns in self._namespaces:
            self.rpc_call("restore_system_config", netns=netns)
        return True

    def set_network_bridges(self, bridges):
        self._network_bridges = bridges

    def get_network_bridges(self):
        if self._network_bridges != None:
            return self._network_bridges
        else:
            raise MachineError("Network bridges not available.")

    def get_domain_ctl(self):
        if not self._domain_ctl:
            raise MachineError("Machine '%s' is not virtual." % self.get_id())

        return self._domain_ctl

    def start_packet_capture(self):
        namespaces = set()
        for iface in self._interfaces:
            namespaces.add(iface.get_netns())

        tmp = {}
        for netns in namespaces:
            tmp.update(self.rpc_call("start_packet_capture", "", netns=netns))
        return tmp

    def stop_packet_capture(self):
        namespaces = set()
        for iface in self._interfaces:
            namespaces.add(iface.get_netns())

        for netns in namespaces:
            self.rpc_call("stop_packet_capture", netns=netns)

    def copy_file_to_machine(self, local_path, remote_path=None, netns=None):
        remote_path = self.rpc_call("start_copy_to", remote_path, netns=netns)

        f = open(local_path, "rb")

        while True:
            data = f.read(1024*1024) # 1MB buffer
            if len(data) == 0:
                break

            self.rpc_call("copy_part_to", remote_path, data, netns=netns)

        self.rpc_call("finish_copy_to", remote_path, netns=netns)

        return remote_path

    def copy_file_from_machine(self, remote_path, local_path):
        status = self.rpc_call("start_copy_from", remote_path)
        if not status:
            raise MachineError("The requested file cannot be transfered." \
                       "It does not exist on machine %s" % self.get_id())

        local_file = open(local_path, "wb")

        buf_size = 1024*1024 # 1MB buffer
        while True:
            data = self.rpc_call("copy_part_from", remote_path, buf_size)
            if data == "":
                break
            local_file.write(data)

        local_file.close()
        self.rpc_call("finish_copy_from", remote_path)

    def sync_resource(self, res_name, file_path):
        digest = sha256sum(file_path)

        if not self.rpc_call("has_resource", digest):
            msg = "Transfering %s to machine %s as '%s'" % (file_path,
                                                            self.get_id(),
                                                            res_name)
            logging.debug(msg)

            remote_path = self.copy_file_to_machine(file_path)
            self.rpc_call("add_resource_to_cache",
                           "file", remote_path, res_name)
        return digest

    def init_remote_class(self, cls, *args, **kwargs):
        module_name = cls.__module__
        cls_name = cls.__name__
        obj_ref = self.rpc_call("init_cls", cls_name, module_name, args, kwargs)

        return SlaveObject(self, cls, obj_ref)

    # def enable_nm(self):
        # return self._rpc_call("enable_nm")

    # def disable_nm(self):
        # return self._rpc_call("disable_nm")

    # def restore_nm_option(self):
        # return self._rpc_call("restore_nm_option")

    def __str__(self):
        return "[Machine hostname(%s) libvirt_domain(%s) interfaces(%d)]" % \
               (self._hostname, self._libvirt_domain, len(self._interfaces))

    def add_netns(self, netns):
        self._namespaces.append(netns)
        return self.rpc_call("add_namespace", netns)

    def del_netns(self, netns):
        return self.rpc_call("del_namespace", netns)

    def get_routes(self, routes_filter, ns):
        routes = self._rpc_call_x(ns, "get_routes", routes_filter)
        return routes

    def del_namespaces(self):
        for netns in self._namespaces:
            self.del_netns(netns)
        self._namespaces = []
        return True

    def get_security(self):
        return self._security
<<<<<<< HEAD

    def enable_service(self, service):
        self._services.append(service)
        return self._rpc_call("enable_service", service)

    def disable_service(self, service):
        try:
            self._services.remove(service)
        except ValueError:
            return False
        return self._rpc_call("disable_service", service)

    def restart_service(self, service):
        if service not in self._services:
            self._services.append(service)
        return self._rpc_call("restart_service", service)

    def get_num_cpus(self):
        return self._rpc_call("get_num_cpus")

class Interface(object):
    """ Abstraction of a test network interface on a slave machine

        This is a base class for object that represent test interfaces
        on a test machine.
    """
    def __init__(self, machine, if_id, if_type):
        self._machine = machine
        self._configured = False

        self._id = if_id
        self._type = if_type

        self._hwaddr = None
        self._devname = None
        self._network = None
        self._netem = None

        self._slaves = {}
        self._slave_options = {}
        self._addresses = []
        self._options = []

        self._master = {"primary": None, "other": []}

        self._ovs_conf = None

        self._netns = None
        self._peer = None
        self._mtu = None
        self._driver = None
        self._devlink = None
        self._routes = []
        self._cdata = None

    def get_id(self):
        return self._id

    def get_type(self):
        return self._type

    def get_driver(self):
        return self._driver

    def set_hwaddr(self, hwaddr):
        self._hwaddr = normalize_hwaddr(hwaddr)

    def get_hwaddr(self):
        if not self._hwaddr:
            msg = "Hardware address is not available for interface '%s'" \
                  % self.get_id()
            raise MachineError(msg)
        return self._hwaddr

    def set_devname(self, devname):
        self._devname = devname

    def get_devname(self):
        if not self._devname:
            msg = "Device name is not available for interface '%s'" \
                  % self.get_id()
            raise MachineError(msg)
        return self._devname

    def set_network(self, network):
        self._network = network

    def get_network(self):
        if not self._network:
            msg = "Network segment is not available for interface '%s'" \
                  % self.get_id()
            raise MachineError(msg)
        return self._network

    def set_option(self, name, value):
        self._options.append((name, value))

    def set_netem(self, netem):
        self._netem = netem

    def add_master(self, master, primary=True):
        if primary and self._master["primary"] != None:
            msg = "Interface %s already has a primary master."\
                    % self.get_id()
            raise MachineError(msg)
        else:
            if primary:
                self._master["primary"] = master
            else:
                self._master["other"].append(master)

    def del_master(self, master):
        if self._master["primary"] is master:
            self._master["primary"] = None
        else:
            self._master["other"].remove(master)

    def get_primary_master(self):
        return self._master["primary"]

    def add_slave(self, iface):
        self._slaves[iface.get_id()] = iface
        if self._type in ["vlan", "vxlan", "gre", "ipip"]:
            iface.add_master(self, primary=False)
        else:
            iface.add_master(self)

    def del_slave(self, iface):
        iface.del_master(self)
        del self._slaves[iface.get_id()]

    def set_slave_option(self, slave_id, name, value):
        if slave_id not in self._slave_options:
            self._slave_options[slave_id] = []
        self._slave_options[slave_id].append((name, value))

    def add_address(self, addr):
        if (type(addr) == type([])):
            for one_addr in addr:
                self._addresses.append(one_addr)
        else:
            self._addresses.append(addr)

    def get_address(self, num):
        return self._addresses[num].split('/')[0]

    def get_addresses(self):
        addrs = []
        for addr in self._addresses:
            addrs.append(tuple(addr.split('/')))
        return addrs

    def set_ovs_conf(self, ovs_conf):
        self._ovs_conf = ovs_conf

    def get_ovs_conf(self):
        return self._ovs_conf

    def set_netns(self, netns):
        self._netns = netns

    def get_netns(self):
        return self._netns

    def get_host(self):
        return self._machine.get_id()

    def set_peer(self, peer):
        self._peer = peer

    def get_peer(self):
        return self._peer

    def get_prefix(self, num):
        try:
            return self._addresses[num].split('/')[1]
        except IndexError:
            raise PrefixMissingError

    def get_mtu(self):
        return self._mtu

    def set_mtu(self, mtu):
        command = {"type": "config",
                   "host": self._machine.get_id(),
                   "persistent": False,
                   "options":[
                       {"name": "/sys/class/net/%s/mtu" % self._devname,
                        "value": str(mtu)}
                    ]}
        command["netns"] = self._netns

        self._machine.run_command(command)
        self._mtu = mtu
        return self._mtu

    def link_stats(self):
        stats = self._machine._rpc_call_x(self._netns, "link_stats",
                                          self._id)
        return stats

    def link_cpu_ifstat(self):
        stats = self._machine._rpc_call_x(self._netns, "link_cpu_ifstat",
                                          self._id)
        return stats

    def set_addresses(self, ips):
        self._addresses = ips
        self._machine._rpc_call_x(self._netns, "set_addresses",
                                  self._id, ips)

    def add_route(self, dest, ipv6 = False):
        self._routes+= [(dest, None, ipv6)]
        self._machine._rpc_call_x(self._netns, "add_route",
                                  self._id, dest, ipv6)

    def del_route(self, dest, ipv6 = False):
        for i, val in enumerate(self._routes):
            if val == (dest, None, ipv6):
                del self._routes[i]
        self._machine._rpc_call_x(self._netns, "del_route",
                                  self._id, dest, ipv6)

    def add_nhs_route(self, dest, nhs, ipv6 = False):
        self._routes+= [(dest, nhs, ipv6)]
        self._machine._rpc_call_x(self._netns, "add_nhs_route",
                                  self._id, dest, nhs, ipv6)

    def mroute_add_vif(self, vif_index, table_id):
        return self._machine._rpc_call_x(self._netns, "mroute_add_vif",
                                         self._id, vif_index, table_id)

    def mroute_del_vif(self, vif_index, table_id):
        return self._machine._rpc_call_x(self._netns, "mroute_del_vif",
                                         self._id, vif_index, table_id)

    def del_nhs_route(self, dest, nhs, ipv6 = False):
        for i, val in enumerate(self._routes):
            if val == (dest, nhs, ipv6):
                del self._routes[i]
        self._machine._rpc_call_x(self._netns, "del_nhs_route",
                                  self._id, dest, nhs, ipv6)

    def update_from_slave(self):
        if_data = self._machine._rpc_call_x(self._netns, "get_if_data",
                                            self._id)

        if if_data is not None:
            self.update(if_data)
        return

    def update(self, if_data):
        self.set_hwaddr(if_data["hwaddr"])
        self.set_devname(if_data["name"])
        self._mtu = if_data["mtu"]
        self._driver = if_data["driver"]
        self._devlink = if_data["devlink"]

    def get_config(self):
        config = {"id": self._id,
                  "hwaddr": self._hwaddr,
                  "devname": self._devname,
                  "network_label": self._network,
                  "type": self._type,
                  "addresses": self._addresses,
                  "slaves": self._slaves.keys(),
                  "options": self._options,
                  "slave_options": self._slave_options,
                  "master": None,
                  "other_masters": [],
                  "ovs_conf": self._ovs_conf,
                  "netns": self._netns,
                  "peer": self._peer,
                  "netem": self._netem,
                  "mtu": self._mtu,
                  "driver": self._driver}

        if self._master["primary"] != None:
            config["master"] = self._master["primary"].get_id()

        for m in self._master["other"]:
            config["other_masters"].append(m.get_id())

        return config

    def up(self):
        self._machine._rpc_call_x(self._netns, "set_device_up", self._id)

    def down(self):
        self._machine._rpc_call_x(self._netns, "set_device_down", self._id)

    def address_setup(self):
        self._machine._rpc_call_x(self._netns, "device_address_setup", self._id)

    def address_cleanup(self):
        self._machine._rpc_call_x(self._netns, "device_address_cleanup", self._id)

    def set_link_up(self):
        self._machine._rpc_call_x(self._netns, "set_link_up", self._id)

    def set_link_down(self):
        self._machine._rpc_call_x(self._netns, "set_link_down", self._id)

    def initialize(self):
        phys_devs = self._machine._rpc_call("map_if_by_hwaddr",
                                            self._id, self._hwaddr)

        if len(phys_devs) == 1:
            self.set_devname(phys_devs[0]["name"])
        elif len(phys_devs) < 1:
            msg = "Device %s not found on machine %s" \
                  % (self.get_id(), self._machine.get_id())
            raise MachineError(msg)
        elif len(phys_devs) > 1:
            msg = "More than one device with hwaddr %s found on machine %s" \
                  % (self._hwaddr, self._machine.get_id())
            raise MachineError(msg)

        self.down()

    def cleanup(self):
        self._machine._rpc_call("unmap_if", self._id)

    def configure(self):
        if self._configured:
            msg = "Unable to configure interface %s on machine %s. " \
                  "It has been configured already." % (self.get_id(),
                  self._machine.get_id())
            raise MachineError(msg)
        else:
            self._configured = True

        logging.info("Configuring interface %s on machine %s", self.get_id(),
                     self._machine.get_id())

        if self._netns != None:
            self._machine._rpc_call("set_if_netns", self.get_id(), self._netns)
        self._machine._rpc_call_x(self._netns, "configure_interface",
                                  self.get_id(), self.get_config())

        self.update_from_slave()

    def deconfigure(self):
        if not self._configured:
            return

        while self._routes != []:
            if self._routes[1] == None:
                del_route(self._routes[0], self._routes[2])
            else:
                del_route(self._routes[0], self._routes[1], self._routes[2])

        self._machine._rpc_call_x(self._netns, "deconfigure_interface",
                                  self.get_id())
        if self._netns != None:
            self._machine._rpc_call_to_netns(self._netns,
                                         "return_if_netns", self.get_id())
        self._configured = False

    def add_br_vlan(self, br_vlan_info):
        self._machine._rpc_call_x(self._netns, "add_br_vlan",
                                  self._id, br_vlan_info)

    def del_br_vlan(self, br_vlan_info):
        self._machine._rpc_call_x(self._netns, "del_br_vlan",
                                  self._id, br_vlan_info)

    def get_br_vlans(self):
        return self._machine._rpc_call_x(self._netns, "get_br_vlans", self._id)

    def add_br_fdb(self, br_fdb_info):
        self._machine._rpc_call_x(self._netns, "add_br_fdb",
                                  self._id, br_fdb_info)

    def del_br_fdb(self, br_fdb_info):
        self._machine._rpc_call_x(self._netns, "del_br_fdb",
                                  self._id, br_fdb_info)

    def get_br_fdbs(self):
        return self._machine._rpc_call_x(self._netns, "get_br_fdbs", self._id)

    def set_br_learning(self, br_learning_info):
        self._machine._rpc_call_x(self._netns, "set_br_learning", self._id,
                                  br_learning_info)

    def set_br_learning_sync(self, br_learning_sync_info):
        self._machine._rpc_call_x(self._netns, "set_br_learning_sync", self._id,
                                  br_learning_sync_info)

    def set_br_flooding(self, br_flooding_info):
        self._machine._rpc_call_x(self._netns, "set_br_flooding", self._id,
                                  br_flooding_info)

    def set_br_state(self, br_state_info):
        self._machine._rpc_call_x(self._netns, "set_br_state", self._id,
                                  br_state_info)

    def set_br_mcast_snooping(self, set_on):
        self._machine._rpc_call_x(self._netns, "set_br_mcast_snooping",
                                  self._id, set_on)

    def set_br_mcast_querier(self, set_on):
        self._machine._rpc_call_x(self._netns, "set_br_mcast_querier", self._id,
                                  set_on)

    def set_mcast_flood(self, on):
        self._machine._rpc_call_x(self._netns, "set_mcast_flood", self._id, on)

    def set_mcast_router(self, state):
        self._machine._rpc_call_x(self._netns, "set_mcast_router", self._id,
                                  state)

    def set_speed(self, speed):
        self._machine._rpc_call_x(self._netns, "set_speed", self._id, speed)

    def set_autoneg(self):
        self._machine._rpc_call_x(self._netns, "set_autoneg", self._id)

    def slave_add(self, if_id):
        self._machine._rpc_call_x(self._netns, "slave_add", self._id, if_id)
        self.add_slave(self._machine.get_interface(if_id))

    def slave_del(self, if_id):
        self.del_slave(self._machine.get_interface(if_id))
        self._machine._rpc_call_x(self._netns, "slave_del", self._id, if_id)

    def get_devlink_name(self):
        if self._devlink:
            return "%s/%s" % (self._devlink["bus_name"],
                              self._devlink["dev_name"])
        return None

    def get_devlink_port_name(self):
        if self._devlink:
            return "%s/%u" % (self.get_devlink_name(),
                              self._devlink["port_index"])
        return None

    def get_ethtool_stats(self):
        return self._machine._rpc_call_x(self._netns, "get_ethtool_stats",
                                         self._id)

    def enable_lldp(self):
        return self._machine._rpc_call_x(self._netns, "enable_lldp", self._id)

    def set_pause_on(self):
        return self._machine._rpc_call_x(self._netns, "set_pause_on", self._id)

    def set_pause_off(self):
        return self._machine._rpc_call_x(self._netns, "set_pause_off", self._id)

    def get_coalesce(self):
        return self._machine._rpc_call_x(self._netns, "get_coalesce", self._id)

    def set_coalesce(self, cdata):
        return self._machine._rpc_call_x(self._netns, "set_coalesce",
                    self._id, cdata)

    def save_coalesce(self):
        self._cdata = self.get_coalesce()
        return self._cdata

    def restore_coalesce(self):
        self.set_coalesce(self._cdata)
        self._cdata = None
        return None


class StaticInterface(Interface):
    """ Static interface

        This class represents interfaces that are present on the
        machine. LNST will only use them for testing without performing
        any special actions.

        This type is suitable for physical interfaces.
    """
    def __init__(self, machine, if_id, if_type):
        super(StaticInterface, self).__init__(machine, if_id, if_type)

class LoopbackInterface(Interface):
    """ Static interface

        This class represents interfaces that are present on the
        machine. LNST will only use them for testing without performing
        any special actions.

        This type is suitable for physical interfaces.
    """
    def __init__(self, machine, if_id, if_type):
        super(LoopbackInterface, self).__init__(machine, if_id, if_type)

    def initialize(self):
        pass

    def cleanup(self):
        pass

    def configure(self):
        self._hwaddr = '00:00:00:00:00:00'
        self._driver = 'loopback'

        phys_devs = self._machine._rpc_call_x(self._netns,
                                              "map_if_by_params", self._id,
                                              { 'hwaddr': self._hwaddr,
                                                'driver': self._driver })

        if len(phys_devs) == 1:
            self.set_devname(phys_devs[0]["name"])
        elif len(phys_devs) < 1:
            msg = "Device %s not found on machine %s" \
                  % (self.get_id(), self._machine.get_id())
            raise MachineError(msg)
        elif len(phys_devs) > 1:
            msg = "More than one device with hwaddr %s found on machine %s" \
                  % (self._hwaddr, self._machine.get_id())
            raise MachineError(msg)

        if self._configured:
            msg = "Unable to configure interface %s on machine %s. " \
                  "It has been configured already." % (self.get_id(),
                  self._machine.get_id())
            raise MachineError(msg)

        logging.info("Configuring interface %s on machine %s", self.get_id(),
                     self._machine.get_id())

        self._machine._rpc_call_x(self._netns, "configure_interface",
                                  self.get_id(), self.get_config())
        self._configured = True
        self.update_from_slave()

    def deconfigure(self):
        if not self._configured:
            return

        self._machine._rpc_call_x(self._netns, "deconfigure_interface",
                                  self.get_id())
        self._machine._rpc_call_x(self._netns, "unmap_if", self.get_id())
        self._configured = False

class VirtualInterface(Interface):
    """ Dynamically created interface

        This class represents interfaces in libvirt virtual machines
        that were created dynamically by LNST just for this test.

        This requires some special handling and communication with
        libvirt.
    """
    def __init__(self, machine, if_id, if_type):
        super(VirtualInterface, self).__init__(machine, if_id, if_type)
        self._driver = "virtio"

    def set_driver(self, driver):
        self._driver = driver

    def get_driver(self):
        return self._driver

    def get_orig_hwaddr(self):
        if not self._orig_hwaddr:
            msg = "Hardware address is not available for interface '%s'" \
                  % self.get_id()
            raise MachineError(msg)
        return self._orig_hwaddr

    def initialize(self):
        domain_ctl = self._machine.get_domain_ctl()

        if self._hwaddr:
            query = self._machine._rpc_call('get_devices_by_hwaddr',
                                           self._hwaddr)
            if len(query):
                msg = "Device with hwaddr %s already exists" % self._hwaddr
                raise MachineError(msg)
        else:
            mac_pool = self._machine.get_mac_pool()
            while True:
                self._hwaddr = normalize_hwaddr(mac_pool.get_addr())
                query = self._machine._rpc_call('get_devices_by_hwaddr',
                                               self._hwaddr)
                if not len(query):
                    break

        bridges = self._machine.get_network_bridges()
        if self._network in bridges:
            net_ctl = bridges[self._network]
        else:
            bridges[self._network] = net_ctl = VirtNetCtl()
            net_ctl.init()

        net_name = net_ctl.get_name()

        logging.info("Creating interface %s (%s) on machine %s",
                     self.get_id(), self._hwaddr, self._machine.get_id())

        self._orig_hwaddr = self._hwaddr
        domain_ctl.attach_interface(self._hwaddr, net_name, self._driver)


        # The sleep here is necessary, because udev sometimes renames the
        # newly created device and if the query for name comes too early,
        # the controller will then try to configure an nonexistent device
        sleep(1)

        ready = wait_for(self.is_ready, timeout=10)

        if not ready:
            msg = "Netdevice initialization failed." \
                  "Unable to create device %s (%s) on machine %s" \
                  % (self.get_id(), self._hwaddr, self._machine.get_id())
            raise MachineError(msg)

        super(VirtualInterface, self).initialize()

    def cleanup(self):
        self._machine._rpc_call("unmap_if", self._id)
        domain_ctl = self._machine.get_domain_ctl()
        domain_ctl.detach_interface(self._orig_hwaddr)

    def is_ready(self):
        ifaces = self._machine._rpc_call('get_devices_by_hwaddr', self._hwaddr)
        return len(ifaces) > 0

class SoftInterface(Interface):
    """ Software interface abstraction

        This type of interface represents interfaces created in the kernel
        during the runtime. This includes devices such as bonds and teams.
    """

    def __init__(self, machine, if_id, if_type):
        super(SoftInterface, self).__init__(machine, if_id, if_type)

    def initialize(self):
        pass

    def cleanup(self):
        pass

    def configure(self):
        if self._configured:
            return
        else:
            self._configured = True

        logging.info("Configuring interface %s on machine %s", self.get_id(),
                     self._machine.get_id())

        if self._type == "veth":
            peer_if = self._machine.get_interface(self._peer)
            peer_config = peer_if.get_config()
            dev_name, peer_name = self._machine._rpc_call("create_if_pair",
                                                self._id, self.get_config(),
                                                self._peer, peer_config)
            self.set_devname(dev_name)
            peer_if.set_devname(peer_name)
            self._configured = True
            peer_if._configured = True
            return

        dev_name = self._machine._rpc_call_x(self._netns,
                                             "create_soft_interface",
                                             self._id, self.get_config())
        self.set_devname(dev_name)
        self.update_from_slave()

    def deconfigure(self):
        if not self._configured:
            return

        if self._type == "veth":
            peer_if = self._machine.get_interface(self._peer)

            self._machine._rpc_call("deconfigure_if_pair", self._id, self._peer)
            self._machine._rpc_call("unmap_if", self._id)
            self._machine._rpc_call("unmap_if", self._peer)

            self._configured = False
            peer_if._configured = False
            return

        self._machine._rpc_call_x(self._netns, "deconfigure_interface",
                                  self.get_id())
        self._machine._rpc_call_x(self._netns, "unmap_if", self.get_id())
        self._configured = False

class UnusedInterface(Interface):
    """ Unused interface for this test

        This class represents interfaces that will not be used in the
        current test setup. This applies when a slave machine from a
        pool has more interfaces then the machine it was matched to
        from the recipe.

        LNST still needs to know about these interfaces so it can turn
        them off.
    """

    def __init__(self, machine, if_id, if_type):
        super(UnusedInterface, self).__init__(machine, if_id, if_type)

    def initialize(self):
        self._machine._rpc_call('set_unmapped_device_down', self._hwaddr)

    def set_driver(self, driver):
        pass

    def configure(self):
        pass

    def deconfigure(self):
        pass

    def up(self):
        pass

    def down(self):
        pass

    def address_setup(self):
        pass

    def address_cleanup(self):
        pass

    def cleanup(self):
        pass

class Device(object):
    """ Represents device information received from a Slave"""

    def pre_call_decorate(func):
        @wraps(func)
        def func_wrapper(inst, *args, **kwargs):
            inst.slave_update()
            return func(inst, *args, **kwargs)
        return func_wrapper

    def __init__(self, data, machine):
        self._if_index = data["if_index"]
        self._hwaddr = None
        self._name = None
        self._ip_addrs = None
        self._ifi_type = None
        self._state = None
        self._master = None
        self._slaves = None
        self._netns = None
        self._peer = None
        self._mtu = None
        self._driver = None
        self._devlink = None

        self._machine = machine

        self.update_data(data)

    def update_data(self, data):
        if data["if_index"] != self._if_index:
            return False

        self._hwaddr = data["hwaddr"]
        self._name = data["name"]
        self._ip_addrs = data["ip_addrs"]
        self._ifi_type = data["ifi_type"]
        self._state = data["state"]
        self._master = data["master"]
        self._slaves = data["slaves"]
        self._netns = data["netns"]
        self._peer = data["peer"]
        self._mtu = data["mtu"]
        self._driver = data["driver"]
        self._devlink = data["driver"]
        return True

    def slave_update(self):
        res = self._machine._rpc_call_x(self._netns,
                                        "get_device",
                                        self._if_index)
        if res:
            self.update_data(res)
        return

    def get_if_index(self):
        return self._if_index

    @pre_call_decorate
    def get_hwaddr(self):
        return self._hwaddr

    @pre_call_decorate
    def get_name(self):
        return self._name

    @pre_call_decorate
    def get_ip_addrs(self, selector={}):
        return [ip["addr"]
                for ip in self._ip_addrs
                    if selector.items() <= ip.items()]

    @pre_call_decorate
    def get_ip_addr(self, num, selector={}):
        ips = self.get_ip_addrs(selector)
        return ips[num]

    @pre_call_decorate
    def get_ifi_type(self):
        return self._ifi_type

    @pre_call_decorate
    def get_state(self):
        return self._state

    @pre_call_decorate
    def get_master(self):
        return self._master

    @pre_call_decorate
    def get_slaves(self):
        return self._slaves

    @pre_call_decorate
    def get_netns(self):
        return self._netns

    @pre_call_decorate
    def get_peer(self):
        return self._peer

    @pre_call_decorate
    def get_mtu(self):
        return self._mtu

    def set_mtu(self, mtu):
        command = {"type": "config",
                   "host": self._machine.get_id(),
                   "persistent": False,
                   "options":[
                       {"name": "/sys/class/net/%s/mtu" % self._name,
                        "value": str(mtu)}
                    ]}
        command["netns"] = self._netns

        self._machine.run_command(command)

        self.slave_update()
        return self._mtu

    @pre_call_decorate
    def get_driver(self):
        return self._driver

    @pre_call_decorate
    def get_devlink_name(self):
        if self._devlink:
            return "%s/%s" % (self._devlink["bus_name"],
                              self._devlink["dev_name"])
        return None

    @pre_call_decorate
    def get_devlink_port_name(self):
        if self._devlink:
            return "%s/%u" % (self.get_devlink_name(),
                              self._devlink["port_index"])
        return None
=======
>>>>>>> jpirko/master
