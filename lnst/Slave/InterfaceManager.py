"""
This module defines the InterfaceManager class that contains a database of
the available devices, handles netlink messages updating these devices and
provides an interface for creating software interfaces from config objects.

Copyright 2014 Red Hat, Inc.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
olichtne@redhat.com (Ondrej Lichtner)
"""

import re
import select
import socket
import logging
<<<<<<< HEAD
import ethtool
from lnst.Slave.NetConfigDevice import NetConfigDevice
=======
from collections import deque
>>>>>>> jpirko/master
from lnst.Slave.NetConfigCommon import get_option
from lnst.Common.NetUtils import normalize_hwaddr
from lnst.Common.ExecCmd import exec_cmd
from lnst.Common.ConnectionHandler import recv_data
from lnst.Common.DeviceError import DeviceNotFound, DeviceConfigError, DeviceDeleted
from lnst.Common.InterfaceManagerError import InterfaceManagerError
from lnst.Slave.DevlinkManager import DevlinkManager
from pyroute2 import IPRSocket
from pyroute2.netlink import NLM_F_REQUEST, NLM_F_DUMP
from pyroute2.netlink.rtnl import RTMGRP_IPV4_IFADDR
from pyroute2.netlink.rtnl import RTMGRP_IPV6_IFADDR
from pyroute2.netlink.rtnl import RTMGRP_LINK
from pyroute2.netlink.rtnl import RTM_NEWLINK
from pyroute2.netlink.rtnl import RTM_GETLINK
from pyroute2.netlink.rtnl import RTM_DELLINK
from pyroute2.netlink.rtnl import RTM_NEWADDR
from pyroute2.netlink.rtnl import RTM_GETADDR
from pyroute2.netlink.rtnl import RTM_DELADDR

NL_GROUPS = RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR | RTMGRP_LINK

class InterfaceManager(object):
    def __init__(self, server_handler):
        self._device_classes = {}

        self._devices = {} #ifindex to device

        self._nl_socket = IPRSocket()
        self._nl_socket.bind(groups=NL_GROUPS)

        self._msg_queue = deque()

        #TODO split DevlinkManager away from the InterfaceManager
        #self._dl_manager = DevlinkManager()

        self._server_handler = server_handler

    def clear_dev_classes(self):
        self._device_classes = {}

    def add_device_class(self, name, cls):
        if name in self._device_classes:
            raise InterfaceManagerError("Device class name conflict %s" % name)

        self._device_classes[name] = cls
        return cls

    def reconnect_netlink(self):
        if self._nl_socket != None:
            self._nl_socket.close()
            self._nl_socket = None
        self._nl_socket = IPRSocket()
        self._nl_socket.bind(groups=NL_GROUPS)

        self.rescan_devices()

    def get_nl_socket(self):
        return self._nl_socket

    def pull_netlink_messages_into_queue(self):
        try:
            while True:
                rl, wl, xl = select.select([self._nl_socket], [], [], 0)
                if not len(rl):
                    break
                self._msg_queue.extend(self._nl_socket.get())
        except socket.error:
            self.reconnect_netlink()
            return []

    def rescan_devices(self):
        self.request_netlink_dump()
        self.handle_netlink_msgs()

    def request_netlink_dump(self):
        self._nl_socket.put(
            None, RTM_GETLINK, msg_flags=NLM_F_REQUEST | NLM_F_DUMP
        )
        self._nl_socket.put(
            None, RTM_GETADDR, msg_flags=NLM_F_REQUEST | NLM_F_DUMP
        )

    def handle_netlink_msgs(self):
        self.pull_netlink_messages_into_queue()

        while len(self._msg_queue):
            msg = self._msg_queue.popleft()
            self._handle_netlink_msg(msg)

        # self._dl_manager.rescan_ports()
        # for device in self._devices.values():
            # dl_port = self._dl_manager.get_port(device.name)
            # device._set_devlink(dl_port)

    def _handle_netlink_msg(self, msg):
        if msg['header']['type'] in [RTM_NEWLINK, RTM_NEWADDR, RTM_DELADDR]:
            if msg['index'] in self._devices:
                self._devices[msg['index']]._update_netlink(msg)
            elif msg['header']['type'] == RTM_NEWLINK:
                dev = self._device_classes["Device"](self)
                dev._init_netlink(msg)
                self._devices[msg['index']] = dev

                update_msg = {"type": "dev_created",
                              "dev_data": dev._get_if_data()}
                self._server_handler.send_data_to_ctl(update_msg)

                dev._disable()
        elif msg['header']['type'] == RTM_DELLINK:
            if msg['index'] in self._devices:
                dev = self._devices[msg['index']]
                dev._deleted = True

                del self._devices[msg['index']]

                del_msg = {"type": "dev_deleted",
                           "ifindex": msg['index']}
                self._server_handler.send_data_to_ctl(del_msg)
        else:
            return

    def untrack_device(self, dev):
        if dev.ifindex in self._devices:
            del self._devices[dev.ifindex]

    def get_device(self, ifindex):
        self.rescan_devices()
        if ifindex in self._devices:
            return self._devices[ifindex]
        else:
            raise DeviceNotFound()

    def get_devices(self):
        self.rescan_devices()
        return list(self._devices.values())

    def get_device_by_hwaddr(self, hwaddr):
        self.rescan_devices()
        for dev in list(self._devices.values()):
            if dev.hwaddr == hwaddr:
                return dev
        raise DeviceNotFound()

    def get_device_by_name(self, name):
        self.rescan_devices()
        for dev in list(self._devices.values()):
            if dev.name == name:
                return dev
        raise DeviceNotFound()

    def get_device_by_params(self, params):
        self.rescan_devices()
        matched = None
        for dev in list(self._devices.values()):
            matched = dev
            dev_data = dev.get_if_data()
            for key, value in params.items():
                if key not in dev_data or dev_data[key] != value:
                    matched = None
                    break

            if matched:
                break

        return matched

    def deconfigure_all(self):
        for dev in self._devices.values():
            pass
            # dev.clear_configuration()

    def create_device(self, clsname, args=[], kwargs={}):
        devcls = self._device_classes[clsname]

        try:
            device = devcls(self, *args, **kwargs)
        except KeyError as e:
            raise DeviceConfigError("%s is a mandatory argument" % e)
        device._create()
        device._bulk_enabled = False

        self.request_netlink_dump()
        self.pull_netlink_messages_into_queue()

        device_found = False
        while len(self._msg_queue):
            msg = self._msg_queue.popleft()
            if msg.get_attr("IFLA_IFNAME") == device.name:
                device_found = True
                device._init_netlink(msg)
                self._devices[msg['index']] = device
            else:
                self._handle_netlink_msg(msg)

        if device_found:
            return device
        else:
            raise DeviceError("Device creation failed")

    def replace_dev(self, if_id, dev):
        del self._devices[if_id]
        self._devices[if_id] = dev

    def _is_name_used(self, name):
        self.rescan_devices()
        for device in self._devices.values():
            if name == device.name:
                return True

        out, _ = exec_cmd("ovs-vsctl --columns=name list Interface",
                          log_outputs=False, die_on_err=False)
        for line in out.split("\n"):
            m = re.match(r'.*: \"(.*)\"', line)
            if m is not None:
                if name == m.group(1):
                    return True
        return False

    def assign_name(self, prefix):
        index = 0
        while (self._is_name_used(prefix + str(index))):
            index += 1
        return prefix + str(index)

    def _assign_name_pair(self, prefix):
        index1 = 0
        index2 = 0
        while (self._is_name_used(prefix + str(index1))):
            index1 += 1
        index2 = index1 + 1
        while (self._is_name_used(prefix + str(index2))):
            index2 += 1
        return prefix + str(index1), prefix + str(index2)
<<<<<<< HEAD

    def assign_name(self, config):
        if "name" in config:
            return config["name"]
        dev_type = config["type"]
        if dev_type == "eth":
            if (not "hwaddr" in config or
                "name" in config):
                return
            hwaddr = normalize_hwaddr(config["hwaddr"])
            for dev in self._devices:
                if dev.get_hwaddr() == hwaddr:
                    return dev.get_name()
        elif dev_type == "bond":
            return self.assign_name_generic("t_bond")
        elif dev_type == "bridge" or dev_type == "ovs_bridge":
            return self.assign_name_generic("t_br")
        elif dev_type == "macvlan":
            return self.assign_name_generic("t_macvlan")
        elif dev_type == "team":
            return self.assign_name_generic("t_team")
        elif dev_type == "vlan":
            netdev_name = self.get_mapped_device(config["slaves"][0]).get_name()
            vlan_tci = get_option(config, "vlan_tci")
            prefix = "%s.%s_" % (netdev_name, vlan_tci)
            return self.assign_name_generic(prefix)
        elif dev_type == "veth":
            return self._assign_name_pair("veth")
        elif dev_type == "vti":
            return self.assign_name_generic("vti")
        elif dev_type == "vti6":
            return self.assign_name_generic("t_ip6vti")
        elif dev_type == "vxlan":
            return self.assign_name_generic("vxlan")
        elif dev_type == "gre":
            return self.assign_name_generic("gre_")
        elif dev_type == "ipip":
            return self.assign_name_generic("ipip_")
        elif dev_type == "dummy":
            return self.assign_name_generic("dummy_")
        else:
            return self.assign_name_generic("dev")

class Device(object):
    def __init__(self, if_manager):
        self._initialized = False
        self._configured = False
        self._created = False
        self._addr_setup = False

        self._if_index = None
        self._hwaddr = None
        self._name = None
        self._conf = None
        self._conf_dict = None
        self._ip_addrs = []
        self._ifi_type = None
        self._state = None
        self._master = {"primary": None, "other": []}
        self._slaves = []
        self._netns = None
        self._peer = None
        self._mtu = None
        self._driver = None
        self._devlink = None

        self._if_manager = if_manager

    def set_devlink(self, devlink_port_data):
        self._devlink = devlink_port_data

    def init_netlink(self, nl_msg):
        self._if_index = nl_msg['index']
        self._ifi_type = nl_msg['ifi_type']
        self._hwaddr = normalize_hwaddr(nl_msg.get_attr("IFLA_ADDRESS"))
        self._name = nl_msg.get_attr("IFLA_IFNAME")
        self._state = nl_msg.get_attr("IFLA_OPERSTATE")
        self._ip_addrs = []
        self.set_master(nl_msg.get_attr("IFLA_MASTER"), primary=True)
        self._netns = None
        self._mtu = nl_msg.get_attr("IFLA_MTU")

        if self._driver is None:
            self._driver = self._ethtool_get_driver()

        self._initialized = True

        #return an update message that will be sent to the controller
        return {"type": "if_update",
                "if_data": self.get_if_data()}

    def update_netlink(self, nl_msg):
        if self._if_index != nl_msg['index']:
            return None
        if nl_msg['header']['type'] == RTM_NEWLINK:
            self._ifi_type = nl_msg['ifi_type']
            self._hwaddr = normalize_hwaddr(nl_msg.get_attr("IFLA_ADDRESS"))
            self._name = nl_msg.get_attr("IFLA_IFNAME")
            self._state = nl_msg.get_attr("IFLA_OPERSTATE")
            self.set_master(nl_msg.get_attr("IFLA_MASTER"), primary=True)
            self._mtu = nl_msg.get_attr("IFLA_MTU")

            if nl_msg.get_nested("IFLA_LINKINFO", "IFLA_INFO_KIND") == "vxlan":
                link = nl_msg.get_nested("IFLA_LINKINFO", "IFLA_INFO_DATA",
                                         "IFLA_VXLAN_LINK")
            elif nl_msg.get_nested("IFLA_LINKINFO", "IFLA_INFO_KIND") == "vti":
                link = nl_msg.get_nested("IFLA_LINKINFO", "IFLA_INFO_DATA",
                                         "IFLA_VTI_LINK")
            else:
                link = nl_msg.get_attr("IFLA_LINK")

            if link != None:
                # IFLA_LINK is an index of device that's closer to physical
                # interface in the stack, e.g. index of eth0 for eth0.100
                # so to properly deconfigure the stack we have to save
                # parent index in the child device; this is the opposite
                # to IFLA_MASTER
                link_dev = self._if_manager.get_device(link)
                if link_dev != None:
                    link_dev.set_master(self._if_index, primary=False)
                # This reference shouldn't change - you can't change the realdev
                # of a vlan, you need to create a new vlan. Therefore the
                # the following add_slave shouldn't be a problem.
                self.add_slave(link)

            if self._conf_dict:
                self._conf_dict["name"] = self._name

            if self._driver is None:
                self._driver = self._ethtool_get_driver()

            self._initialized = True
        elif nl_msg['header']['type'] == RTM_NEWADDR:
            scope = nl_msg['scope']
            addr_val = nl_msg.get_attr('IFA_ADDRESS')
            prefix_len = str(nl_msg['prefixlen'])
            addr = {"addr": addr_val,
                    "prefix": prefix_len,
                    "scope": scope}
            if self.find_addrs(addr) == []:
                self._ip_addrs.append(addr)
        elif nl_msg['header']['type'] == RTM_DELADDR:
            scope = nl_msg['scope']
            addr_val = nl_msg.get_attr('IFA_ADDRESS')
            prefix_len = str(nl_msg['prefixlen'])
            addr = {"addr": addr_val,
                    "prefix": prefix_len,
                    "scope": scope}
            matching_addrs = self.find_addrs(addr)
            for ip_addr in matching_addrs:
                self._ip_addrs.remove(ip_addr)

        #return an update message that will be sent to the controller
        return {"type": "if_update",
                "if_data": self.get_if_data()}

    def del_link(self):
        if self._master["primary"]:
            primary_id = self._master["primary"]
            primary_dev = self._if_manager.get_device(primary_id)
            if primary_dev:
                primary_dev.del_slave(self._if_index)

        for m_id in self._master["other"]:
            m_dev = self._if_manager.get_device(m_id)
            if m_dev:
                m_dev.del_slave(self._if_index)

        for dev_id in self._slaves:
            dev = self._if_manager.get_device(dev_id)
            if dev != None:
                dev.del_master(self._if_index)

    def find_addrs(self, addr_spec):
        ret = []
        for addr in self._ip_addrs:
            if addr_spec.items() <= addr.items():
                ret.append(addr)
        return ret

    def get_if_index(self):
        return self._if_index

    def get_hwaddr(self):
        return self._hwaddr

    def get_name(self):
        return self._name

    def get_ips(self):
        return self._ip_addrs

    def clear_ips(self):
        self._ip_addrs = []

    def is_configured(self):
        return self._configured

    def get_conf_dict(self):
        return self._conf_dict

    def set_peer(self, dev):
        self._peer = dev

    def get_peer(self):
        return self._peer

    def set_configuration(self, conf):
        self.clear_configuration()
        if "name" not in conf or conf["name"] == None:
            conf["name"] = self._name
        self._conf_dict = conf
        self._conf = NetConfigDevice(conf, self._if_manager)

        if not self._initialized:
            self._name = conf["name"]

    def get_configuration(self):
        return self._conf

    def del_configuration(self):
        self._conf = None
        self._conf_dict = None

    def _clear_tc_qdisc(self):
        try:
            #checks device existence as it might have been removed by
            #calling self.deconfigure()
            exec_cmd("ip l show %s" % self._name, log_outputs=False)
        except:
            return

        exec_cmd("tc qdisc del dev %s root" % self._name, die_on_err=False)
        out, _ = exec_cmd("tc filter show dev %s" % self._name)
        ingress_handles = re.findall("ingress (\\d+):", out)
        for ingress_handle in ingress_handles:
            exec_cmd("tc qdisc del dev %s handle %s: ingress" %
                     (self._name, ingress_handle))
        out, _ = exec_cmd("tc qdisc show dev %s" % self._name)
        ingress_qdiscs = re.findall("qdisc ingress (\\w+):", out)
        if len(ingress_qdiscs) != 0:
                exec_cmd("tc qdisc del dev %s ingress" % self._name)

    def _clear_tc_filters(self):
        try:
            #checks device existence as it might have been removed by
            #calling self.deconfigure()
            exec_cmd("ip l show %s" % self._name, log_outputs=False)
        except:
            return

        out, _ = exec_cmd("tc filter show dev %s" % self._name)
        egress_prefs = re.findall("pref (\\d+) .* handle", out)

        for egress_pref in egress_prefs:
            exec_cmd("tc filter del dev %s pref %s" % (self._name,
                     egress_pref))

    def clear_configuration(self):
        if self._master["primary"]:
            primary_id = self._master["primary"]
            primary_dev = self._if_manager.get_device(primary_id)
            if primary_dev:
                primary_dev.clear_configuration()

        for m_id in self._master["other"]:
            m_dev = self._if_manager.get_device(m_id)
            if m_dev and self._if_index not in m_dev.get_master()["other"]:
                m_dev.clear_configuration()

        if self._conf != None and self._configured:
            self.address_cleanup()
            self.down()
            self.deconfigure()
            self._clear_tc_qdisc()
            self._clear_tc_filters()
            self.destroy()
            self._conf = None
            self._conf_dict = None

    def set_master(self, if_index, primary=True):
        if primary:
            prev_master_id = self._master["primary"]
            if prev_master_id != None and if_index != prev_master_id:
                prev_master_dev = self._if_manager.get_device(prev_master_id)
                if prev_master_dev != None:
                    prev_master_dev.del_slave(self._if_index)

            self._master["primary"] = if_index
            if self._master["primary"] != None:
                master_id = self._master["primary"]
                master_dev = self._if_manager.get_device(master_id)
                if master_dev != None:
                    master_dev.add_slave(self._if_index)
        elif if_index not in self._master["other"]:
            self._master["other"].append(if_index)

    def get_master(self):
        return self._master

    def del_master(self, if_index):
        if self._master["primary"] == if_index:
            self._master["primary"] = None
        elif if_index in self._master["other"]:
            self._master["other"].remove(if_index)

    def add_slave(self, if_index):
        if if_index not in self._slaves:
            self._slaves.append(if_index)

    def del_slave(self, if_index):
        if if_index in self._slaves:
            self._slaves.remove(if_index)

    def create(self):
        if self._conf != None and not self._created:
            self._conf.create()
            self._created = True
            return True
        return False

    def destroy(self):
        if self._conf != None and self._created:
            self._conf.destroy()
            self._created = False
            return True
        return False

    def configure(self):
        if self._conf != None and not self._configured:
            self._conf.configure()
            self._configured = True

    def deconfigure(self):
        if self._master["primary"]:
            primary_id = self._master["primary"]
            primary_dev = self._if_manager.get_device(primary_id)
            if primary_dev:
                primary_dev.deconfigure()

        for m_id in self._master["other"]:
            m_dev = self._if_manager.get_device(m_id)
            if m_dev and self._if_index not in m_dev.get_master()["other"]:
                m_dev.deconfigure()

        if self._conf != None and self._configured:
            self._conf.deconfigure()
            self._configured = False

    def up(self):
        if self._conf != None:
            self._conf.up()
        else:
            exec_cmd("ip link set %s up" % self._name)

    def down(self):
        if self._conf != None:
            self._conf.down()
        else:
            exec_cmd("ip link set %s down" % self._name)

    def address_setup(self):
        if self._conf != None and self._configured and not self._addr_setup:
            self._conf.address_setup()
            self._addr_setup = True

    def address_cleanup(self):
        if self._conf != None and self._addr_setup:
            self._conf.address_cleanup()
            self._addr_setup = False

    def link_up(self):
        exec_cmd("ip link set %s up" % self._name)

    def link_down(self):
        exec_cmd("ip link set %s down" % self._name)

    def link_stats(self):
        stats = {"devname": self._name,
                 "hwaddr": self._hwaddr}
        try:
            out, _ = exec_cmd("ip -s link show %s" % self._name)
        except:
            return {}

        lines = iter(out.split("\n"))
        for line in lines:
            if (len(line.split()) == 0):
                continue
            if (line.split()[0] == 'vf'):
                break
            if (line.split()[0] == "RX:"):
                rx_stats = map(int, lines.next().split())
                stats.update({"rx_bytes"  : rx_stats[0],
                              "rx_packets": rx_stats[1],
                              "rx_errors" : rx_stats[2],
                              "rx_dropped": rx_stats[3],
                              "rx_overrun": rx_stats[4],
                              "rx_mcast"  : rx_stats[5]})
            if (line.split()[0] == "TX:"):
                tx_stats = map(int, lines.next().split())
                stats.update({"tx_bytes"  : tx_stats[0],
                              "tx_packets": tx_stats[1],
                              "tx_errors" : tx_stats[2],
                              "tx_dropped": tx_stats[3],
                              "tx_carrier": tx_stats[4],
                              "tx_collsns": tx_stats[5]})
        return stats

    def link_cpu_ifstat(self):
        stats = {"devname": self._name,
                 "hwaddr": self._hwaddr}
        try:
            out, _ = exec_cmd("ifstat -x c %s" % self._name)
        except:
            return {}
        lines = iter(out.split("\n"))
        line_first = ""
        line_decond = ""
        for line in lines:
            if (len(line.split()) == 0):
                continue
            if (line.split()[0] == self._name):
                break
        else:
            return {}
        stats_data = line.split()[1:]
        for i in range(len(stats_data)):
            stats_data[i] = stats_data[i].replace("K",  "000")
            stats_data[i] = stats_data[i].replace("M", "000000")

        stats_data = map(int, stats_data)
        stats["rx_packets"] = stats_data[0]
        stats["tx_packets"] = stats_data[2]
        stats["rx_bytes"] = stats_data[4]
        stats["tx_bytes"] = stats_data[6]
        return stats

    def set_addresses(self, ips):
        self._conf.set_addresses(ips)
        exec_cmd("ip addr flush %s scope global" % self._name)
        for address in ips:
            exec_cmd("ip addr add %s dev %s" % (address, self._name))

    def add_route(self, dest, ipv6):
        exec_cmd("ip %s route add %s dev %s" % ("-6" if ipv6 else "", dest, self._name))

    def del_route(self, dest, ipv6):
        exec_cmd("ip %s route del %s dev %s" % ("-6" if ipv6 else "", dest, self._name))

    def route_cmd(self, cmd, dest, nhs, ipv6):
        cmd = "ip %s route %s %s" % ("-6" if ipv6 else "", cmd, dest)
        for ns in nhs:
            cmd = cmd + (" \\\n   nexthop via %s" % ns)
        exec_cmd(cmd)

    def add_nhs_route(self, dest, nhs, ipv6):
        self.route_cmd("add", dest, nhs, ipv6)

    def del_nhs_route(self, dest, nhs, ipv6):
        self.route_cmd("del", dest, nhs, ipv6)

    def set_netns(self, netns):
        self._netns = netns
        return

    def get_netns(self):
        return self._netns

    def _ethtool_get_driver(self):
        if self._ifi_type == 772:  #loopback ifi type
            return 'loopback'
        out, _ = exec_cmd("ethtool -i %s" % self._name, False, False, False)
        match = re.search("^driver: (.*)$", out, re.MULTILINE)
        if match is not None:
            return match.group(1)
        else:
            return None

    def get_if_data(self):
        if_data = {"if_index": self._if_index,
                   "hwaddr": self._hwaddr,
                   "name": self._name,
                   "ip_addrs": self._ip_addrs,
                   "ifi_type": self._ifi_type,
                   "state": self._state,
                   "master": self._master,
                   "slaves": self._slaves,
                   "netns": self._netns,
                   "peer": self._peer.get_if_index() if self._peer else None,
                   "mtu": self._mtu,
                   "driver": self._driver,
                   "devlink": self._devlink}
        return if_data

    def set_speed(self, speed):
        exec_cmd("ethtool -s %s speed %s autoneg off" % (self._name, speed))

    def set_autoneg(self):
        exec_cmd("ethtool -s %s autoneg on" % self._name)

    def slave_add(self, if_id):
        if self._conf != None:
            self._conf.slave_add(if_id)

    def slave_del(self, if_id):
        if self._conf != None:
            self._conf.slave_del(if_id)

    def get_ethtool_stats(self):
        stdout, _ = exec_cmd("ethtool -S %s" % self._name)

        d = {}
        # First and last lines don't contain stats.
        for line in stdout.split('\n')[1:-1]:
            stat, count = line.split(':')
            d[stat.strip()] = int(count)
        return d

    def enable_lldp(self):
        self._conf.enable_lldp()
        exec_cmd("lldptool -i %s -L adminStatus=rxtx" % self._name)

    def set_pause_on(self):
        exec_cmd("ethtool -A %s rx on tx on autoneg off" % self._name,
                 die_on_err=False)

    def set_pause_off(self):
        exec_cmd("ethtool -A %s rx off tx off autoneg off" % self._name,
                 die_on_err=False)

    def set_mcast_flood(self, on = True):
        cmd = "ip link set dev %s type bridge_slave mcast_flood " % self._name
        if on:
            cmd += "on"
        else:
            cmd += "off"
        exec_cmd(cmd)

    def set_mcast_router(self, state):
        cmd = "ip link set dev %s type bridge_slave mcast_router %d" % \
                   (self._name, state)
        exec_cmd(cmd)

    def get_coalesce(self):
        try:
            return ethtool.get_coalesce(self._name)
        except IOError as e:
            logging.error("Failed to get coalesce settings: %s", e)
            return {}

    def set_coalesce(self, cdata):
        try:
            ethtool.set_coalesce(self._name, cdata)
        except IOError as e:
            logging.error("Failed to set coalesce settings: %s", e)
=======
>>>>>>> jpirko/master
