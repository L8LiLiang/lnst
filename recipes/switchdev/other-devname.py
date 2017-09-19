"""
Copyright 2016 Redhat. All rights reserved.
Licensed under the GNU General Public License, version 2 as
published by the Free Software Foundation; see COPYING for details.
"""

__author__ = """
liali@redhat.com (Li Liang)
"""

# Description:
#       Make sure the interface default name don't change from distro to distro
# 
# Relateds bug:
#       https://bugzilla.redhat.com/show_bug.cgi?id=1477285
# 
# Test method:
#       1.after running this test,the interface name will be stored in database
#       2.you need to run this test one time first on a benchmark version to generate the benchmark interface name
#       3.this test will compare the current interface name with the name stored in database
#               if equal,                           pass
#               if not eauql,                       fail
#               if can't get vf name from database, pass
#       4.database table desc:
#               +--------+------------------+------+-----+---------+----------------+
#               | Field  | Type             | Null | Key | Default | Extra          |
#               +--------+------------------+------+-----+---------+----------------+
#               | id     | int(10) unsigned | NO   | PRI | NULL    | auto_increment |
#               | distro | varchar(20)      | YES  |     | NULL    |                |
#               | driver | varchar(20)      | YES  |     | NULL    |                |
#               | host   | varchar(100)     | YES  |     | NULL    |                |
#               | mac    | varchar(40)      | YES  |     | NULL    |                |
#               | vfidx  | varchar(3)       | YES  |     | NULL    |                |
#               | ifname | varchar(50)      | YES  |     | NULL    |                |
#               +--------+------------------+------+-----+---------+----------------+
#         note: the vfidx column is not used by this case


from lnst.Controller.Task import ctl
from TestLib import TestLib
from time import sleep
import re
import random
import MySQLdb
import operator

class DBManager:

    def __init__(self,host="10.66.12.166",user="guest",passwd="Redhat@123",database="work",table="dev_name"):
        self.host = host
        self.user = user
        self.passwd = passwd
        self.database = database
        self.table = table
        self.conn = MySQLdb.connect(
                host = host,
                user = user,
                passwd = passwd,
                db = database)

    def get_devname(self,distro,driver,machine,mac):
        cur=self.conn.cursor()
        search="""driver='%s' and distro='%s' and host='%s' and mac='%s'""" %(driver,distro,machine,mac)
        cmd="""select ifname from %s where %s""" %(self.table,search)
        record_sum=cur.execute(cmd)
        if record_sum==0:
            return "null"
        else:
            record=cur.fetchone()
            return record[0]
 
    def new_devname(self,distro,driver,machine,mac,ifname):
        cur=self.conn.cursor()
        search="""driver='%s' and distro='%s' and host='%s' and mac='%s'""" %(driver,distro,machine,mac)
        old_devname = self.get_devname(distro,driver,machine,mac)
        if old_devname=="null":
            cur.execute("""insert into %s (driver,distro,host,mac,ifname) values('%s','%s','%s','%s','%s')""" %(self.table,driver,distro,machine,mac,ifname))
        else:
            cur.execute("""update %s set ifname='%s' where %s""" %(self.table,ifname,search))
        self.conn.commit()
    
    def __del__(self):
        self.conn.close()

def do_task(ctl, hosts, ifaces, aliases):
    tl = TestLib(ctl, aliases)
    sw = hosts
    sw_if1, sw_if2, = ifaces

    sw_if1_mac = sw_if1.get_hwaddr()
    sw_if2_mac = sw_if2.get_hwaddr()

    sw_if1_devname = str(sw_if1.get_devname())
    sw_if2_devname = str(sw_if2.get_devname())

    dbm = DBManager()

    current_distro = sw.run("cat /etc/redhat-release | awk  '{print $7}'").out().strip()
    pre_distro = str(float(current_distro) - 0.1)
    hostname = sw.run("hostname|head -n 1").out().strip()
    sw_if1_devname_old = dbm.get_devname(pre_distro,sw_if1.get_driver(),hostname,sw_if1_mac)
    sw_if2_devname_old = dbm.get_devname(pre_distro,sw_if2.get_driver(),hostname,sw_if2_mac)
    
    if sw_if1_devname_old != "null" and sw_if1_devname_old != sw_if1_devname:
        failMod = ctl.get_module("DummyFailing")
        print "devname check failed, %s vs %s" %(sw_if1_devname,sw_if1_devname_old)
        sw.run(failMod)
        
    dbm.new_devname(current_distro,sw_if1.get_driver(),hostname,sw_if1_mac,sw_if1_devname)


do_task(ctl, ctl.get_host("switch"),
        [ctl.get_host("switch").get_interface("if1"),
         ctl.get_host("switch").get_interface("if2")],
        ctl.get_aliases())
