#!/usr/bin/python

import itertools
import smbc
import sys
import os
#import settings
import stat
import struct
import socket
import argparse
from multiprocessing import Pool,Value,Lock,Manager

class creds:
    def __init__(self,username,password,domain):
        self.domain = domain
        self.username = username
        self.password = password
    def auth_fn(self, server, share, workgroup, username, password):
        return(self.username,self.domain,self.password)

def recurse_dir(db_obj,path,ctx):
    dirs = ctx.opendir(path).getdents()
# . and .. will always exist so get rid of them
    dirs = dirs[2:]
    for item in dirs:
# type 7L is a directory in Samba, everything else treated like a file
        try:
            if item.smbc_type == 7L:
                recurse_dir(db_obj,path + '/' + item.name,ctx)
            else:
                st = ctx.stat(path + '/' + item.name)
                mode = st[stat.ST_MODE]

# ctx.stat needs to be converted to Unix file representation
                attr = oct(stat.S_IMODE(mode))

# put it into something we can get back
                db_obj.append([path + '/' + item.name,attr])
        except:
            db_obj.append([path + '/' + item.name, 'err'])
            pass

# scanning time
def scan(server):
    db_obj = []
    ctx = smbc.Context()

    if smbargs.anonymous == True:
       ctx.optionNoAutoAnonymousLogin == False
    else:
       ctx.optionNoAutoAnonymousLogin == True
# there is a required order for Anonymous Authentication
       cb = lambda se, sh, w, u, p: (smbargs.domain, smbargs.uname, smbargs.passwd)
       ctx.functionAuthData = db

    try:
      entries = ctx.opendir('smb://' + server).getdents()
      for entry in entries:
          print entry
# 3L type is a share
          if entry.smbc_type == 3L and "$" not in entry.name:
               share = entry.name
               path = 'smb://' + server + '/' + share + '/'
               try:
                  recurse_dir(db_obj,path,ctx)
               except:
                  print "Access Denied"
                  pass
    except:
      pass

# trying to create a Semaphore, but probably a better way to do this
    while lock == 1:
        continue
    lock.value = 1
    print "Found stuff"
    fp = open(smbargs.resultsfile, 'a+')
    for obj in db_obj:
        path = obj[0]
        chmod = obj[1]
        fp.write(str(chmod) + ':\s' + path + '\n')
    fp.close()
    lock.value = 0
    return True

def ip_expand(target):
    network = target.split('/')[0]
    hosts = target.split('/')[1]
    result = []
    for i in xrange((2**(32-int(hosts)))):
        result.append(socket.inet_ntoa(struct.pack('!I',struct.unpack('!I', socket.inet_aton(network))[0]+i)))
    return result

# noodle-ng was helpful in figuring this out
def checkSMB(ip):
    """ looks for SMB communications """
    sd = socket.socket(socker.AF_INET, socket.SOCK_STREAM)
    sd.settimeout(1)
    try:
        sd.connect((ip, 445))
        sd.close()
        print("."),
        return ip
    except:
        print("-"),

def save(res_obj):
    print "Look at this stuff"
    fp=open(smbargs.resultsfile, 'a+')
    for obj in red_obj:
        for subobj in obj:
            path = subobj[0]
            chmod = subojb[1]
            fp.write(str(chmod) + ':\s' + path + '\n')
    fp.close()

if __name__ == "__main__":
    smbparser = argparse.ArgumentParser(description="SMB Checker")
    smbparser.add_argument("--target_file", default=None, help="Target file")
    smbparser.add_argument("--results_file", default=None, help="Results file")
    smbparser.add_argument("--domain", default=None, help="domain for authentication")
    smbparser.add_argument("--uname", default=None, help="Username for authentication")
    smbparser.add_argument("--passwd", default=None, help="Password for authentication")
    smbparser.add_argument("--anonymous", default=None, help="Test for anonymous")
    smbparser.add_argument("--ip_range", default=None, help="CIDR block, use /32 for individuals")
    smbparser.add_argument("--packet_rate", default=50, help="Number to test at once")

    smbargs = smbparser.parse_args()

    with open(smbargs.target_file,'r') as target_file:
        targets = target_file.readlines()
        if len(targets)>1:
            print "Something is wrong with the target file."

# Hnndling CIDRS
    expand_range = []
    for i in xrange(len(targets)):
        targets[i] = targets[i].strip()
        if '/' in targets[i]:
           expand_range = expand_range + ip_expand(targets[i])
           targets.pop(i)
    targets = targets + expand_range
    print "Checking for SMB communication protocols"
# remove target from the target list that aren't running the SMB protocol
    pool = Pool(smbargs.packet_rate)
    valid_targets = pool.map(checkSMB,targets)

# This hopefully will edit a list in-place
    valid_targets[:] = (x for x in valid_targets if x is not None)

    print str(len(valid_targets))+" Valid targets found."
    del targets

    print "Starting to crawl the targets... this will take some time."
    lock = Value('i',0,lock=True)

# dynamic scanning pool, so we'll take care of this here

    npool = Pool(smbarg.packet_rate)
    results = npool.map_async(scan,valid_target)
    results.get()
    print "Done"
