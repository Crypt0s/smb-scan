#!/usr/bin/python

import smbc
import sys
import os
import stat
import struct
import argparse
from socket import *
from multiprocessing import Pool, Value, Lock, Manager

class creds:
    def __init__(self, username, password, domain):
        self.domain = domain
        self.username = username
        self.password = password
    def auth_fn(self, server, share, workgroup, username, password):
        return(self.username, self.domain, self.password)

def recurse_dir(path_obj, path, ctx):
    dirs = ctx.opendir(path).getdents()
# attempting to remove . and .. since we know this is always there
    dirs = dirs[2:]
    for dir in dirs:
# type 7L represents a directory in SMB, everything else is treated like a file
        try:
            if dir.smbc_type == 7L:
                recurse_dir(path_obj, path + '/' + dir.name, ctx)
            else:
                ctxobj = ctx.stat(path + '/' + dir.name)
                mode = ctxobj[st.ST_MODE]
# now convert ctx.stat to unix mode
                attr = oct(stat.S_IMODE(mode))

# put it into something we can use later
                path_obj.append([path + '/' + dir.name, attr])
        except:
            path_obj.append([path + '/' + dir.name, 'err'])
            pass

# scanning time... I hope
def smbscan(server):
    path_obj = []
    ctx = smbc.Context()

    if smbargs.anonymous == True:
        ctx.optionNoAutoAnonymousLogin == False
    else:
        ctx.optionNoAutoAnonymousLogin == True
# there is a required order for Anonymous Authentication.  i found this lambda action somewhere.
        cb = lambda se, sh, w, u, p: (smbargs.domain, smbargs.uname, smbargs.passwd)
        ctx.functionAuthData = cb

# trying to separate 3L entries which are shares instead of directories
    try:
        entries = ctx.opendir('smb://' + server).getdents() 
        if entry.smbc_type == 3L and "$" not in entry.name:
            share = entry.name
            path = 'smb://' + server + '/' + share + '/'
            try:
                recurse_dir(path_obj, path, ctx)
            except:
                print "Access Denied"
                pass
    except:
        pass

# tryaing a semaphore, so hopefully this will work
    while lock == 1:
        continue
    lock.value = 1
    print "Writing SMB Records"
    fp = open(smbargs.results_file, 'a+')
    for obj in path_obj:
         path = obj[0]
         chmod = obj[1]
         fp.write(str(chmod) + ':\s' + path + '\n')
    fp.close()
    lock.value = 0
    return True

def PortScan(ip):
    connector = socket(AF_INET, SOCK_STREAM)
    connector.connect((ip, 445))
    connector.send('Friendly Portscanner\r\n')
    connector.close()
    print("."),
    return ip

def save(res_obj):
    print "Does this get anywhere"
    fp=open(smbargs.results_file, 'a+')
    for obj in res_obj:
        path = subobj[0]
        chmod = subobj[1]
        fp.write(str(chmod) + ':\s' + path + '\n')
    fp.close()

if __name__ == "__main__":
    smbparser = argparse.ArgumentParser(description="SMB Checker")
    smbparser.add_argument("-target_file", type=str, help="Target file")
    smbparser.add_argument("-results_file", type=str, help="Results file")
    smbparser.add_argument("-domain", type=str, help="domain for authentication")
    smbparser.add_argument("-uname", type=str, help="Username for authentication")
    smbparser.add_argument("-passwd", type=str, help="Password for authentication")
    smbparser.add_argument("-anonymous", default=False, type=str, help="Use True to test for Anonymous access.")
#    smbparser.add_argument("--ip_range", type=str, help="CIDR block, use /32 for individuals")
    smbparser.add_argument("-packet_rate", default=50, type=int, help="Number to test at once")

    smbargs = smbparser.parse_args()

    print smbargs.target_file

    with open(smbargs.target_file, mode='r', buffering=1) as targets_file:
        targets = targets_file.readlines()
        if len(targets)>1:
           print "Something is wrong with the target file."

# Handling CIDRS
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
    valid_targets = pool.map(checkSMB, targets)

# This hopefully will edit a list in-place
    valid_targets[:] = (x for x in valid_targets if x is not None)
    print valid_targets
    print str(len(valid_targets))+" Valid targets found."
    del targets

    print "Starting to crawl the targets... this will take some time."
    lock = Value('i',0,lock=True)

# dynamic scanning pool, so we'll take care of this here

    npool = Pool(smbargs.packet_rate)
    results = npool.map_async(scan,valid_targets)
    results.get()
    print "Done"
