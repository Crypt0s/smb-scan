#!/usr/bin/python

import smbc
import sys
import os
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
        for entry in entries:
            print entry 
    except:
        pass

# trying a semaphore, so hopefully this will work
    while lock == 1:
        continue
    lock.value = 1
#    print "Writing SMB Records"
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
    connector.settimeout(1)
    try:
        connector.connect((ip, 445))
        connector.send('Friendly Portscanner\r\n')
        smbbg = connector.recv(2048)
        connector.close()
        print("+ " + smbbg + '\n')
        return ip
    except:
        print("- " + ip + "- Port 445 Closed")
        return ip

if __name__ == "__main__":
    smbparser = argparse.ArgumentParser(description="SMB Checker")
    smbparser.add_argument("-target_file", type=str, help="Target file")
    smbparser.add_argument("-results_file", type=str, help="Results file")
    smbparser.add_argument("-domain", type=str, help="domain for authentication")
    smbparser.add_argument("-uname", type=str, help="Username for authentication")
    smbparser.add_argument("-passwd", type=str, help="Password for authentication")
    smbparser.add_argument("-anonymous", default=False, type=str, help="Use True to test for Anonymous access.")
#    smbparser.add_argument("--ip_range", type=str, help="CIDR block, use /32 for individuals")
    smbparser.add_argument("-packet_rate", default=1, type=int, help="Number to test at once")

    smbargs = smbparser.parse_args()

#    print smbargs.target_file

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
                 print "Checking for communication"

    pool = Pool(smbargs.packet_rate)
    valid_targets = pool.map(PortScan, targets)

    valid_targets[:] = (x for x in valid_targets if x is not None)
    print valid_targets
    print "Starting to crawl the targets... this will take some time."
    lock = Value('i',0,lock=True)

# dynamic scanning pool, so we'll take care of this here

    npool = Pool(smbargs.packet_rate)
    results = npool.map_async(smbscan, valid_targets)
    results.get()
    print "Done"
