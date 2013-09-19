#!/usr/bin/python

import itertools
import smbc
import sys
import os
import settings
import stat
import struct
import socket
from multiprocessing import Pool
from multiprocessing import Value,Lock,Manager

class creds:
    def __init__(self,username,password,domain):
        self.domain = domain
        self.username = username
        self.password = password
    def auth_fn(self, server, share, workgroup, username, password):
        return (self.username,self.domain,self.password)

def recurse_dir(db_obj,path,ctx):
    dirs = ctx.opendir(path).getdents()
    # Scrape off the two leading entries (which are . and ..)
    dirs = dirs[2:]
    for item in dirs:
        # Type 7L is a directory, everything else i'm treating like a file
        try:
            if item.smbc_type == 7L:
                recurse_dir(db_obj,path+'/'+item.name,ctx)
            else:
                st = ctx.stat(path+'/'+item.name)
                mode = st[stat.ST_MODE]
                # Convert things into unix file perm representation
                attr = oct(stat.S_IMODE(mode))
                # put it into the object holding a list of all the files.
                db_obj.append([path+'/'+item.name,attr])
        except:
            db_obj.append([path+'/'+item.name,'err'])
            pass

# Where the magic happens
def scan(server):
    db_obj = []
    ctx = smbc.Context()
    ctx.optionNoAutoAnonymousLogin = True
    # You want to do it this way otherwise things get out of order???
    cb = lambda se, sh, w, u, p: (settings.DOMAIN, settings.USERNAME, settings.PASSWORD)
    ctx.functionAuthData = cb
    try:
        entries = ctx.opendir('smb://'+server).getdents()
        for entry in entries:
            print entry
            # 3L type is a share
            if entry.smbc_type == 3L and "$" not in entry.name:
                 share = entry.name
                 path = 'smb://'+server+'/'+share+'/'
                 try:
                     recurse_dir(db_obj,path,ctx)
                 except:
                     print "Access Denied or something broke"
                     pass
    except:
        pass

    #Poor man's semaphore
    while lock == 1:
        continue
    lock.value = 1
    print "SAVE"
    fp=open(settings.OUTPUT_FILE,'a+')
    for obj in db_obj:
        path = obj[0]
        chmod = obj[1]
        fp.write(str(chmod) + "\t" + path + '\n')
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
        
# Borrowed the below function from noodle-ng https://code.google.com/p/noodle-ng/  
def checkSMB(ip):
    """ looks for running samba server """
    # check if the server is running a smb server
    sd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # This may need to get changed on high-latency links...
    sd.settimeout(1)
    try:
        sd.connect((ip, 445))
        sd.close()
        print("."),
        return ip
    except:
        print("-"),

def save(res_obj):
    #pdb.set_trace()
    print "SAVE"
    fp=open(settings.OUTPUT_FILE,'a+')
    for obj in res_obj:
        for subobj in obj:
            path = subobj[0]
            chmod = subobj[1]
            fp.write(str(chmod) + "\t" + path + '\n')
    fp.close()    

if __name__ == "__main__":
    if len(sys.argv)>1:
        print "Python Share Scanner v1 -- Bryan 'Crypt0s' Halfpap"
        print "Usage:"
        print "./scanner.py"
        print "All settings and documentation for settings are found in settings.py"

    # Settings housekeeping
    if settings.TARGET_LIST is None:
        print "You don't have a target list specified"
        exit()
    with open(settings.TARGET_LIST,'r') as target_list:
        targets = target_list.readlines()
        if len(targets)>1:
            print "You did not specify anything to scan in your target file."



    # Handles any network ranges in the target list.
    expanded_range = []
    for i in xrange(len(targets)):
        targets[i] = targets[i].strip()
        if '/' in targets[i]:
            expanded_range = expanded_range + ip_expand(targets[i])
            targets.pop(i)
    targets = targets + expanded_range
    print "Checking for SMB servers on target hosts"
    # remove targets from the target list that aren't running the SMB server process.
    pool = Pool(50)
    valid_targets = pool.map(checkSMB,targets)

    # This is a neat tidbit for editing a list in-place
    valid_targets[:] = (x for x in valid_targets if x is not None)

    print str(len(valid_targets))+" Valid targets found."
    del targets

    print "Starting to crawl the targets...this will take a while."
    # Cheap semaphore
    lock = Value('i',0,lock=True)
    
    # Scanner pool - creates one scan thread for each host -- this can get slow if you have very few file shares with lots of files.
    npool = Pool(settings.MAX_THREADS)
    results = npool.map_async(scan,valid_targets)
    results.get()
    print "Finished scanning"
