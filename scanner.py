#!/usr/bin/python

import smbc
import sys
import os
import pdb
import settings
import stat
#import thread
#import threading
import struct
import socket
from multiprocessing import Pool
import psycopg2

#import multiprocessing, logging

class creds:
    def __init__(self,username,password,domain):
        self.domain = domain
        self.username = username
        self.password = password
    def auth_fn(self, server, share, workgroup, username, password):
        #return (self.domain,self.username,self.password)
        return (self.username,self.domain,self.password)
        #return (self.password,self.domain,self.username)

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
                attr = stat.S_IMODE(mode)
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
    entries = ctx.opendir('smb://'+server).getdents()

    for entry in entries:
        print entry
        # 3L type is a share
        if entry.smbc_type == 3L and "$" not in entry.name:
             share = entry.name
             path = 'smb://'+server+'/'+share+'/'
             try:
                 #thread.start_new_thread(recurse_dir,(db_obj,path,ctx))
                 recurse_dir(db_obj,path,ctx)
             except:
                 print "Access Denied or something broke"
                 pass
    return db_obj    

def ip_expand(target):
    network = target.split('/')[0]
    hosts = target.split('/')[1]
    result = []
    for i in xrange((2**32-int(hosts))):
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
        return True
    except:
        return False

#class db_connection:
#    def __init__(self,db_enable):
#        self.db_enable = db_enable
#        if self.db_enable:
#            self.connection = psycopg2.connect(host=settings.DB_SRV dbname=settings.DB_DBASE user=settings.DB_USER password=settings.DB_PASS)
#
#    def save(db_obj):
#        if self.db_enable:
#            cursor = conn.cursor()
#            cursor.execute("INSERT INTO results 
#        else:
#            output_file = open(settings.OUTPUT_FILE,'a+')
#            for obj in db_obj:
#                path = obj[0]
#                attr = obj[1]
#                output_file.write(path+':'+str(attr)+'\n')
def save(res_obj):
    for obj in res_obj[0]:
        path = obj[0]
        chmod = obj[1]
        fp.write(str(chmod) + "\t" + path + '\n')

if __name__ == "__main__":
    # TODO: allow this to be set from a configuration file or on cmdline

    #if settings.SERVER is not None and settings.TARGET_LIST is not None:
    #    print "Please either scan a single server or a list of servers.  Modify settings.py"
    
    if len(sys.argv)>1:
        print "Python Share Scanner v1 -- Bryan 'Crypt0s' Halfpap"
        print "Usage:"
        print "./scanner.py"
        print "All settings and documentation for settings are found in settings.py"

    # I'm using a giant list right now but obviously there's room for improvement by using something like ZODB or Postgres.
    db_obj = []
    # Will the db_obj as a list need a mutex for access?  Who knows...

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
        targets = targets + expanded_range

        # remove targets from the target list that aren't running the SMB server process.
        for x in xrange(len(targets)):
            if checkSMB(targets[x]) is False:
                targets.pop(x)
            #scan(targets[x])
    #database_stub = db_connection(settings.DB_ENABLE)
    print "Starting to scan the ranges...this will take a while."
    pool = Pool(settings.MAX_THREADS)
    fp = open(settings.OUTPUT_FILE,'a+')
    results = pool.map_async(scan,targets,None,save)
    results.get()
    print "Finished scanning"
    fp.close()
