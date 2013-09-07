#!/usr/bin/python

import smbc
import sys
import os
import pdb
import settings
import stat
#import thread
import threading

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
def scan(server,db_obj):
    server = '10.50.70.181'
    ctx = smbc.Context()
    ctx.optionNoAutoAnonymousLogin = True
    # You want to do it this way otherwise things get out of order???
    cb = lambda se, sh, w, u, p: (settings.DOMAIN, settings.USERNAME, settings.PASSWORD)
    ctx.functionAuthData = cb
    entries = ctx.opendir('smb://'+server).getdents()
    #db_obj = []
    #threads = []
    #thread_array = []
    #thread_lock = 1
    for entry in entries:
        #print entry
        # 3L type is a share
        if entry.smbc_type == 3L and "$" not in entry.name:
             share = entry.name
             path = 'smb://'+server+'/'+share+'/'
             try:
                 recurse_dir(db_obj,path,ctx)
                 #t = threading.Thread(target=recurse_dir,args=(db_obj,path,ctx))
                 #t.daemon = True
                 #t.start()
                 #thread_array.append(t)
                 #thread_lock-=1
                 #print str(len(thread_array))
                 #if thread_lock == 0:
                 #    thread_array[0].join()
                 #    thread_lock+=1
                 #    thread_array.pop(0)

             except:
                 print "Access Denied or something broke"
                 pass
    return db_obj    


if __name__ == "__main__":
    # TODO: allow this to be set from a configuration file or on cmdline

    if settings.SERVER is not None and settings.TARGET_LIST is not None:
        print "Please either scan a single server or a list of servers.  Modify settings.py"
    
    if len(sys.argv)>1:
        print "Python Share Scanner v1 -- Bryan 'Crypt0s' Halfpap"
        print "Usage:"
        print "./scanner.py"
        print "All settings and documentation for settings are found in settings.py"

    # I'm using a giant list right now but obviously there's room for improvement by using something like ZODB or Postgres.
    db_obj = []
    # Will the db_obj as a list need a mutex for access?  Who knows...

    if settings.SERVER is not None:
        server = settings.SERVER
        scan(server,db_obj)

    if settings.TARGET_LIST is not None:
        with open(settings.TARGET_LIST,'r') as target_list:
            targets = target_list.readlines()

        # A fairly rudimentary thread limiter -- libsmb easily screws itself with threads though....ymmv
        #thread_lock = settings.MAX_THREADS
        #thread_array = []
        for target in targets:
            scan(target,db_obj)
            #t = threading.Thread(target=scan,args=(target,db_obj))
            #t.daemon = True
            #t.start()
            #thread_array.append(t)
            #thread_lock-=1
            #print str(len(thread_array))
            #if thread_lock == 0:
            #    thread_array[0].join()
            #    thread_lock+=1
            #    thread_array.pop(0)

        # now we take all the data and push it into that file.
        #check to see if the file exists.
        output_file = open(settings.OUTPUT_FILE,'a+')
        for entry in db_obj:
            path = entry[0]
            attrs = entry[1]
            output_file.write(attrs+" : "+path)
        pdb.set_trace()
        
