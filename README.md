SMB-Scan - This is a forked beta version, but is functional for most flags that are currently implemented.  Read below.
========

Python-based SMB Share scanner -- scans a bunch of computers, outputs the path and the file permissions for the account

Lesson Learned
===

One lesson learned when forking this tool and re-writing sections is that even though SMB can find shares, port 445 isn't
port 445 isn't always open so this fork will let you know if shares are available and if port 445 is open it will present the
banner grab information in the output.  Otherwise, a closed message occurs.

I am still trying to understand why this is happening, but my current guess is something happening over NetBIOS as well since
I think NetBIOS and SMB are closely tied together.  Either way, my opinion is that neither NetBIOS or SMB should ever be
presented to the public internet.

Example:

My Samba docker container is off in this example:

- 192.168.10.5
- Port 445 Closed
['192.168.10.5\n']
Starting to crawl the targets... this will take some time.
Done

This is the output with my docker container turned on:

- 192.168.10.5
- Port 445 Closed
['192.168.10.5\n']
Starting to crawl the targets... this will take some time.
<smbc.Dirent object "(null)" (?) at 0x7fabf7ff1be8>
<smbc.Dirent object "(null)" (?) at 0x7fabf7da9788>
Done

Dependancies:
=============

https://pypi.python.org/pypi/pysmbc/



Usage:
======

Currently, you still need a targets file because I haven't finished the flag to input an IP or range as a command-line
argument. The targets file can be a list of IPs, a list of CIDRS, or combination of the two.
Will output a flat file containing the Unix-style numerical permissions for the user account used

You may specify many targets in the targets.txt file, including networks.  Be sure to be classy ;) (192.168.1.0/24, not 192.168.1.1/24)

./smbscanner.py -h
usage: smbscanner.py [-h] [-target_file TARGET_FILE]
                     [-results_file RESULTS_FILE] [-domain DOMAIN]
                     [-uname UNAME] [-passwd PASSWD] [-anonymous ANONYMOUS]
                     [-packet_rate PACKET_RATE]

SMB Checker

optional arguments:
  -h, --help            show this help message and exit
  -target_file TARGET_FILE
                        Target file
  -results_file RESULTS_FILE
                        Results file
  -domain DOMAIN        domain for authentication
  -uname UNAME          Username for authentication
  -passwd PASSWD        Password for authentication
  -anonymous ANONYMOUS  Use True to test for Anonymous access.
  -packet_rate PACKET_RATE  Default is 1.
  
Example
===

./smbscanner.py -target_file targets.txt -packet_rate 50

Bugs
====
The file permissions for the file are literally the file permissions for the file -- not for the kind of access your account
has to that file -- I'm working on fixing that. 

Writing to a results file isn't perfect yet.  I'm still working on fixing that as well.  I also want to be able to output to
multiple formats, but that will be later down the road.

Untested
===

I haven't tested the flags for Domain, User, or Password yet due to not currently having a need for it.

Anonymous is still a test function.

If you find other bugs that I haven't mentioned, please report them to gmail (rlastinger) or create a ticket, and I will get to it when I can.  

Help or improvement suggestions are also welcome.  Just email me at gmail (rlastinger).

Credits to Twitter (@crypt0s) or gmail (Bryanhalf) for the original project that I forked to start this one.
Thanks Bryan.
Enjoy.
