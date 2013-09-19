SMB-Scan
========

Python-based SMB Share scanner -- scans a bunch of computers, outputs the path and the file permissions for the account



Dependancies:
=============

https://pypi.python.org/pypi/pysmbc/



Usage:
======

Edit the settings in settings.py to be what you want to be.  Follow the formatting there.
Will output a flat file containing the Unix-style numerical permissions for the user account used

You may specify many targets in the targets.txt file, including networks.  Be sure to be classy ;) (192.168.1.0/24, not 192.168.1.1/24)



Bugs
====
The file permissions for the file are literally the file permissions for the file -- not for the kind of access your account has to that file -- I'm working on fixing that.


Please report bugs via Here, Twitter (@crypt0s) or gmail (Bryanhalf)
Enjoy.
