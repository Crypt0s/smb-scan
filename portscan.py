#!/usr/bin/python

import argparse
from socket import *
from threading import *

screenlock = Semaphore(value=1)
def connScan(Host, Port):
    try:
        connector = socket(AF_INET, SOCK_STREAM)
        connector.connect((Host, Port))
        connector.send('Safe Banner Grabber\r\n')
        results = connector.recv(2048)
        screenlock.acquire()
        print '[+]%d/tcp open'% Port
        print '[+] ' + str(results)
    except:
        screenlock.acquire()
        print '[-]%d/tcp closed'% Port
    finally:
        screenlock.release()
        connector.close()

def portScan(Host, Ports):
    try:
        IP = gethostbyname(Host)
    except:
        print "[-] Cannot resolve '%s': Unknown host "%Host
        return
    try:
        hostname = gethostbyaddr(IP)
        print '\n[+] Scan Results for: ' + Name[0]
    except:
        print '\n[+] Scan Results for: ' + IP
    setdefaulttimeout(1)

    for Port in Ports:
        threadnum = Thread(target=connScan, args=(Host, int(Port)))
        threadnum.start()

def main():
    portparser = argparse.ArgumentParser(description="Multi-threaded python portscanner")
    portparser.add_argument('-H', dest='Host', type=str, required='True', help="IP Address or Domain Name")
    portparser.add_argument('-p', dest='Port', type=str, required='True', help="Ports to scan")
    portargs = portparser.parse_args()

    Host = portargs.Host
    Ports = portargs.Port.split(', ')

    portScan(Host, Ports)

if __name__ == "__main__":
    main()
