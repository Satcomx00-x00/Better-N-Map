#!/usr/bin/python
# -*- coding: utf-8  -*-
import subprocess
import os
from time import sleep
import time
import sys
import datetime
from netifaces import interfaces, ifaddresses, AF_INET
from terminaltables import AsciiTable

# echo " nmap brute force password : nmap --script brute -Pn <ip>"
# echo " test if target is vuln to Dos: nmap --script dos -Pn <ip>"
# echo " perform DOS attack: nmap --max-parallelism 750 -Pn --script http-slowloris ->
# echo " firewall info: nmap  -sA <ip> OR protected host nmap -PN"
# echo " list hosts nmap -sn <ip> AND open ports only nmap --open"
# echo " scan for weaknesses in Firewall: nmap -sN/F/X <ip>"
# echo " Scan Remote Hosts using SCTP: nmap -sZ --top-ports 20 -T4 192.168.1.1/24"
# echo " Determine route: nmap --traceroute <ip>"
# echo " Disable reverse DNS for perf: nmap --traceroute"
# echo " Geo ip : nmap --script=ip-geolocation-maxmind <ip>"
# echo " nmap –sU –A –PN –n –pU:19,53,161 –script=snmp-sysdescr,dns-recursion,ntp-mon>


# ----------------------------------------------------------------------------------------------
def my_quit_fn():
    os.system('clear')
    raise SystemExit


def invalid():
   print "INVALID CHOICE!"
   os.system('clear')


def credits():
    os.system('clear')
    print ('''
                  ,ad8888ba,  88        88 88888888888 88        88
                 d8"'    `"8b 88        88 88          88        88
                d8'           88        88 88          88        88
                88            88aaaaaaaa88 88aaaaa     88aaaaaaaa88
                88            88""""""""88 88"""""     88""""""""88
                Y8,           88        88 88          88        88
                 Y8a.    .a8P 88        88 88          88        88
                  `"Y8888Y"'  88        88 88888888888 88        88 \n \n''')

    print 'AS THEY SAY IN FRENCH ! \n'
    print 'SATCOM'
    time.sleep(4)
    os.system('clear')
    main()


def template():
    os.system('clear')
    print ("""\033[1m\033[5m\033[31m/ ____|     | |\n| (___  __ _| |_ ___ ___  _ __ ___\n\___ \ / _` | __/ __/ _ \| '_ ` _ \ \n____) | (_| | || (_| (_) | | | | | |\n|____/ \__,_|\__\___\___/|_| |_| |_| \033[0m \033[37m""")
    print ("---Script by Satcom--- \n")
    x = datetime.datetime.now()
    print(x)
    print('\n ----------------------------------------------------')
    for ifaceName in interfaces():
        addresses = [i['addr'] for i in ifaddresses(ifaceName).setdefault(AF_INET, [{'addr':'No IP address'}] )]
        print '   		%s: %s' % (ifaceName, ', '.join(addresses))
    print(' ----------------------------------------------------')

# ----------------------------------------------------------------------------------------------
def normal_nmap():
    os.system('clear')
    answ=True
    while answ:
        template()
        print """
                1.Get Firewall Information of Hosts
                2.Scan Firewall Protected Hosts
                3.Detect OS Information
                4.Scan Hosts for Specific Ports
                5.List Hosts without Port Scanning
                6.Do a Fast Scan of Hosts
                7.Detect Service and Version Information
                8.Get OS Fingerprints
                00.Exit"""
        ans=raw_input("What would you like to do? ")
        if ans=="1":
            # target = raw_input("Target ip or hostname: ")
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -sA --reason '"+target+"' && read'")
        elif ans=="2":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -PN --reason '"+target+"' && read'")
        elif ans=="3":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -A -O -v '"+target+"' && read'")
        elif ans=="4":
            template()
            target = raw_input('Target ip: ')
            ports = raw_input('write ports separate(,) : ')
            os.system("xterm -e 'nmap -p --reason '"+ports+" "+target+"' && read'")
        elif ans=="5":
            template()
            target = raw_input('Target ip subnet (192.168.1.0/24): ')
            os.system("xterm -e 'nmap -sn '"+target+"' && read'")
        elif ans=="6":
            template()
            target = raw_input('Target ip : ')
            os.system("xterm -e 'nmap -F --open --reason '"+target+"'&& read'")
        elif ans=="7":
            template()
            target = raw_input('Target ip subnet (192.168.1.0/24): ')
            os.system("xterm -e 'nmap -sV '"+target+"' && read'")
        elif ans=="8":
            template()
            target = raw_input('Target ip subnet (192.168.1.0/24): ')
            os.system("xterm -e 'nmap -sT '"+target+"' && read'")
        elif ans=="00":
            ans = None
            print("\n Not Valid Choice Try again")
            time.sleep(0.5)
            os.system('clear')
            template()
        else:
            os.system('clear')
            time.sleep(0.5)
            invalid()


def hard_nmap():
    os.system('clear')
    answ=True
    while answ:
        template()
        print """
                1.Scan Remote Hosts using SCTP
                2.creates a zombie host on the network and scan other hosts
                3.Scan Remote Hosts using ARP Pings
                4.Determine Route to Remote Host
                5.Disable Reverse DNS Resolution for All Hosts
                6.Control Version Detection
                7.Scan Hosts Using Ip Fragments
                8.Use Decoy IP Addresses

                00.Exit"""
        ans=raw_input("What would you like to do? ")
        if ans=="1":
            template()
            # target = raw_input("Target ip or hostname: ")
            target = raw_input('Target ip subnet (192.168.1.0/24): ')
            os.system("xterm -e 'nmap -sZ --top-ports 20 -T4 '"+target+"' && read'")
        elif ans=="2":
            template()
            zombie = raw_input('Zombie ip (random ip): ')
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -sI '"+zombie+" "+target+"' && read'")
        elif ans=="3":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -PR '"+target+"' && read'")
        elif ans=="4":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap --traceroute '"+target+"' && read'")
        elif ans=="5":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -n '"+target+"' && read'")
        elif ans=="6":
            template()
            target = raw_input('Target ip: ')
            intensity = raw_input("Select aggresivity (1 to 5):")
            os.system("xterm -e 'nmap -sV --version-intensity 5 '"+target+"' && read'")
        elif ans=="7":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -f '"+target+"' && read'")
        elif ans=="8":
            template()
            print "Need 3 ip to cloak idendity"
            cloak1 = raw_input("ip cloak 1: ")
            cloak2 = raw_input("ip cloak 2: ")
            cloak3 = raw_input("ip cloak 3: ")
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap --top-ports 10 -D '"+cloak1+" "+cloak2+" "+cloak3+" "+target+"' && read'")
        elif ans=="00":
            ans = None
        else:
            os.system('clear')
            time.sleep(0.5)
            invalid()

def script_nmap():
    os.system('clear')
    answ=True
    while answ:
        template()
        print """
                1.Use Default Safe Scripts
                2.Use Specific NSE Scripts
                3.Scan for Common Files/Directories
                4.Get HTTP Page Titles
                5.Use Multiple Script Categories
                6.Use Wildcards for Script Selection
                7.Inspect Heartbleed Vulnerability
                8.Retrieve IP Information
                9.Scan DDoS Reflective UDP Services
                10.Scan taget to find vulns
                11.Scan taget to exploit vulns
                00.Exit"""
        ans=raw_input("What would you like to do? ")
        if ans=="1":
            # target = raw_input("Target ip or hostname: ")
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -sV -sC '"+target+"' && read'")
        elif ans=="2":
            template()
            target = raw_input('Target domain: ')
            os.system("xterm -e 'nmap --script=whois-ip.nse '"+target+"' && read'")
        elif ans=="3":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -n --script=http-enum.nse '"+target+"' && read'")
        elif ans=="4":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap --script=http-title '"+target+"' && read'")
        elif ans=="5":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap --script discovery,brute '"+target+"' && read'")
        elif ans=="6":
            template()
            print "The following command will utilize all scripts that start with ssh."
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap --script 'ssh*' '"+target+"' && read'")
        elif ans=="7":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap -sV -p 443 --script=ssl-heartbleed '"+target+"' && read'")
        elif ans=="8":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap --script=whois*,ip-geolocation-maxmind,asn-query '"+target+"' && read'")
        elif ans=="9":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap  –sU –A –PN –n –pU:19,53,161 –script=snmp-sysdescr,dns-recursion,ntp-monlist '"+target+"' && read'")
        elif ans=="10":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap nmap -Pn --script vuln '"+target+"' && read'")
        elif ans=="11":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap nmap -Pn --script exploit '"+target+"' && read'")
        elif ans=="00":
            ans = None
            print("\n Not Valid Choice Try again")
            time.sleep(0.5)
            os.system('clear')
            template()
        else:
            os.system('clear')
            time.sleep(0.5)
            invalid()

def hack_the_world():
    os.system('clear')
    answ=True
    while answ:
        template()
        print """
                1.Use Default Safe Scripts
                2.Use Specific NSE Scripts
                3.Scan for Common Files/Directories
                4.Get HTTP Page Titles
                5.Use Multiple Script Categories
                6.Use Wildcards for Script Selection
                7.Inspect Heartbleed Vulnerability
                8.Retrieve IP Information
                9.Scan DDoS Reflective UDP Services
                10.Scan taget to find vulns
                11.Scan taget to exploit vulns
                00.Exit"""
        ans=raw_input("What would you like to do? ")
        if ans=="1":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap nmap -Pn --script exploit '"+target+"' && read'")
        elif ans=="11":
            template()
            target = raw_input('Target ip: ')
            os.system("xterm -e 'nmap nmap -Pn --script exploit '"+target+"' && read'")
        elif ans=="00":
            ans = None
            print("\n Not Valid Choice Try again")
            time.sleep(0.5)
            os.system('clear')
            template()
        else:
            os.system('clear')
            time.sleep(0.5)
            invalid()


    nmap --script dos -Pn

def main():
    template()
    answ=True
    while answ:
        print("""
         1.Casu Nmap
         2.Nmap Commands for Ethical Hackers
         3.Scripts Nmap
         4.CREDITS

         00.Exit/Quit
         """)
        ans=raw_input("What would you like to do? ")
        if ans=="1":
          normal_nmap()
        elif ans=="2":
            hard_nmap()
        elif ans=="3":
            script_nmap()
        elif ans=="4":
            credits()
        elif ans=="00":
          my_quit_fn()
          ans = None
        else:
            os.system('clear')
            print("\n Not Valid Choice Try again")
            time.sleep(0.5)
            os.system('clear')
            template()



# --------------------------------MAIN---------------------------------------------------------
# ----------------------------------------------------------------------------------------------


if __name__ == "__main__":
	main()


# p=subprocess.Popen("nmap -sA "+target, shell=True)
