


#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
#
#
#	File Name 	 	: nmap4.py
#	Author	 	 	: Dheeraj Deshmukh
#	last modified	: 15 jan 2021
#	Language		: Python
#	python version  : python3.9
#	Requirment 		: re , nmap3 , threading , os , subprocess , time , sys , pyfiglet
#	LinkedIn		:https://www.linkedin.com/in/dheeraj-deshmukh-65b7901a4/
#	Twitter			:https://twitter.com/dheeraj_deshmuk
#
#
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
# 
#    ____   ___  ____ _____   ____   ____    _    _   _ _   _ _____ ____      
#    |  _ \ / _ \|  _ \_   _| / ___| / ___|  / \  | \ | | \ | | ____|  _ \     
#    | |_) | | | | |_) || |   \___ \| |     / _ \ |  \| |  \| |  _| | |_) |    
# _ _|  __/| |_| |  _ < | |    ___) | |___ / ___ \| |\  | |\  | |___|  _ < _ _ 
#(_|_)_|    \___/|_| \_\|_|   |____/ \____/_/   \_\_| \_|_| \_|_____|_| \_(_|_)
#
#
#::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::::
                                                                              


import re 
import nmap3
import threading
from threading import Thread
import os
import subprocess as sp
import time 
import sys 
import pyfiglet
import argparse
import socket


				# :::::::::::::::::: HANDELING ARGUMENTS :::::::::::::::::::::

parser = argparse.ArgumentParser()
parser.add_argument("-i","--ip",)
parser.add_argument("-d","--domain",)
parser.add_argument("-s","--segment",)
parser.add_argument("-t","--thread",)
parser.add_argument("-li","--listip",)
parser.add_argument("-ld","--domainlist",)
args = parser.parse_args()





if(	args.ip and args.domain ) or (args.ip and args.segment) or (args.domain and args.segment):
	print("Please Enter only ip or only domain both at the same time are not accepted")
	exit()

#Regular Expression for ip address
if args.ip:
	aa=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",args.ip)
	if aa:
		network = args.ip
	else:
		print("Please Enter correct ip address")
		exit()

#Regular Expression for domain name
if args.domain:
	domain1 = args.domain
	pattern =re.match(r"^([A-Za-z0-9]\.|[A-Za-z0-9][A-Za-z0-9-]{0,61}[A-Za-z0-9]\.){1,3}[A-Za-z]{2,6}$",args.domain)
	if pattern:
		#network = socket.gethostbyname("{}".format(domain1))
		pass
	else:
		print("Please Enter Valid Domain")
		exit()

#Regular Expression for network segment
if args.segment:
	aa=re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,3}$",args.segment)
	if aa:
		network = args.segment
	else:
		print("Please Enter correct segment eg : [ 1.1.1.1/24 ] ")
		exit()

if args.listip:
	dirname = args.listip
	dirname = dirname.replace(".txt", "")
	os.mkdir('{}'.format(dirname))

if args.domainlist:
	dirname = args.domainlist
	dirname = dirname.replace(".txt", "")
	os.mkdir('{}'.format(dirname))
if args.domain:
	dirname = args.domain
	os.mkdir('{}'.format(dirname))


if args.thread:
	ipip6 = args.thread

print("\033[01;33m ") #starting orange colour of animation


# ::::::::::::::::::::::::::::::::::::::::::: FUNCTIONS :::::::::::::::::::::::::::::::::::::::::::::::::::::


def help_func():
	print("Welcome to Help Section..")
	print("\nusage: nmap4.py [-h] [-i IP] [-d DOMAIN] [-s SEGMENT] [-t THREAD] [-li LISTIP] [-ld DOMAINLIST]")
	print("\n__________________________________________________________________________________________________")
	print("\n -h  | --help                           : Show help")
	print("\n -i  | --ip                             : Define Ip")
	print("\n -s  | --segment                        : Define segment [ 1.1.1.1/24 ]")
	print("\n -li | --listip                         : Ip list for scanning")
	print("\n -ld | --domainlist                     : Domain list for scanning")
	print("\n__________________________________________________________________________________________________")
	print("\n >>> It generate file of each ip or domain. ")
	print("\n >>> Spicify only one switch at a time. ")
	print("\n >>> See Folder same as your ip-name-list in which all reports are generated.")
	



#function to find the live ip in the given network segment 
def ip_find2():

	#declaration of global variable
	global ipip  # number of ip which is live 
	global ipip2
	global ipip3
	global dirname

	
	#nmap function to discover live host 
	nmap = nmap3.NmapHostDiscovery()
	results = nmap.nmap_portscan_only("{}".format(network))
	results2=str(results)


	#re.findall to filter unique elements inside the list
	ipip=re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',results2)
	ipip = list(dict.fromkeys(ipip))
	ipip2 = str(ipip)
	ipip3 = list(dict.fromkeys(ipip2))
	ipip3= str(ipip3)



	#defining directory name 
	dirname = network.replace("/24", "")


	#making directory
	os.mkdir('{}'.format(dirname))

	
	#making file to store output
	f = open("{}/hosts_up.txt".format(dirname), "a")
	

	
	#print up ip on screen from the list ipip and store this in file
	for ip in ipip :
		print("\033[1;37m[\033[1;31m*\033[1;37m]\033[1;32m"+" "+ip)
		f.write(ip)
		f.write(' \n')
	f.close()

	
	#store down ip into the file 
	'''
	if args.segment:
		f2= open("{}/hosts_down.txt".format(dirname),"a")
		for i in range(256):
			x = network.replace("1./24", "{}")
			ii = "{}".format(x,i)
			if re.search(ii,ipip3):
				pass
			else:
				f2.write(ii)
				f2.write(' \n')
		f2.close()

'''

#function to find the open port and version of open port
def find_port(i):



	#making seprate directory of each up ip
	os.mkdir('{}/{}'.format(dirname,i))
	
	
	#doing port scan and save the ip in file
	f = open("{}/{}/port_scan_result.txt".format(dirname,i), "a")
	otp = sp.getoutput('nmap -sT -p- {}'.format(i))
	f.write(otp)
	f.close()
	
	
	#filter open ports from the port_scan_result.txt file and make seprate file of open port
	f1 = open("{}/{}/open_port.txt".format(dirname,i), "a")
	otp1 = sp.getoutput("cat"+" "+dirname+"/"+i+"/port_scan_result.txt |grep open| awk -F/ '{print $1$2}'")
	f1.write(otp1)
	f1.close()
	


	#detect version of running service on open port
	f2 = open("{}/{}/service-version.txt".format(dirname,i), "a")
	port = sp.getoutput("cat"+" "+dirname+"/"+i+"/port_scan_result.txt |grep open| awk -F/ '{print $1}'")
	port1=port.replace("\n",",")
	otp2 = sp.getoutput('nmap -sV -p{} --version-intensity 1 {}'.format(port1,i))
	f2.write(otp2)
	f2.close()
	print("\033[1;31m=============================================\033[1;37m")
	print("\033[1;36mSCANNING OF {} COMPLETE".format(i))
	print("\033[1;31m=============================================\033[1;37m")


#:::  FUNCTION FOR IP LIST :::




def find_port2(i):

	


	#making seprate directory of each up ip
	os.mkdir('{}/{}'.format(dirname,i))
	
	
	#doing port scan and save the ip in file
	f = open("{}/{}/port_scan_result.txt".format(dirname,i), "a")
	otp = sp.getoutput('nmap -sT -p- {}'.format(i))
	f.write(otp)
	f.close()
	
	
	#filter open ports from the port_scan_result.txt file and make seprate file of open port
	f1 = open("{}/{}/open_port.txt".format(dirname,i), "a")
	otp1 = sp.getoutput("cat"+" "+dirname+"/"+i+"/port_scan_result.txt |grep open| awk -F/ '{print $1$2}'")
	f1.write(otp1)
	f1.close()
	


	#detect version of running service on open port
	f2 = open("{}/{}/service-version.txt".format(dirname,i), "a")
	port = sp.getoutput("cat"+" "+dirname+"/"+i+"/port_scan_result.txt |grep open| awk -F/ '{print $1}'")
	port1=port.replace("\n",",")
	otp2 = sp.getoutput('nmap -sV -p{} --version-intensity 1 {}'.format(port1,i))
	f2.write(otp2)
	f2.close()
	print("\033[1;31m=============================================\033[1;37m")
	print("\033[1;36mSCANNING OF {} COMPLETE".format(i))
	print("\033[1;31m=============================================\033[1;37m")


def find_port3(i,j):

	


	#making seprate directory of each up ip
	os.mkdir('{}/{}'.format(dirname,j))
	
	
	#doing port scan and save the ip in file
	f = open("{}/{}/port_scan_result.txt".format(dirname,j), "a")
	otp = sp.getoutput('nmap -sT -p- {}'.format(i))
	f.write(otp)
	f.close()
	
	
	#filter open ports from the port_scan_result.txt file and make seprate file of open port
	f1 = open("{}/{}/open_port.txt".format(dirname,j), "a")
	otp1 = sp.getoutput("cat"+" "+dirname+"/"+j+"/port_scan_result.txt |grep open| awk -F/ '{print $1$2}'")
	f1.write(otp1)
	f1.close()
	


	#detect version of running service on open port
	f2 = open("{}/{}/service-version.txt".format(dirname,j), "a")
	port = sp.getoutput("cat"+" "+dirname+"/"+j+"/port_scan_result.txt |grep open| awk -F/ '{print $1}'")
	port1=port.replace("\n",",")
	otp2 = sp.getoutput('nmap -sV -p{} --version-intensity 1 {}'.format(port1,i))
	f2.write(otp2)
	f2.close()
	print("\033[1;31m=============================================\033[1;37m")
	print("\033[1;36mSCANNING OF {} COMPLETE".format(j))
	print("\033[1;31m=============================================\033[1;37m")



#starting animation of the scanner. 
def load_animation(): 
    load_str = "starting your PORT SCANNER..."
    ls_len = len(load_str) 
  
  
    animation = "|/-\\"
    anicount = 0
      

    counttime = 0        
      
    i = 0                     
  
    while (counttime != 100): 
          

        time.sleep(0.075)  

        load_str_list = list(load_str)  
  
        x = ord(load_str_list[i]) 
          
        y = 0                             
 
        if x != 32 and x != 46:              
            if x>90: 
                y = x-32
            else: 
                y = x + 32
            load_str_list[i]= chr(y) 
          
        res =''              
        for j in range(ls_len): 
            res = res + load_str_list[j] 
              
        sys.stdout.write("\r"+res + animation[anicount]) 
        sys.stdout.flush() 
   
        load_str = res 
  
          
        anicount = (anicount + 1)% 4
        i =(i + 1)% ls_len 
        counttime = counttime + 1
      
  
    if os.name =="nt": 
  
        os.system("clear") 

		#:::::::::::::::::::::::::::::::: SCANNER START :::::::::::::::::::::::::::::::::::::::#

if __name__ == '__main__':  
	load_animation()
	
	
	#print the banner of the scanner.
	print("\n")
	print("\033[31m ")
	ascii_banner = pyfiglet.figlet_format("..PORT SCANNER..")
	print(ascii_banner) 
	print("                                    					       \033[1;37m  version - 1.0 ")
	print("                                       					      -Dheeraj Deshmukh ")

	print("\033[0m ")
	print("\033[1;30m>>> Faster than nmap.\n")
	print("\033[1;30m>>> Scan multiple ip or domain symeltaneously.\n")
	print("\033[1;30m>>> Suitable for scan big ip or domain list faster.\n")
	print("\033[1;30m>>> Speed depends upon power of processor.\n")
	print("\033[1;30m>>> Generate report of each network seperately.\n")
	print("\033[1;30m>>> See folder for detailed report.\033[1;37m\n")
	print("\n")

	if not (args.ip or args.segment or args.domain or args.listip or args.domainlist):
		help_func()
	print("\n")
	if args.domainlist or args.listip :
		pass
	else:
		if (args.ip or args.segment ):
			print("\033[1;31m--------------------: DETECTING LIVE HOST IN YOUR NETWORK :--------------------------\033[1;32m")
			print("\033[1;36mSearching for live host started....\033[1;32m")
			print("\n")
		else:
			pass
	if args.listip or args.domainlist:
		pass
	else:
		if (args.ip or args.segment):
			ip_find2()
	print("\n")
	if (args.ip or args.segment or args.domain or args.listip or args.domainlist):
		print("\033[1;31m----------------: DETECTING OPEN PORT  :-----------------\033[1;37m")
	
	

	#loop for threading 
	#For List of ip
	if args.listip:
		f = open(args.listip,"r")
		g = f.readlines()
		for ipadr in g :
			ipadr = ipadr.replace("\n","")
			ipadr = ipadr.replace(" ","")
			t=Thread(target=find_port2,args=(ipadr,))
			t.start()

	#loop for threading 
	#For List of domain
	if args.domainlist:
		f = open(args.domainlist,"r")
		g = f.readlines()
		for ipadr in g :
			ipadr = ipadr.replace("\n","")
			ipadr2 = ipadr.replace(" ","")
			ipadr3 = socket.gethostbyname("{}".format(ipadr2))
			t=Thread(target=find_port3,args=(ipadr3,ipadr2))
			t.start()
	if args.domain:
		name=args.domain
		ipadr = socket.gethostbyname("{}".format(name))
		find_port3(ipadr,name)
		


	if (args.listip or args.domainlist or args.domain):
		pass
	else:
		if (args.ip or args.segment):
			for ipadr in ipip:
				t=Thread(target=find_port,args=(ipadr,))
				t.start()