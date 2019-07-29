#importing necessary modules
import logging
from datetime import datetime
import subprocess
import sys

#This will suppress all messages that have lower level of seriousness than error messages, while running or loading scapy

logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
logging.getLogger('scapy.interactive').setLevel(logging.ERROR)
logging.getLogger('scapy.loading').setLevel(logging.ERROR)

try:
    from scapy.all import *
except ImportError:
    print('Scapy package for python is not installed on your system')
    sys.exit()

#pringting a message to the user; always use 'sudo scapy' in Linux
print('\n! Make sure to run this program as ROOT !\n')

#Asking the user for some parameters: interface on which have to sniff, the number of packets to sniff,
#the time interval to sniff, the protocol

#Asking the user for input - the interface on which to run sniffer
net_iface = input('* Enter the interface on which to run the sniffer eg(enp0s8): ')

#Setting network interface in promiscous mode
'''
Wikipedia: In computer networking, promiscuous mode or promisc mode[1] is a mode for a wired network interface
controller(NIC) or wireless network interface controller(WNIC) that causes  the controller to pass all traffic
it receives  to the central processing unit(CPU) rather than passing only frames that the controller is intended
to receive.
This Mode is normally used for packet sniffing that takes place on a router or on a computer connected to a hub
'''

try:
    subprocess.call(['ifconfig', net_iface, 'promisc'], stdout = None, stderr= None, shell= False)
except:
    print('\n Failed to configure interface as promiscuous')
else:
    print('\n Successfully configured interface {} as promiscuous'.format(net_iface))


#Asking the user the number of packets to sniff ( the 'count' parameter)
pkt_to_sniff = input('\n* Enter the number of packets to capture( 0 -> infinity)\n')

if int(pkt_to_sniff) !=0:
    print('\n* The number of packets to sniff is/are {}'.format(pkt_to_sniff))
elif int(pkt_to_sniff)==0:
    print('\n* The program will capture packets until time expires.\n')

#Asking the user for time-interval to sniff
time_to_sniff = input('\n Enter the time interval for capturing packets.\n')

#Handling the value entered by the user
if int(time_to_sniff)!=0:
    print('\n The capturing will go on till {}seconds\n'.format(time_to_sniff))

#Asking the user for any protocol filter he might want to apply to the sniffing process
#for example, I choose: ARP, BOOTP, ICMP
#You can customize to add your own protocols

proto_sniff = input('\n* Enter the protocol to filter by (arp|BOOTP|icmp|0 is all: ')

#Considering the case when user enters 0( meaning all protcols)
if(proto_sniff=='arp') or (proto_sniff =='bootp') or (proto_sniff=='icmp'):
    print('\n The program capture only {} packets'.format(proto_sniff.upper()))
elif(proto_sniff == '0'):
    print('\n The program will capture all protocols.\n')

#Asking the user to enter the name and path of the log file to be created
file_name = input('* please give a name to the log file: ')

#Creating the text file  (if it doesn't exist) for packet logging and/or opening it for appending
sniffer_log = open(file_name,'a')

#This is the function that will be called for each captured packet
#The function will extract parameters from the packet and then log each packet to the log file.

def packet_log(packet):

    #Getting the current timestamp
    now = datetime.now()

    #wrinting the packet information to the log file, also considering the protocol or 0 for all protocols
    if proto_sniff == '0':
        #writing the data to the log file
        print('Time: '+str(now)+'protocol: ALL'+' SMAC : '+packet[0].src +' DMAC : '+packet[0].dst, file= sniffer_log)
    elif((proto_sniff =='arp') or (proto_sniff=='bootp') or (proto_sniff=='icmp')):
        #writing the data to the log file
        print('Time: ' +str(now)+'protocol: '+proto_sniff.upper()+ 'SMAC : ' +packet[0].src +' DMAC : '+packet[0].dst, file = sniffer_log)

#Printing the informational message to the screen
print('\n* Starting the capture...')

#Running the sniffing process (with or without a filter)
if(proto_sniff =='0'):
    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout= int(time_to_sniff), prn= packet_log)
elif(proto_sniff =='arp') or (proto_sniff=='bootp') or (proto_sniff=='icmp'):
    sniff(iface = net_iface, count = int(pkt_to_sniff), timeout= int(time_to_sniff), prn = packet_log)
else:
    print('\n Could not identify the protocol.\n')

#printing the closing message
print('\n* Please check the {} file to see the captured packets.\n'.format(file_name))

#Closing the log file
sniffer_log.close()

#End of the program
