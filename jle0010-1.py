#!/usr/bin/env python

import dpkt
import socket
import sys

# References:
# Assuming Src -> Dest where Src initiates scan
#


#Object named dest port, holds src port, if udp, 
#   and which type of packet has been received
class Port:
    SrcPort = 0
    SrcAddr = ''
    Syn = False
    SynAck = False
    Ack = False
    RstAck = False
    None1 = False
    None2 = False
    FPU1 = False
    FPU2 = False
    Rst = False
    UDP = False
    
    
#--- Global Variables Here ---#

# IPAddrs = {'DestIP' : {Ports} }
# Ports = {'DestPort' : Port() }
IPAddrs = {}

# OpenScans/ClosedScans count open and closed scans
OpenScans = {'Connect':0,'Null':0,'SYN':0,'XMAS':0,'UDP':0}
ClosedScans = {'Connect':0,'Null':0,'SYN':0,'XMAS':0,'UDP':0}
ICMP= {'ICMP:0'}

ClosedSRA = 0
FoundSRA = ''

#--- End Global Variables ---#
    
def CheckForScan(ip,port):
    p = IPAddrs[ip][port]
    global ClosedSRA
    global FoundSRA
    found = False
    if (p.Syn and p.RstAck and not p.SynAck): #Closed Connect or SYN Scan
        if FoundSRA == '':
            ClosedSRA += 1
        else:
            ClosedScans[FoundSRA] += 1
        found = True
    elif (p.None1 and p.RstAck): #Closed Null Scan
        ClosedScans['Null'] += 1
        found = True
    elif (p.FPU1 and p.RstAck): #Closed XMAS Scan
        ClosedScans['XMAS'] += 1
        found = True
    elif (p.UDP): #UDP Scan
        if (p.None1 and p.None2): #Open UDP Scan
            OpenScans['UDP'] += 1
        elif (p.None1): #Closed UDP Scan
            ClosedScans['UDP'] += 1
        found = True
    elif (p.Syn and p.SynAck and p.Ack ): #Open Connect Scan
        OpenScans['Connect'] += 1
        found = True
        #print "Found Connect"
        FoundSRA = 'Connect'
        ClosedScans[FoundSRA] += ClosedSRA
        ClosedSRA = 0
    elif (p.None1 and p.None2): #Open Null Scan
        OpenScans['Null'] += 1
        found = True
    elif (p.Syn and p.SynAck and p.Rst): #Open SYN Scan
        OpenScans['SYN'] += 1
        found = True
        FoundSRA = 'SYN'
        ClosedScans[FoundSRA] += ClosedSRA
        ClosedSRA = 0
    elif (p.FPU1 and p.FPU2): #Open XMAS Scan
        OpenScans['XMAS'] += 1
        found = True
        
    #if found:
        #print "IP:", ip, " Port:", port
        #del IPAddrs[ip][port]
    return
    
    
    
    
filename = ''
if len(sys.argv) != 3 or sys.argv[1] != '-i':
    print "Incorrect arguments."
    sys.exit()
else:
    filename = sys.argv[2]
    
f = open(filename,'r')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    eth = dpkt.ethernet.Ethernet(buf) 
    if eth.type == dpkt.ethernet.ETH_TYPE_IP: #if IP Packet
        ip = eth.data   
        if ip.p == dpkt.ip.IP_PROTO_TCP: #if TCP Packet
            src_addr = socket.inet_ntoa(ip.src)
            dst_addr = socket.inet_ntoa(ip.dst)
            src_port = ip.data.sport
            dst_port = ip.data.dport
            tcp = ip.data
            #Verifying it's a reply packet. All replies are
            #  SYN,ACK or RST,ACK.
            if (((tcp.flags & dpkt.tcp.TH_SYN) != 0 and
               (tcp.flags & dpkt.tcp.TH_ACK) != 0) or
               ((tcp.flags & dpkt.tcp.TH_RST) != 0 and
               (tcp.flags & dpkt.tcp.TH_ACK) != 0)):
                temp = dst_addr
                dst_addr = src_addr
                src_addr = temp
                temp = dst_port
                dst_port = src_port
                src_port = temp
            if dst_addr not in IPAddrs:
                IPAddrs[dst_addr] = {}
            if dst_port not in IPAddrs[dst_addr]:
                IPAddrs[dst_addr][dst_port] = Port()
                IPAddrs[dst_addr][dst_port].SrcPort = src_port
                IPAddrs[dst_addr][dst_port].SrcAddr = src_addr
            if ((tcp.flags & dpkt.tcp.TH_SYN) != 0 and
                    (tcp.flags & dpkt.tcp.TH_ACK) != 0):
                IPAddrs[dst_addr][dst_port].SynAck = True
            elif ((tcp.flags & dpkt.tcp.TH_RST) != 0 and
                    (tcp.flags & dpkt.tcp.TH_ACK) != 0):
                IPAddrs[dst_addr][dst_port].RstAck = True
                #CheckForScan(dst_addr,dst_port)
            elif ((tcp.flags & dpkt.tcp.TH_FIN) != 0 and
                    (tcp.flags & dpkt.tcp.TH_PUSH) != 0 and
                    (tcp.flags & dpkt.tcp.TH_URG) != 0):
                if IPAddrs[dst_addr][dst_port].FPU1 == False:
                    IPAddrs[dst_addr][dst_port].FPU1 = True
                else:
                    IPAddrs[dst_addr][dst_port].FPU2 = True
                    #CheckForScan(dst_addr,dst_port)
            elif (tcp.flags & dpkt.tcp.TH_SYN) != 0:
                IPAddrs[dst_addr][dst_port].Syn = True
            elif (tcp.flags & dpkt.tcp.TH_ACK) != 0:
                IPAddrs[dst_addr][dst_port].Ack = True
            elif (tcp.flags & dpkt.tcp.TH_RST) != 0:
                IPAddrs[dst_addr][dst_port].Rst = True
                #CheckForScan(dst_addr,dst_port)
            elif tcp.flags == 0:
                if IPAddrs[dst_addr][dst_port].None1 == False:
                    IPAddrs[dst_addr][dst_port].None1 = True
                else:
                    IPAddrs[dst_addr][dst_port].None2 = True
                    #CheckForScan(dst_addr,dst_port)

        elif (ip.p == dpkt.ip.IP_PROTO_UDP):
            src_addr = socket.inet_ntoa(ip.src)
            dst_addr = socket.inet_ntoa(ip.dst)
            src_port = ip.data.sport
            dst_port = ip.data.dport
            if len(ip.data.data) == 0:
                if dst_addr not in IPAddrs:
                    IPAddrs[dst_addr] = {}
                if dst_port not in IPAddrs[dst_addr]:
                    IPAddrs[dst_addr][dst_port] = Port()
                    IPAddrs[dst_addr][dst_port].UDP = True
                    IPAddrs[dst_addr][dst_port].SrcPort = src_port
                    IPAddrs[dst_addr][dst_port].SrcAddr = src_addr
                if IPAddrs[dst_addr][dst_port].None1 == False:
                    IPAddrs[dst_addr][dst_port].None1 = True
                else:
                    IPAddrs[dst_addr][dst_port].None2 = True
        #elif (ip.p == dpkt.ip.IP_PROTO_ICMP):
            #print(ip.p)

f.close()

for ip,ports in IPAddrs.items():
    for port, data in ports.items():
        CheckForScan(ip,port)
        
#Printing results
print "Null:            ",OpenScans['Null']+ClosedScans['Null']
print "XMAS:            ",OpenScans['XMAS']+ClosedScans['XMAS']
print "UDP:             ",OpenScans['UDP']+ClosedScans['UDP']
print "Half-open (SYN): ",OpenScans['SYN']+ClosedScans['SYN']
print "Connect:         ",OpenScans['Connect']+ClosedScans['Connect']
if ClosedSRA > 0:
    print ClosedSRA," SYN and RST,ACK packets received, which could be"
    print "either Connect Scan Packets or Half-open (Syn) packets."


#For testing purposes
#"""for ip,ports in IPAddrs.items():
    #if (len(ports) > 0):
        #print "----- Destination IP Addr: ", ip,"-----"
    #for port,info in ports.items():
        #print "Destination Port:",port
        #print "   Source IP Address:",info.SrcAddr
        #print "   Source Port:",info.SrcPort
        #print "   Syn:",info.Syn
        #print "   SynAck:",info.SynAck
        #print "   Ack:",info.Ack
        #print "   RstAck",info.RstAck
        #print "   RST:",info.Rst
        #print "   None1",info.None1
        #print "   None2",info.None2
        #print "   FPU1",info.FPU1
        #print "   FPU2",info.FPU2"""
        #print "   UDP:","""#info.UDP"""
        
