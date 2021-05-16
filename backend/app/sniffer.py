from scapy.all import *
import os
# from geoip import geolite2
import json
import pandas as panda
from spam_lists import SPAMHAUS_DBL as checker

# global variables
tcpPackets = 0
udpPackets = 0
icmpPackets = 0
packets = 0
ipAdresses = [[]]
frame = ''
# type of local network
localNetwork = '192.168.'


# function is returning true if IP address is already in list
# parameters are both IP addresses, then we check which one is local
# and if foreign IP is already in list of IP addresses add packet count
def is_in_ipadresses(ipAddressFrom, ipAddressTo):
    global ipAdresses
    for ip in ipAdresses:
        if(ip and ip[0] == ipAddressFrom and ip[1] == ipAddressTo):
            ip[2] += 1
            return True
        elif(ip and ip[0] == ipAddressTo and ip[1] == ipAddressFrom):
            ip[3] += 1
            return True
    return False


# main sniffer function, pkt is packed which arrived on network card
def network_sniffer(pkt):
    interface = "eth0"                         # set used interface (wlan0 is wifi)
    myMac = get_if_hwaddr(interface)
    if(pkt[Ether].src == myMac):                # no check packet if src mac is yours
        return

    if(pkt.haslayer(IP)):                       # if packet has IP header add to statistics
        global packets
        packets += 1
        global ipAdresses, localNetwork
        inList = is_in_ipadresses(pkt[IP].src, pkt[IP].dst)

        if(not inList):
            if(pkt[IP].src.startswith(localNetwork)):
                onBlacklist = False
                if(pkt[IP].dst in checker):
                    print('IP found on blacklist')
                    onBlacklist = True
                ipAdresses.append([pkt[IP].src, pkt[IP].dst, 1, 0, onBlacklist])
            elif(pkt[IP].dst.startswith(localNetwork)):
                onBlacklist = False
                if(pkt[IP].src in checker):
                    print('IP found on blacklist')
                    onBlacklist = True
                ipAdresses.append([pkt[IP].dst, pkt[IP].src, 0, 1, onBlacklist])
        panda.DataFrame(ipAdresses, columns=['ipAddressLocal', 'ipAddressForeign', 'sendPackets', 'receivedPackets', 'blackList']).to_json("networkdata/ipAdresses.json", orient="table")
    
    if (pkt.haslayer(TCP)):
        with open('networkdata/packets.json', 'r+') as f:
            data = json.load(f)
            global tcpPackets 
            tcpPackets += 1
            data['tcp'] = tcpPackets 
            f.seek(0)       
            json.dump(data, f, indent=4)
            f.truncate()     
    if (pkt.haslayer(UDP)):
        with open('networkdata/packets.json', 'r+') as f:
            data = json.load(f)
            global udpPackets 
            udpPackets += 1
            data['udp'] = tcpPackets 
            f.seek(0)       
            json.dump(data, f, indent=4)
            f.truncate()     
    if (pkt.haslayer(ICMP)):
        with open('networkdata/packets.json', 'r+') as f:
            data = json.load(f)
            global icmpPackets 
            icmpPackets += 1
            data['icmp'] = icmpPackets 
            f.seek(0)       
            json.dump(data, f, indent=4)
            f.truncate()     

# this function is called once on startup of flask
def sniffer():
    print("Network packet counter started.")
    with open('networkdata/ipAdresses.json', 'r+') as f:    # clear file 
        f.truncate(0)
    global ipAdresses
    ipAdresses = [[]]                                       # clear global variables
    load_layer("tls")                                       # count packets with tls connection too
    sniff(prn=network_sniffer, iface="eth0", store=0)      # start sniffing on interface wlan0, no store any packet localy