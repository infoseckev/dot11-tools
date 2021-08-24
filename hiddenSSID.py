from scapy.all import Dot11Beacon, Dot11ProbeResp, Dot11Deauth, Dot11ProbeReq, sniff, RadioTap
from threading import Thread
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.layout import Layout
import time
import os
import sys
import argparse
import string
import csv
from datetime import datetime

console = Console()

table_APs = Table(show_header=True, header_style='bold #2070b2',
              title='[bold]ACTIVE Access Points')

table_clients_list = Table(show_header=True, header_style='bold #2070b2',
              title='[bold]ACTIVE Clients')

table_hidden_ssid = Table(show_header=True, header_style='bold #2070b2',
              title='[bold]Hidden APs')

table_deauth_packets = Table(show_header=True, header_style='bold #2070b2',
              title='[bold]Deauth packets')

hidden_AP_list = []
visible_AP_list = []
clientMACs = []
listOfClients = []
visibleAPs = []
deauth_packet_list = []

interface_name = ""

d = {}

with open('output.txt') as lookup:
    for line in lookup:
       (key, val) = line.split('\t')
       d[str(key)] = str(val)


def signal_handler(signal, frame):
    print('\n=================')
    print('Execution aborted')
    print('=================')
    os.system("kill -9 " + str(os.getpid()))
    sys.exit(1)

def signal_exit(signal, frame):
    print ("Signal exit")
    sys.exit(1)

def setup_monitor (iface):
    print("Putting interface "  + iface + " in monitor mode")
    os.system('ifconfig ' + iface + ' down')
    try:
        os.system('iwconfig ' + iface + ' mode monitor')
    except:
        print("Failed to setup monitor mode")
        sys.exit(1)
    os.system('ifconfig ' + iface + ' up')
    return iface

def check_root():
    if not os.geteuid() == 0:
        print("This script requires sudo privileges")
        exit(1)

def channel_hop():
    #global interface_name
    ch = 1
    while True:
        os.system(f"iwconfig {interface_name} channel {ch}")
        # switch channel from 1 to 14 each 1s
        ch = ch % 11 + 1
        time.sleep(0.5)

def find_mac_vendor2(mac_addr):
    tmpres = mac_addr.upper().split(":")
    mac_str = tmpres[0] + "-" + tmpres[1] + "-" + tmpres[2]
    vendor =  (d.get(mac_str))
    print(vendor)
    return str(vendor).strip()


def get_channel(freq):
    
    if freq == 2412:
        return '1'
    if freq == 2417:
        return '2'
    if freq == 2422:
        return '3'
    if freq == 2427:
        return '4'
    if freq == 2432:
        return '5'
    if freq == 2437:
        return '6'
    if freq == 2442:
        return '7'
    if freq == 2447:
        return '8'
    if freq == 2452:
        return '9'
    if freq == 2457:
        return '10'
    if freq == 2462:
        return '11'
    if freq == 2467:
        return '12'
    if freq == 2472:
        return '13'
    if freq == 2484:
        return '14'
    else:
        return ''
                    
def parseSSID(pkt):

    #Sniff Access Points
    if pkt.haslayer(Dot11Beacon):
        if pkt.type == 0 and pkt.subtype == 8 :
            bssid = str(pkt.addr2).strip()

            ssid = pkt.info.decode('ascii').strip().strip('\x00')
            try:
                dbm_signal = str(pkt.dBm_AntSignal)
            except:
                dbm_signal = "N/A"
            stats = pkt[Dot11Beacon].network_stats()
            chan = str(stats.get("channel"))
            crypto = str(stats.get("crypto"))
            

            #SSID is not visible
            if len(ssid) == 0 :

                #if 1st time we see this hidden SSID
                if  (bssid) not in hidden_AP_list:
                    
                    #add to our seen list
                    hidden_AP_list.append(bssid)
                    vendor = find_mac_vendor2(pkt.addr2)
                    table_hidden_ssid.add_row(bssid, ssid, dbm_signal, chan, crypto, vendor)
            #SSID is visible
            else:

                #if 1st time we see this non-hidden SSID
                if (bssid) not in visible_AP_list:
                    visible_AP_list.append(bssid)
                    #print("ssid : " + ssid +  " : " + str(len(str(ssid))))
                    vendor = str(find_mac_vendor2(bssid))
                    table_APs.add_row(bssid, ssid, dbm_signal, chan, crypto, vendor)
                
    #Sniff Probes sent from AP (AP may be 'hidden' )
    elif pkt.haslayer(Dot11ProbeResp):

        #An AP is leaking a SSID in a Probe Response
        if  (pkt.addr3 in hidden_AP_list):
            #Hidden SSID Found!
            bssid = str(pkt.addr2)
            ssid = pkt.info.decode()
            try:
                dbm_signal = str(pkt.dBm_AntSignal)
            except:
                dbm_signal = "N/A"
            stats = pkt[Dot11Beacon].network_stats()
            chan = str(stats.get("channel"))
            crypto = str(stats.get("crypto") )
            vendor = find_mac_vendor2(pkt.addr3)

            table_hidden_ssid.add_row(bssid, ssid, dbm_signal, chan, crypto, vendor)

        #An AP is sending a probe for this client
        elif (pkt.addr1 not in clientMACs):
            client_mac = pkt.addr1
            clientMACs.append(client_mac)
            ssid = pkt.info.decode("ascii", errors="ignore")
            chan = get_channel(pkt[RadioTap].ChannelFrequency)
            
            try:
                dbm_signal = pkt.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            stats = pkt[Dot11ProbeResp].network_stats()
            crypto = stats.get("crypto") 
            vendor = str(find_mac_vendor2(client_mac))
            table_clients_list.add_row(str(client_mac), str(ssid), str(dbm_signal), str(chan), str(crypto), "Resp", str(vendor) )

    elif pkt.haslayer(Dot11Deauth):
        client_mac = pkt.addr1
        deauthing_mac = pkt.addr2
        
        deauth_packet_list.append(pkt.addr3)
        table_deauth_packets.add_row(client_mac, deauthing_mac)

    elif pkt.haslayer(Dot11ProbeReq):
        probe_type = "Req"

        if pkt.type == 0 and pkt.subtype == 4:

            mac = str(pkt.addr2)
            try:
                ssid = pkt.info.decode("UTF-8", errors="strict")
            except UnicodeError:
                pass
            
            else:
                #block blank ssid and add your home ap name in list to filter it
                if not (ssid == ""):
                    # print(ssid)

                    timestamp = pkt.getlayer(RadioTap).time
                    dt = datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
                    rssi = str(pkt[RadioTap].dBm_AntSignal)
                    #dbm_signal = pkt.dBm_AntSignal
                    chan = get_channel(pkt[RadioTap].ChannelFrequency)
                    if (pkt.addr2 not in clientMACs):
                        #to only show once in UI table
                        clientMACs.append(mac)

                        vendor = str(find_mac_vendor2(mac))

                        #info = {"timestamp": dt, "mac": mac, "ssid": ssid, "signal_strength": rssi, "channel": chanfreq, "location": "home"}
                        #print("%s Access Point MAC: %s MADE BY: %s - SSID: %s %s dBm, frequency : %s" % (dt, vendor, mac, ssid, rssi, chanfreq))

                        table_clients_list.add_row(str(mac), str(ssid), str(rssi), str(chan), "N/A", probe_type, str(vendor))
        
def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header"),
        Layout(name="footer")
    )
    layout["header"].ratio = 2
    layout["header"].split_row(
        Layout(name="top-left"),
        Layout(name="top-right")
    )

    layout["footer"].split_row(
        Layout(name="bottom-left"),
        Layout(name="bottom-right")
    )
    # layout["bottom-left"].split_row(
    #     Layout(name="left-left"),
    #     Layout(name="left-right")
    # )

    return layout

def make_AP_grid() :
    
    table_APs.add_column('MAC', justify='right')
    table_APs.add_column('SSID', justify='right')
    table_APs.add_column('dBm')
    table_APs.add_column('Ch.', max_width=3, no_wrap=True, justify='center')
    table_APs.add_column('Encryption', justify='center', max_width=13, no_wrap=True)
    table_APs.add_column('Vendor', max_width=15, no_wrap=True)

    return table_APs

def make_clients_grid() :
    
    table_clients_list.add_column('MAC', justify='right', max_width=18, no_wrap=True)
    table_clients_list.add_column('SSID', justify='right')
    table_clients_list.add_column('dBm')
    table_clients_list.add_column('Ch.', max_width=3, no_wrap=True, justify='center')
    table_clients_list.add_column('Encryption', justify='center', max_width=15, no_wrap=True)
    table_clients_list.add_column('Probe Type', max_width=5, no_wrap=True)
    table_clients_list.add_column('Vendor', max_width=17, no_wrap=True)
    
    return table_clients_list

def make_deauth_grid() :
    
    table_deauth_packets.add_column('Target MAC', justify='right')
    table_deauth_packets.add_column('Culprit AP', justify='right')
    # table_deauth_packets.add_column('dBm')
    # table_deauth_packets.add_column('Channel', justify='center')
    # table_deauth_packets.add_column('Encryption', justify='center')
    # table_deauth_packets.add_column('Targeted Vendor')
    # table_deauth_packets.add_column('Culprit AP Vendor')

    return table_deauth_packets

def make_hidden_SSID_grid() :
    table_hidden_ssid.add_column('MAC', justify='right')
    table_hidden_ssid.add_column('SSID', justify='right')
    table_hidden_ssid.add_column('dBm')
    table_hidden_ssid.add_column('Ch.', max_width=3, justify='center')
    table_hidden_ssid.add_column('Encryption', justify='center', max_width=15, no_wrap=True)
    table_hidden_ssid.add_column('Vendor', max_width=20, no_wrap=True)

    return table_hidden_ssid

def create_output_process():
    
    layout = make_layout()
    layout["top-left"].update(make_AP_grid())
    layout["top-right"].update(make_clients_grid())
    layout["bottom-left"].update(make_hidden_SSID_grid())
    layout["bottom-right"].update(make_deauth_grid())

    with Live(layout, refresh_per_second=10, screen=True) as live:
        while True:
            time.sleep(1)
#########################################################################3

if __name__ == "__main__":
    check_root()
    #TODO: check if db schemas exist

    parser = argparse.ArgumentParser()
    parser.add_argument('--interface', '-i', default='wlx9091673016a3',
                help='monitor mode enabled interface')
    parser.add_argument('--location', '-l', default='home',
                help='description of sniffing location')
    args = parser.parse_args()

    interface_name = args.interface

    setup_monitor(interface_name)

    time.sleep(4)

    # Start channel hopping
    hop = Thread(target=channel_hop)
    hop.daemon = True
    hop.start()

    # Start displaying nice grid
    outputThread = Thread(target=create_output_process)
    outputThread.daemon = True
    outputThread.start()

    sniff(iface=interface_name, prn=parseSSID,  store=0, monitor=True)

    while True:
        time.sleep(1)