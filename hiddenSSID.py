from rich import table
from scapy.all import Dot11Beacon, Dot11ProbeResp, Dot11Deauth, Dot11ProbeReq, sniff, RadioTap, Dot11
from threading import Thread
from rich.live import Live
from rich.table import Row, Table
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from contextlib import closing
import time
import os
import sys
import argparse
import string
import csv
from datetime import datetime
import pprint
from tabulate import tabulate
import sqlite3

console = Console()

LAST_INSERTED_PROBE_RESPONSE = ""
LAST_INSERTED_PROBE_REQUEST = ""
hidden_AP_list = []
visible_AP_list = []
clientMACs = []
listOfClients = []
visibleAPs = []
deauth_packet_list = []
interface_name = ""

USER_LOCATION = "home"

DB_WIFI = "wifi.db"
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

#this uses alot of CPU
def channel_hop():
    #global interface_name
    ch = 1
    while True:
        os.system(f"iwconfig {interface_name} channel {ch}")
        # switch channel from 1 to 14 each 1s
        ch = ch % 11 + 1
        time.sleep(1)

def find_mac_vendor2(mac_addr):
    tmpres = mac_addr.upper().split(":")
    mac_str = tmpres[0] + "-" + tmpres[1] + "-" + tmpres[2]
    vendor =  (d.get(mac_str))
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

def truncate_string(leng, str):
    if str is None:
        str = ""

    return (str[:leng] + '..') if len(str) > leng else str

def get_dbm_signal(pkt):
    dbm_signal = ""
    try:
        dbm_signal = pkt.dBm_AntSignal
    except:
        dbm_signal = "N/A"
    return str(dbm_signal)

def sniff_APs(pkt):
    #Sniff Access Points
    if pkt.haslayer(Dot11Beacon):
        if pkt.type == 0 and pkt.subtype == 8 :
            addr2 = str(pkt.addr2).strip()
            #Chipset hack
            ssid = pkt.info.decode('ascii').strip().strip('\x00')
            dbm_signal = get_dbm_signal(pkt)
            stats = pkt[Dot11Beacon].network_stats()
            chan = str(stats.get("channel"))
            enc = str(stats.get("crypto"))
            vendor =  str(find_mac_vendor2(addr2))
            utc_time = int(pkt.getlayer(RadioTap).time)

            # #SSID is not visible
            if len(ssid) > 0 :
            #     if  (bssid) not in hidden_AP_list:
                    
            #         #add to our seen list
            #         # hidden_AP_list.append(bssid)
            #         # vendor = find_mac_vendor2(pkt.addr2)
            #         # table_hidden_ssid.add_row(bssid, ssid, dbm_signal, chan, enc, vendor)
            #         pass
            # else:
                if (addr2) not in visible_AP_list:
                    visible_AP_list.append(addr2)
                    
                    build_AP_table(addr2, ssid, dbm_signal, chan, enc, vendor)

                    with closing(sqlite3.connect(DB_WIFI)) as connection:
                        with closing(connection.cursor()) as cursor:
                            
                            cursor.execute("insert into accessPoints (date_added, mac_address, mac_address_vendor, ssid, signal, longitude, latitude, location, session_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", (utc_time, addr2, vendor, ssid, dbm_signal, "gps_lon", "gps_lat", USER_LOCATION, session_id))
                            connection.commit()

def fingerprint_packet(str1, str2, str3):
    res = str(str1)+ str(str2) +str( str3)
    return res

def sniff_Probes(pkt):    
    addr2 = str(pkt.addr2).strip()
    addr1 = str(pkt.addr1).strip()   
    addr3 = str(pkt.addr3).strip()
    chan = str(get_channel(pkt[RadioTap].ChannelFrequency))
    dbm_signal = get_dbm_signal(pkt)

    if pkt.haslayer(Dot11ProbeResp):
        utc_time = int(pkt.getlayer(RadioTap).time)
        ssid = pkt.info.decode('ascii').strip().strip('\x00')
        stats = pkt[Dot11ProbeResp].network_stats()
        # chan = str(stats.get("channel"))
        enc = str(stats.get("crypto"))
        vendor = str(find_mac_vendor2(addr1))
        vendor_AP = str(find_mac_vendor2(addr3))
        
        global LAST_INSERTED_PROBE_RESPONSE
        if(fingerprint_packet(utc_time, ssid,addr1 ) != LAST_INSERTED_PROBE_RESPONSE):
        
            with closing(sqlite3.connect(DB_WIFI)) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute("insert into wifiProbeResponses (date_added, client_mac_address, client_mac_address_vendor, ap_mac_address, ap_mac_address_vendor, ssid, signal, longitude, latitude, location, session_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", (utc_time, addr1, vendor, addr3, vendor_AP, ssid, dbm_signal,"gps_lon", "gps_lat", "home", session_id))
                    connection.commit()
            LAST_INSERTED_PROBE_RESPONSE = fingerprint_packet(utc_time, ssid,addr1 ) 

        #Found hidden SSID name!
        if  (addr3 in hidden_AP_list):
            build_AP_table(addr2, ssid, dbm_signal, chan, enc, "FINDMYMACLOL")
            hidden_AP_list.remove(addr3)
            with closing(sqlite3.connect(DB_WIFI)) as connection:
                with closing(connection.cursor()) as cursor:
                    cursor.execute("insert into accessPoints (date_added, mac_address, mac_address_vendor, ssid, signal, longitude, latitude, location, session_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", (utc_time, addr2, vendor, ssid, dbm_signal, "gps_lon", "gps_lat", USER_LOCATION, session_id))
                    connection.commit()
                    
        #An AP is sending a probe for this client
        elif (addr1 not in clientMACs):
            clientMACs.append(addr1)
            build_Client_table(addr1, ssid, dbm_signal, chan, enc, "Resp" ,vendor)
            
    elif pkt.haslayer(Dot11ProbeReq):

        if pkt.type == 0 and pkt.subtype == 4:
            probe_type = "Req"
            try:
                ssid = pkt.info.decode("UTF-8", errors="strict")
            except UnicodeError:
                pass
            else:
                # block blank ssid and add your home ap name in list to filter it
                if not (ssid == ""):
                    utc_time = int(pkt.getlayer(RadioTap).time)
                    global LAST_INSERTED_PROBE_REQUEST
                    if(fingerprint_packet(utc_time, ssid,addr1 ) != LAST_INSERTED_PROBE_REQUEST):
                    
                        #were doing lots more lookups now im inserting in DB 
                        vendor = find_mac_vendor2(addr2)
                        with closing(sqlite3.connect(DB_WIFI)) as connection:
                                with closing(connection.cursor()) as cursor:
                                    cursor.execute("insert into wifiProbeRequests (date_added, mac_address, mac_address_vendor, ssid, signal, location, longitude, latitude, session_id) values (?, ?, ?, ?, ?, ?, ?, ?, ?)", (utc_time, addr2, vendor, ssid, dbm_signal, "gps_lon", "gps_lat", USER_LOCATION, session_id))
                                    connection.commit()
                        LAST_INSERTED_PROBE_REQUEST = fingerprint_packet(utc_time, ssid,addr1 ) 

                    if (addr2 not in clientMACs):
                        clientMACs.append(addr2)
                        build_Client_table(addr2, ssid, dbm_signal, chan, "N/A", "Req",  vendor)

                        
def sniff_Deauth(pkt):
    if pkt.haslayer(Dot11Deauth):
        # client_mac = pkt.addr1
        # deauthing_mac = pkt.addr2
        # deauth_packet_list.append(pkt.addr3)
        # table_deauth_packets.add_row(client_mac, deauthing_mac)
        pass

def parseSSID(pkt):
    if pkt.haslayer(Dot11):
        sniff_APs(pkt)
        sniff_Probes(pkt)
        sniff_Deauth(pkt)
        
#######################################################################################
ap_table = [['MAC','SSID', "dBm", "Ch.", "Encryption", "Vendor"]]
def build_AP_table(bssid, ssid, dbm, ch, enc, ven):

    global ap_table
    ssid = truncate_string(15, ssid)
    ven = truncate_string(15, ven)
    enc = truncate_string(12, enc)[2:-2]
    ap_table.insert(1, [bssid, ssid, dbm, ch, enc, ven])

client_table = [['MAC','SSID', "dBm", "Ch.", "Encryption","Type", "Vendor"]]
def build_Client_table(bssid, ssid, dbm, ch, enc, type, ven):
    
    global client_table
    ssid = truncate_string(15, ssid)
    ven = truncate_string(15, ven)
    enc = truncate_string(10, enc)[2:-2]
    client_table.insert(1, [bssid, ssid, dbm, ch, enc, type, ven])

def show_AP_table():
    global ap_table
    return (tabulate(ap_table, headers='firstrow',   
    tablefmt='fancy_grid'))

def show_Client_table():
    global client_table
    return (tabulate(client_table, headers='firstrow',   
    tablefmt='fancy_grid')) 
#######################################################################################

def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header")
        # Layout(name="footer")
    )
    layout["header"].ratio = 3
    layout["header"].split_row(
        Layout(name="top-left"),
        Layout(name="top-right")
    )

    # layout["footer"].split_row(
    #     Layout(name="bottom-left"),
    #     Layout(name="bottom-right")
    # )
    # layout["bottom-left"].split_row(
    #     Layout(name="left-left"),
    #     Layout(name="left-right")
    # )

    return layout

#UI Thread for Rich library live display
def create_output_process():
    
    layout = make_layout()
    with Live(layout, refresh_per_second=10, screen=True, vertical_overflow="visible") as live:
        while True:
            layout["top-left"].update(show_AP_table())
            layout["top-right"].update(show_Client_table())
            time.sleep(1)

if __name__ == "__main__":
    #get utc  timestamp
    session_id = datetime.utcnow()
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

    time.sleep(2)

    # Start channel hopping
    hop = Thread(target=channel_hop)
    hop.daemon = True
    hop.start()

    # Start displaying nice grid
    outputThread = Thread(target=create_output_process)
    outputThread.daemon = True
    outputThread.start()

    filt="wlan type mgt"
    capture = sniff(iface=interface_name, prn=parseSSID, filter=filt, store=0, monitor=True)
    
    while True:
        time.sleep(1)