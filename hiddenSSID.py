import threading
from scapy.all import Dot11Beacon, Dot11ProbeResp, sniff, RadioTap
from threading import Thread, Lock
from MacLookup import *
from rich.live import Live
from rich.table import Table
from rich.console import Console
from rich.layout import Layout
import time
import csv
import os

console = Console()
table_APs = Table(show_header=True, header_style='bold #2070b2',
              title='[bold]ACTIVE Access Points')


table_clients_list = Table(show_header=True, header_style='bold #2070b2',
              title='[bold]ACTIVE Clients')

table_hidden_ssid = Table(show_header=True, header_style='bold #2070b2',
              title='[bold]Hidden SSIDs')

OUIMEM = {}
hidden_AP_list = []
visible_AP_list = []
clientMACs = []
listOfClients = []
visibleAPs = []
interface= "wlx9091673016a3"

with open('OUI.txt', 'r', encoding="UTF-8") as OUILookup:
    for line in csv.reader(OUILookup, delimiter='\t'):
        if not line or line[0] == "#":
            continue
        else:
            OUIMEM[line[0]] = line[1:]

def channel_hop():
    ch = 1
    while True:
        os.system(f"iwconfig {interface} channel {ch}")
        # switch channel from 1 to 14 each 1s
        ch = ch % 11 + 1
        time.sleep(0.5)

def find_mac_vendor2(mac_addr):
    loop = asyncio.get_event_loop()
    vendor = ""
    try:
        vendor = (loop.run_until_complete(AsyncMacLookup().lookup(mac_addr)))
    except KeyError:
        return ""
    except InvalidMacError as e:
        return ""

    return vendor

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

        bssid = str(pkt.addr2)

        ssid = pkt.info.decode()
        try:
            dbm_signal = str(pkt.dBm_AntSignal)
        except:
            dbm_signal = "N/A"
        stats = pkt[Dot11Beacon].network_stats()
        chan = str(stats.get("channel"))
        crypto = str(stats.get("crypto") )
        
        #Hidden SSID for AP
        #TODO: some blank ones still made it to the list
        if not ssid:

            #if 1st time we see this hidden SSID
            if  (bssid.strip()) not in hidden_AP_list:
                
                #add to our seen list
                hidden_AP_list.append(bssid)
                vendor = find_mac_vendor2(pkt.addr2)
                table_hidden_ssid.add_row(bssid, ssid, dbm_signal, chan, crypto, vendor)

        else:

            #if 1st time we see this non-hidden SSID
            if (bssid) not in visible_AP_list:
                visible_AP_list.append(bssid)

                vendor = str(find_mac_vendor2(bssid))
                table_APs.add_row(bssid, ssid, dbm_signal, chan, crypto, vendor)
                
    #Sniff Probe responses to uncover hidden SSID's
    elif pkt.haslayer(Dot11ProbeResp) and (pkt.addr3 in hidden_AP_list):

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

    
    elif pkt.haslayer(Dot11ProbeResp) :
        client_mac = pkt.addr1
        if (client_mac not in clientMACs):
            
            clientMACs.append(client_mac)
            ssid = pkt.info.decode()
            chan = get_channel(pkt[RadioTap].ChannelFrequency)
            
            try:
                dbm_signal = pkt.dBm_AntSignal
            except:
                dbm_signal = "N/A"
            stats = pkt[Dot11ProbeResp].network_stats()
            crypto = stats.get("crypto") 
            vendor = str(find_mac_vendor2(client_mac))
            table_clients_list.add_row(str(client_mac), str(ssid), str(dbm_signal), str(chan), str(crypto), str(vendor))

def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header"),
        Layout(name="middle"),
        Layout(name="footer")
    )

    return layout

def make_top_grid() :
    
    table_APs.add_column('MAC', justify='right')
    table_APs.add_column('SSID', justify='right')
    table_APs.add_column('dBm')
    table_APs.add_column('Channel', justify='center')
    table_APs.add_column('Encryption', justify='center')
    table_APs.add_column('Vendor')

    return table_APs

def make_middle_grid() :
    
    table_clients_list.add_column('MAC', justify='right')
    table_clients_list.add_column('SSID', justify='right')
    table_clients_list.add_column('dBm')
    table_clients_list.add_column('Channel', justify='center')
    table_clients_list.add_column('Encryption', justify='center')
    table_clients_list.add_column('Vendor')

    return table_clients_list

def make_bottom_grid() :
    
    table_hidden_ssid.add_column('MAC', justify='right')
    table_hidden_ssid.add_column('SSID', justify='right')
    table_hidden_ssid.add_column('dBm')
    table_hidden_ssid.add_column('Channel', justify='center')
    table_hidden_ssid.add_column('Encryption', justify='center')
    table_hidden_ssid.add_column('Vendor')

    return table_hidden_ssid

def create_output_process():
    
    layout = make_layout()
    layout["header"].update(make_top_grid())
    layout["middle"].update(make_middle_grid())
    layout["footer"].update(make_bottom_grid())

    with Live(layout, refresh_per_second=10, screen=True) as live:
        while True:
            time.sleep(1)

if __name__ == "__main__":

    lock = threading.Lock()
    # Start channel hopping
    hop = Thread(target=channel_hop)
    hop.daemon = True
    hop.start()

    #Start displaying nice grid
    outputThread = Thread(target=create_output_process)
    outputThread.daemon = True
    outputThread.start()

    sniff(iface='wlx9091673016a3', prn=parseSSID,  store=0, monitor=True)

    while True:
        time.sleep(1)