"""Lite simulation of the top linux command."""
import datetime
import random
import sys
import time
from scapy.all import sniff
from rich.console import Console
from rich.live import Live
from rich.table import Table
from threading import Thread

console = Console()

table = Table(show_header=True, header_style='bold #2070b2',
                title='[bold]ACTIVE Access Points')

table.add_column('MAC', justify='right')
table.add_column('SSID', justify='right')
table.add_column('dBm')
table.add_column('Channel', justify='center')
table.add_column('Encryption', justify='center')
table.add_column('Vendor')

def parseSSID(pkt) -> Table:
    bssid = str(pkt.addr3)
    table.add_row(
        str("bssid"),str(datetime.datetime.now()),str(datetime.datetime.now()),
        str(datetime.datetime.now()),str(datetime.datetime.now()),str(datetime.datetime.now())
    )
    
def tmp2() ->Table:
    
    return table

def create_output_process():
    
    with Live(console=console, screen=True, auto_refresh=False) as live:
        while True:
            live.update(tmp2(), refresh=True)
            time.sleep(1)

if __name__ == "__main__":

    hop = Thread(target=create_output_process)
    hop.daemon = True
    hop.start()
    

    sniff(iface='wlx00c0ca3e91fa', prn=parseSSID)


    
    
    
            