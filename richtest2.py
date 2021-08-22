"""Lite simulation of the top linux command."""
import datetime
import random
import sys
import time
from scapy.all import sniff
from rich.console import Console
from rich.live import Live
from rich.table import Table
from rich.layout import Layout
from threading import Thread

console = Console()

table = Table(show_header=True, header_style='bold #2070b2',
                title='[bold]ACTIVE Access Points')

def make_layout() -> Layout:
    """Define the layout."""
    layout = Layout(name="root")

    layout.split(
        Layout(name="header"),
        Layout(name="footer")
    )

    return layout

def make_top_grid() :
    
    table.add_column('MAC', justify='right')
    table.add_column('SSID', justify='right')
    table.add_column('dBm')
    table.add_column('Channel', justify='center')
    table.add_column('Encryption', justify='center')
    table.add_column('Vendor')
    # table.add_row(
    #     str("bssid"),str(datetime.datetime.now()),str(datetime.datetime.now()),
    #     str(datetime.datetime.now()),str(datetime.datetime.now()),str(datetime.datetime.now())
    # )
    return table

def parseSSID(pkt) -> Table:
    bssid = str(pkt.addr3)
    table.add_row(
        str("bssid"),str(datetime.datetime.now()),str(datetime.datetime.now()),
        str(datetime.datetime.now()),str(datetime.datetime.now()),str(datetime.datetime.now())
    )

def create_output_process():
    layout = make_layout()
    layout["header"].update(make_top_grid())

    with Live(layout, refresh_per_second=10, screen=True) as live:
        while True:
            # layout["header"].update(make_top_grid())
            time.sleep(1)

if __name__ == "__main__":

    hop = Thread(target=create_output_process)
    hop.daemon = True
    hop.start()
    

    sniff(iface='wlx00c0ca3e91fa', prn=parseSSID)


    
    
    
            