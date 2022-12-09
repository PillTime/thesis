#!/usr/bin/env python

from bcc import BPF
#from scapy.all import *


b = BPF(src_file="mac_header.c")


def macaddr(addr):
    ret = "{:02x}".format(addr[0])
    for b in addr[1:]:
        ret += ":{:02x}".format(b)
    return ret

def printer(cpu, data, size):
    info = b["data_out"].event(data)

    if info.fn == 1:
        print("----- mesh_nexthop_resolve -----------------------")
    elif info.fn == 2:
        print("----- ieee80211_mesh_rx_queued_mgmt --------------")
    else:
        print("----- UNKNOWN REASON -----------------------------\n")
        return

    print("mac addr: {}".format(macaddr(info.mac)))
    print("skb mem: {:#018x}".format(info.skb))
    print("seq num: {}".format(info.seq_num))
    print("frm num: {}".format(info.frm_num))

    addr1 = macaddr(info.addr1)
    addr2 = macaddr(info.addr2)
    addr3 = macaddr(info.addr3)
    addr4 = macaddr(info.addr4)

    if info.ds_from == info.ds_to == 0:
        print("da addr: {}".format(addr1))
        print("sa addr: {}".format(addr2))
        print("id addr: {}".format(addr3))
    elif info.ds_from == info.ds_to == 1:
        print("ra addr: {}".format(addr1))
        print("ta addr: {}".format(addr2))
        print("da addr: {}".format(addr3))
        print("sa addr: {}".format(addr4))
    elif info.ds_from == 1:
        print("da addr: {}".format(addr1))
        print("id addr: {}".format(addr2))
        print("sa addr: {}".format(addr3))
    elif info.ds_to == 1:
        print("id addr: {}".format(addr1))
        print("sa addr: {}".format(addr2))
        print("da addr: {}".format(addr3))
    else:
        print("unknown DS byte")
    print()


print("Started tracing. Press Ctrl+C to stop.")

b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        b["data_out"].clear()
        exit()
