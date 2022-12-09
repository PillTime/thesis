#!/usr/bin/env python

from bcc import BPF


b = BPF(src_file="mac.bpf.c")


def macaddr(mac):
    ret = "{:02x}".format(mac[0])
    for b in mac[1:]:
        ret += ":{:02x}".format(b)
    return ret

def printer(cpu, data, size):
    info = b["data_out"].event(data)

    global counter
    counter += 1
    if info.fn == 1:
        print("---{:02}--- mesh_nexthop_resolve --------------------".format(counter))
    elif info.fn == 2:
        print("---{:02}--- ieee80211_mesh_rx_queued_mgmt -----------".format(counter))
    else:
        print("---{:02}--- UNKNOWN REASON --------\n".format(counter))
        return
    print("{:#018x}".format(info.skb))

    print("mac: {}".format(macaddr(info.addr)))

    print("seq num: {}".format(info.seq_num))
    print("frg num: {}".format(info.frg_num))

    print("ds byte: {}".format(info.ds_byte))
    if info.ds_byte == 0:
        mac_sa = macaddr(info.addr2)
        mac_da = macaddr(info.addr1)
        print("da: {}".format(mac_da))
        print("sa: {}".format(mac_sa))
        print("id: {}".format(macaddr(info.addr3)))
    elif info.ds_byte == 1:
        mac_sa = macaddr(info.addr2)
        mac_da = macaddr(info.addr3)
        print("da: {}".format(mac_da))
        print("sa: {}".format(mac_sa))
        print("id: {}".format(macaddr(info.addr1)))
    elif info.ds_byte == 2:
        mac_sa = macaddr(info.addr3)
        mac_da = macaddr(info.addr1)
        print("da: {}".format(mac_da))
        print("sa: {}".format(mac_sa))
        print("id: {}".format(macaddr(info.addr2)))
    elif info.ds_byte == 3:
        mac_sa = macaddr(info.addr4)
        mac_da = macaddr(info.addr3)
        print("da: {}".format(mac_da))
        print("ra: {}".format(macaddr(info.addr1)))
        print("sa: {}".format(mac_sa))
        print("ta: {}".format(macaddr(info.addr2)))
    else:
        print("UNKNOWN DS BYTE")

    flt = "wlan.seq == {} && wlan.frag == {} && wlan.sa == {} && wlan.da == {}" \
        .format(info.seq_num, info.frg_num, mac_sa, mac_da)
    print("wireshark filter:", flt)

    print()


print("Started tracing. Press Ctrl+C to stop.\n")

counter = 0
b["data_out"].open_perf_buffer(printer)
while True:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        b["pass"].clear()
        exit()
