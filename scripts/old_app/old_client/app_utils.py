import json
import os
import scapy.all as scp
import sys


# TODO: some packets might not have toDS fromDS fields. careful (9.2.4.1.1)


def check_output_files(file_bcc, file_scapy):
    exists_bcc = os.path.exists(file_bcc)
    exists_scapy = os.path.exists(file_scapy)

    if exists_bcc or exists_scapy:
        print("At least one of these files already exist:")
        print("\t{}".format(file_bcc))
        print("\t{}".format(file_scapy))
        print("If you continue, they'll be overwritten.")

        user_input = input("Do you want to continue (Y/N)? ").lower()
        while user_input not in ["n", "y", "no", "yes"]:
            user_input = input("Do you want to continue (Y/N)? ").lower()

        if user_input in ["n", "no"]:
            print("User canceled the script.")
            sys.exit(0)
        else:
            if exists_bcc:
                os.remove(file_bcc)
            if exists_scapy:
                os.remove(file_scapy)


def _mac_list_to_str(addr):
    ret = "{:02x}".format(addr[0])
    for f in addr[1:]:
        ret += ":{:02x}".format(f)
    return ret


def _trace_packet_match(trace, packet):
    # check mac80211 layer
    if scp.Dot11 not in packet:
        return False

    # check DS bits
    if "from-DS" in packet.FCfield:
        packet_fromds = True
    else:
        packet_fromds = False
    if "to-DS" in packet.FCfield:
        packet_tods = True
    else:
        packet_tods = False
    if packet_fromds != trace["from_ds"] or packet_tods != trace["to_ds"]:
        return False

    # check sequence control
    if packet.SC is not None and hex(packet.SC) != trace["sequence_control"]:
        return False

    # check addresses
    addresses = _mac_list_to_str(trace["addr2"]) == packet.addr2
    addresses &= _mac_list_to_str(trace["addr3"]) == packet.addr3
    if packet_fromds and packet_tods:
        addresses &= _mac_list_to_str(trace["addr4"]) == packet.addr4
    # mesh_nexthop_resolve addr1 problem
    if trace["reason"] != "mesh_nexthop_resolve (add/tx)":
        addresses &= _mac_list_to_str(trace["addr1"]) == packet.addr1
    return addresses


# O(n^2), but can't really improve that much because the order of traces and
# packets isn't necessarily the same (e.g.: it's possible for trace 1 to be
# related to packet 8 while trace 2 is related to packet 6)
def relate(list_traces, list_packets):
    for t in range(len(list_traces)):
        for p in range(len(list_packets)):
            if _trace_packet_match(list_traces[t], list_packets[p]):
                list_traces[t]["packets"].append(p + 1)
    return list_traces
