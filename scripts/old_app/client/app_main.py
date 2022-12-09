#!/usr/bin/env python3

import app_bcc as bcc
import app_utils as util
import json
import scapy.all as scp
import signal as sig
import sys


# TODO: optional tcpdump filter for packet capture


if __name__ == "__main__":
    interface = sys.argv[1]
    station = sys.argv[2]

    # set names of output files
    file_output_bcc = "{}-outbcc.json".format(station)
    file_output_scapy = "{}-outscapy.pcap".format(station)

    # check if output files already exist (and delete them if they do)
    util.check_output_files(file_output_bcc, file_output_scapy)

    # create threads and start them
    bcc_thread = bcc.AsyncTracer(file_output_bcc)
    scapy_thread = scp.AsyncSniffer(
        store=False,
        monitor=True,
        iface=interface,
        prn=lambda pkt: scp.wrpcap(file_output_scapy, pkt, append=True)
    )
    bcc_thread.start()
    scapy_thread.start()

    # main "loop"
    try:
        print("Ready!")
        sig.pause()
    except KeyboardInterrupt:
        print("\rDone!")
        # the '\r' removes the '^C' from doing Ctrl+C

    # stop the threads (save output files)
    bcc_thread.stop()
    scapy_thread.stop()

    # read files contents into objects
    with open(file_output_bcc, "r") as file_bcc:
        traces = json.load(file_bcc)
    packets = scp.rdpcap(file_output_scapy)

    # identify packets corresponding to events
    traces = util.relate(traces, packets)
    with open(file_output_bcc, "w") as file_bcc:
        json.dump(traces, file_bcc, indent=2)
