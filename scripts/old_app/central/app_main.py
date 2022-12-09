#!/usr/bin/env python3

import json
import PySimpleGUI as psg
import subprocess
import sys


def _list_to_mac(addr):
    ret = "{:02x}".format(addr[0])
    for f in addr[1:]:
        ret += ":{:02x}".format(f)
    return ret

def _orderer(trace):
    return trace[1]["timestamp_action"]

def sort(traces):
    traces.sort(key=_orderer)
    # TODO: verify order makes sense (can't assign a nexthop before creating the path)
    return traces


if __name__ == "__main__":
    traces = []
    for station in sys.argv[1:]:
        bcc = json.load(open("{}-outbcc.json".format(station), "r"))
        for trace in bcc:
            traces.append((station, trace))
    traces = sort(traces)

    layout = []
    for i, trace in enumerate(traces):
        frame = [
            [ psg.Text(trace[1]["action"]) ],
            [ psg.Button("Open in Wireshark", key="ws{}".format(i)) ],
        ]
        layout.append([psg.Frame("{}".format(trace[0]), frame)])
    window = psg.Window("Mesh Analyzer", layout)

    while True:
        event, _ = window.read()
        if event == psg.WIN_CLOSED:
            break
        elif event[:2] == "ws":
            i = int(event[2:])
            if len(traces[i][1]["packets"]) < 1:
                print("no packets associated with the event")
            elif len(traces[i][1]["packets"]) > 1:
                print("more than 1 packet associated with the event")
            else:
                subprocess.call(["/usr/bin/env", "wireshark", "-g", str(traces[i][1]["packets"][0]), "-r", "{}-outscapy.pcap".format(traces[i][0])])
    window.close()
