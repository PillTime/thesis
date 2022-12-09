from bcc import BPF
from enum import Enum
import json
import psutil
import threading as thrd
import time

# TODO: make this work with any type of trace setup, not hardcoded


class Action(Enum):
    ACT_TX_ADD = 1
    ACT_TX_ASG = 2
    ACT_TX_CHG = 3
    ACT_TX_ADD_ASG = 4
    ACT_TX_DEL = 5
    ACT_RX_ADD = 6
    ACT_RX_ASG = 7
    ACT_RX_CHG = 8
    ACT_RX_ADD_ASG = 9
    ACT_RX_DEL = 10
    ACT_US_ASG = 11
    ACT_US_ADD_ASG = 12
    ACT_US_CHG = 13
    ACT_US_DEL = 14

ACTIONS = [
    "UNKNOWN",
    "TX - add path without nexthop",
    "TX - assign nexthop to path",
    "TX - change nexthop of path",
    "TX - add path with nexthop",
    "TX - delete path",
    "RX - add path without nexthop",
    "RX - assign nexthop to path",
    "RX - change nexthop of path",
    "RX - add path with nexthop",
    "RX - delete path",
    "US - assign nexthop to path",
    "US - add a path with nexthop",
    "US - change nexthop of path",
    "US - delete path",
]


class AsyncTracer:
    def __init__(self, output_file):
        self.bpf = BPF(src_file="tracer.bpf.c")
        self.traces = 0
        self.thread = thrd.Thread(target=self._run)
        self.thread.daemon = True
        self.continue_tracing = True
        self.btime = psutil.boot_time()
        self.output_file = open(output_file, "w")

    def _poll(self, cpu, data, size):
        self.traces += 1
        info = self.bpf["dataout"].event(data)

        qos_ctrl = None
        addr4 = None

        hasqos = 0x0008 | 0x0080
        checkqos = 0x000c | 0x0080
        if (info.frm_ctrl & checkqos) == hasqos:
            qos_ctrl = hex(info.qos_ctrl)
        check4addr = 0x0100 | 0x0200
        if (info.frm_ctrl & check4addr) == check4addr:
            addr4 = list(info.addr4)

        dataout = {
            "counter"         : self.traces,
            "mac"             : list(info.mac),
            "interface"       : str(info.iface, "UTF-8"),
            "timestamp_action": self.btime + info.ts_action / (10**9),
            "timestamp_txrx"  : self.btime + info.ts_txrx / (10**9),
            "action"          : ACTIONS[info.action],
            "action_id"       : info.action,
            "frame_control"   : hex(info.frm_ctrl),
            "sequence_control": hex(info.seq_ctrl),
            "qos_control"     : qos_ctrl,
            "from_ds"         : bool(info.frm_ctrl & 0x0200),
            "to_ds"           : bool(info.frm_ctrl & 0x0100),
            "fragment_number" : info.seq_ctrl & 0xf,
            "sequence_number" : info.seq_ctrl >> 4,
            "addr1"           : list(info.addr1),
            "addr2"           : list(info.addr2),
            "addr3"           : list(info.addr3),
            "addr4"           : addr4,
            "destiny"         : list(info.dst),
            "old_nexthop"     : list(info.old_nh),
            "new_nexthop"     : list(info.new_nh),
            "packets"         : []
        }
        if self.traces != 1:
            self.output_file.write(",\n" + json.dumps(dataout))
        else:
            self.output_file.write(json.dumps(dataout))

    def _run(self):
        self.output_file.write("[\n")
        self.bpf["dataout"].open_perf_buffer(self._poll)
        while self.continue_tracing:
            self.bpf.perf_buffer_poll(500)

    def start(self):
        self.thread.start()

    def stop(self):
        self.continue_tracing = False
        self.thread.join()
        self.output_file.write("]\n")
        self.output_file.close()
