from bcc import BPF
import json
import threading as thrd
import time

# TODO: make this work with any type of trace setup, not hardcoded


REASONS = [
    "REASON_UNKNOWN",
    "mesh_nexthop_resolve (add/tx)",
    "ieee80211_mesh_rx_queued_mgmt (add/rx)"
]


class AsyncTracer:
    def __init__(self, output_file):
        self.bpf = BPF(src_file="tracer.bpf.c")
        self.traces = 0
        self.thread = thrd.Thread(target=self._run)
        self.thread.daemon = True
        self.continue_tracing = True
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
            "timestamp_boot"  : info.ts,
            "timestamp_unix"  : int(time.time()),
            "reason"          : REASONS[info.reason],
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
