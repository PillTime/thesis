#!/usr/bin/env python

from bcc import BPF


BPF(src_file="add_path.c").trace_print()


#def printer(cpu, data, size):
    #out = b["out"].event(data)
    #print("--- mesh_path_add --------------------------------")
#    print("src: %s" % out.src)
#    print("dst: %s" % out.dst)
    #print("--------------------------------------------------\n")

#b["out"].open_perf_buffer(printer)

#print("Tracing... Ctrl+C to stop.")
#while True:
    #try:
        #b.perf_buffer_poll()
    #except KeyboardInterrupt:
        #exit()
