#!/usr/bin/env python3

from bcc import BPF

source="""

"""

b = BPF(text=source)
