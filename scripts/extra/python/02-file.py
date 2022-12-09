#!/usr/bin/env python

import yaml as yml

info = {
    "reason" : "fn1",
    "mac" : [0, 0, 0, 0, 0, 1],
    "sequence" : 12,
    "fragment" : 0,
    "ds" : 3
}

with open("test.txt", "w") as f:
    yml.dump(info, f)
