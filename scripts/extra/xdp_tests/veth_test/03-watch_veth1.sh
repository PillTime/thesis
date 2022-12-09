#!/usr/bin/env bash

sudo tcpdump "ip6" -i veth1 -w captured.pcap -c 10 &
