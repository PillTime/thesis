#!/usr/bin/env bash

sudo ip link set dev veth1 xdp object xdp_dropv6.o sec xdp_dropv6
