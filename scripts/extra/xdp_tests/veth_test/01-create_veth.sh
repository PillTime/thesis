#!/usr/bin/env bash

sudo ip link add dev veth0 type veth peer name veth1
sudo ip link set up dev veth0
sudo ip link set up dev veth1
