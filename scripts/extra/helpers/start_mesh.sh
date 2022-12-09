#!/usr/bin/env bash

echo "Creates/connects to mesh network"

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root"
   exit 1
fi

_check_can_use_mesh(){
  phy=$(iw dev $1 info | awk '/wiphy/{ print $NF }')
  ibss=$(iw phy "phy$phy" info | grep -A 10 "Supported interface modes" | grep "*" | grep "mesh")
  if [ -z "$ibss" ]
  then
    echo "Interface $1 does NOT support mesh mode, please use other interface"
    exit 1
  fi
}


freq="2412"

_create_node(){
    iface="$2"
    addr="192.168.50.$1"
    ip link set $iface down
    iw dev $iface set type mesh
    already_set=$(ip addr show $iface to $addr)
    if [ -z "$already_set" ]
    then
        sudo ip addr add dev $iface "$addr"/24
    fi
    ip link set $iface up
    iw dev $iface mesh join hello freq $freq HT40+
    echo "Connected with IP address $addr"
}

_down(){
    iw dev $1 mesh leave
    ip link set $1 down
    ip addr flush dev $1
    echo "Disconnected"
}

help(){
    printf "Use 'up[1..5] \$interface' to setup node 1, 2, 3, 4, or 5.\
    \nUse 'down \$interface' turn off the mode for interface.\n"
}

case "$1" in
  up1)
    _check_can_use_mesh $2
    _create_node "1" $2
    ;;
  up2)
    _check_can_use_mesh $2
    _create_node "2" $2
    ;;
  up3)
    _check_can_use_mesh $2
    _create_node "3" $2
    ;;
  up4)
    _check_can_use_mesh $2
    _create_node "4" $2
    ;;
  up5)
    _check_can_use_mesh $2
    _create_node "5" $2
    ;;
  up6)
    _check_can_use_mesh $2
    _create_node "6" $2
    ;;
  up7)
    _check_can_use_mesh $2
    _create_node "7" $2
    ;;
  up8)
    _check_can_use_mesh $2
    _create_node "8" $2
    ;;
  down)
    _down $2
  ;;
  *)
    help
    ;;
esac
exit 0
