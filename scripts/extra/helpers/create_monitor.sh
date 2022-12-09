#!/usr/bin/env bash
# verified with shellcheck

# if asked for help, show help
case $1 in
    '-h'|'--help')
      echo "Usage: $0 (add|del) STATION_NAME ORIGAL_INTERFACE"
        exit 0
esac

# verify number of arguments
[ $# -ne 3 ] && echo 'Need the mesh interface and station names as arguments.' && exit 1

mon="$2-mon"
phy=$(iw dev | awk "/^phy/{phy=\$1};/Interface $3/{sub(/#/,\"\",phy);print phy}")

# TODO: check that a monitor can be created and exit early if not

case $1 in
    'add')
        sudo iw phy "$phy" interface add "$mon" type monitor
        sudo ifconfig "$mon" up
        echo "The new monitor interface '$mon' is up and running!"
        ;;
    'del')
        sudo ifconfig "$mon" down
        sudo iw dev "$mon" del
        echo "The monitor interface '$mon' has been shutdown and removed!"
        ;;
    *)
        echo 'Unknown command.'
        exit 1
        ;;
esac
