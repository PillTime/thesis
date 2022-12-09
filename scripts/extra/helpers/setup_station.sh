#!/usr/bin/env bash
# verified with shellcheck

# if asked for help, show help
case $1 in
    '-h'|'--help')
        echo "Usage: $0 STATION_NUMBER SCRIPT_LOCATION"
        exit 0
esac

# verify number of arguments
[ $# -ne 2 ] && echo 'Need the number of the station and script location as arguments.' && exit 1

# verify argument is valid
[ "$1" -lt 1 ] || [ "$1" -gt 3 ] && echo "Argument should be value between 1 and 3." && exit 2

# set name of station
station_name="sta$1"

# get pid of station
station_pid=$(pgrep -f "mininet:$station_name\$")

working_dir=$(pwd)

# verify that station was found
[ -z "$station_pid" ] && echo -e 'No station found.\nMake sure mininet is running.' && exit 3

# set interface to monitor, mount debugfs, and start the script
# (mount ends with ; because it might fail (if debugfs is already mounted))
sudo nsenter -at "$station_pid" bash -c "\
ifconfig $station_name-wlan0 down && \
iw $station_name-wlan0 set monitor none && \
ifconfig $station_name-wlan0 up && \
mount -t debugfs none /sys/kernel/debug 2> /dev/null ; \
cd $working_dir && \
$(realpath "$2") $station_name $station_name-wlan0"
