#!/bin/bash
echo "0">/proc/sys/net/ipv4/ip_forward
iptables -t nat -D POSTROUTING 1

