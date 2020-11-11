#!/usr/bin/bash
export RUST_LOG=debug
IFACE=`ifconfig |grep LOOPBACK|awk -F ':' '{print $1}'`
../target/debug/skarfhttp -tl -i $IFACE -p 4000 -h user-agent,content-type  -q GET,POST -j object,activity
