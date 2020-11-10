#!/usr/bin/bash
export RUST_LOG=debug
IFACE=`ifconfig |grep LOOPBACK|awk -F ':' '{print $1}'`
../target/debug/skarfhttp -i $IFACE -p 4000 -h user-agent,content-type -j object
