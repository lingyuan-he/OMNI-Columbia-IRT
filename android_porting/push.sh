#!/bin/sh

# Unified Heterogeneous Networking Middleware
# Android Cross Compile - Push Compiled Executable
# Lingyuan He - 05/2015

# prepare android folders
adb shell "su -c 'chmod 777 /data; chmod 777 /data/misc'"
adb shell mkdir -p /data/misc/install
adb shell mkdir -p /data/misc/install/odtone
adb shell mkdir -p /data/misc/install/hipl
adb shell mkdir -p /data/misc/install/sine

# prepare android environment
adb shell "su -c 'mount -o remount,rw /; mount -o remount,rw /system; mkdir -p /var/lock; mkdir -p /etc/hip'"

# install folder
cd ./install

# push odtone components
adb push odtone /data/misc/install/odtone

# push sine component 
adb push sine /data/misc/install/sine

# libraries for hipl
adb push lib/libmnl.so.0 /data/misc/install/hipl
adb push lib/libnfnetlink.so.0 /data/misc/install/hipl
adb push lib/libnetfilter_queue.so.1 /data/misc/install/hipl

# push hipl
cd ./hipl
adb push sbin/hipd /data/misc/install/hipl
adb push sbin/hipfw /data/misc/install/hipl
adb push sbin/hipconf /data/misc/install/hipl
adb push etc/hip/hipd.conf /data/misc/install/hipl
adb push etc/hip/relay.conf /data/misc/install/hipl
adb push etc/hip/hipfw.conf /data/misc/install/hipl

# copy file into correct privileged folder
adb shell "su -c 'cp /data/misc/install/hipl/hipd.conf /etc/hip; cp /data/misc/install/hipl/relay.conf /etc/hip; cp /data/misc/install/hipl/hipfw.conf /etc/hip'"
adb shell "su -c 'cp /data/misc/install/hipl/libmnl.so.0 /system/lib; cp /data/misc/install/hipl/libnfnetlink.so.0 /system/lib; cp /data/misc/install/hipl/libnetfilter_queue.so.1 /system/lib'"

echo ""
echo "All done, you now have hipl, odtone and middleware in /data/misc/install"
echo ""

