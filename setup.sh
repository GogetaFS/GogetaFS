#!/usr/bin/env bash

if [ -z $1 ]; then
    target=/dev/nvme0n1p1
else
    target=$1
fi

if [ -z $2 ]; then
    mountpoint=/mnt/nvme0n1p1
else
    mountpoint=$2
fi

sudo umount $target
sync

sleep 1

rmmod f2fs
make -j32
insmod f2fs.ko

sudo mkdir -p $mountpoint

sudo mkfs.f2fs -l wtf -f $target
sync

sudo mount $target $mountpoint