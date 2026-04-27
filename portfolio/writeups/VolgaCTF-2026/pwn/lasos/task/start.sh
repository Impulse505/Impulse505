#!/bin/sh
qemu-system-x86_64 -drive format=raw,file=./image.bin -serial stdio -enable-kvm -cpu host -display none -no-reboot -snapshot
