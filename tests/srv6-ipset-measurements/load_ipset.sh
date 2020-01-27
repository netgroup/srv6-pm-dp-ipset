#!/bin/bash

IPSET_FOLDER=../../.
IPSET_FOLDER_KERN_NF="${IPSET_FOLDER}/kernel/net/netfilter"

# Load nfnetlink before doing anything
modprobe nfnetlink

#Modules must be loaded in this order!
insmod "${IPSET_FOLDER_KERN_NF}/ipset/ip_set.ko"
insmod "${IPSET_FOLDER_KERN_NF}/xt_set.ko"
insmod "${IPSET_FOLDER_KERN_NF}/ipset/ip_set_hash_sr6.ko"
