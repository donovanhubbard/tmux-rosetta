#!/usr/env/bin bash

xxd recvmsg.bin | awk '{ print $2,$3,$4,$5,$6,$7,$8,$9 }' | tr -d " " | tr -d '\n'
echo ""
