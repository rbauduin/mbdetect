#!/bin/bash

file=12_dns_ares.c
f=$(basename $file .c)


gcc -c $f.c
gcc -o $f.test $f.o -L/usr/lib/x86_64-linux-gnu -lcurl -lcares
