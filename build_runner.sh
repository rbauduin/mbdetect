#!/bin/bash

f=$(basename $1 .c)


gcc -ggdb -c $f.c utils/strlcpy.c utils/mbd_utils.c
gcc -o $f.test $f.o strlcpy.o mbd_utils.o -L/usr/lib/x86_64-linux-gnu -lcurl -lconfig -lsodium
