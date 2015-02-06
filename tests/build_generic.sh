#!/bin/bash

f=$(basename $1 .c)


gcc -ggdb -c $f.c strlcpy.c
gcc -o $f.test $f.o strlcpy.o -L/usr/lib/x86_64-linux-gnu -lcurl -lconfig -lsodium
