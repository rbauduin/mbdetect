#!/bin/bash

f=$(basename $1 .c)


gcc -ggdb -c $f.c
gcc -o $f.test $f.o -L/usr/lib/x86_64-linux-gnu -lcurl
