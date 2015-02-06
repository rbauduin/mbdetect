gcc -c 04_host_mismatch.c
gcc -o 04_host_mismatch.test 04_host_mismatch.o -L/usr/lib/x86_64-linux-gnu -lcurl
