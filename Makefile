.PHONY: set_client_commit set_server_commit clean
COMMIT=$(shell /usr/bin/git rev-parse HEAD)
client.o: client.c utils/mbd_utils.c utils/mbd_utils.h set_version
	gcc -O0 -ggdb -c client.c utils/strlcat.c utils/strlcpy.c utils/mbd_utils.c utils/mkpath.c
client: client.o
	gcc -o client client.o strlcat.o strlcpy.o mbd_utils.o mkpath.o -L/usr/lib/x86_64-linux-gnu -lcurl -lconfig -lsodium -luuid -lcares
server.o: server.c utils/mbd_utils.c utils/mbd_utils.h utils/mongoose.c utils/mbd_utils.h utils/mongoose.h set_version utils/mkpath.c
	cc -ggdb -c server.c utils/mongoose.c utils/strlcpy.c utils/strlcat.c utils/mbd_utils.c
server: server.o
	gcc -o server server.o mongoose.o mbd_utils.o strlcat.o strlcpy.o mkpath.o -pthread -lsodium
test: client
	./client tests/curl_tests.cfg
clean: 
	rm -f *.o client server
set_version:
	echo "#define GIT_COMMIT \"$(COMMIT)\"" > utils/mbd_version.h
