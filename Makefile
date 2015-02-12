
client.o: client.c utils/mbd_utils.c utils/mbd_utils.h
	gcc -ggdb -c client.c utils/strlcat.c utils/strlcpy.c utils/mbd_utils.c
client: client.o
	gcc -o client client.o strlcat.o strlcpy.o mbd_utils.o -L/usr/lib/x86_64-linux-gnu -lcurl -lconfig -lsodium
server.o: server.c utils/mbd_utils.c utils/mbd_utils.h utils/mongoose.c utils/mbd_utils.h utils/mongoose.h
	cc -ggdb -c server.c utils/mongoose.c utils/strlcpy.c utils/strlcat.c utils/mbd_utils.c
server: server.o
	gcc -o server server.o mongoose.o mbd_utils.o strlcat.o strlcpy.o -pthread -lsodium
test: client
	./client tests/curl_tests.cfg
clean: 
	rm -f *.o client server
