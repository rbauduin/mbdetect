
client.o: client.c utils/mbd_utils.c
	gcc -ggdb -c client.c utils/strlcpy.c utils/mbd_utils.c
client: client.o
	gcc -o client client.o strlcpy.o mbd_utils.o -L/usr/lib/x86_64-linux-gnu -lcurl -lconfig -lsodium
server.o: server.c utils/mbd_utils.c
	gcc -ggdb -c server.c utils/mongoose.c utils/strlcpy.c utils/mbd_utils.c
server: server.o
	gcc -o server server.o mongoose.o -pthread -lsodium
test: client
	./client tests/curl_tests.cfg
