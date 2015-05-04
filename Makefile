.PHONY: set_client_commit set_server_commit clean
COMMIT=$(shell /usr/bin/git rev-parse HEAD)
client.o: client.c utils/mbd_utils.c utils/mbd_utils.h set_version utils/mptcp_ctrl.c
	${CC} -O0 -ggdb -c client.c utils/strlcat.c utils/strlcpy.c utils/mbd_utils.c utils/mkpath.c utils/slist.c utils/mptcp_ctrl.c utils/uuid/gen_uuid.c utils/uuid/pack.c utils/uuid/unpack.c -Iinclude
client: client.o
	${CC} -o client client.o strlcat.o strlcpy.o mbd_utils.o mkpath.o slist.o mptcp_ctrl.o gen_uuid.o pack.o unpack.o -Llib -lcurl -lconfig -lsodium -lcares
server.o: server.c utils/mbd_utils.c utils/mbd_utils.h utils/mongoose.c utils/mbd_utils.h utils/mongoose.h set_version utils/mkpath.c utils/repl_str.c
	${CC} -ggdb -c server.c utils/mongoose.c utils/strlcpy.c utils/strlcat.c utils/mbd_utils.c utils/repl_str.c utils/mkpath.c
server: server.o
	${CC} -o server server.o mongoose.o mbd_utils.o strlcat.o strlcpy.o mkpath.o repl_str.o -pthread -lsodium
test: client
	./client tests/curl_tests.cfg
clean: 
	rm -f *.o client server
set_version:
	echo "#define GIT_COMMIT \"$(COMMIT)\"" > utils/mbd_version.h
