CFLAGS=-static -Wall -Werror -Wno-error=maybe-uninitialized -I. $(EXTRA_CFLAGS)

BIN_DIR=bin

OBJS=server.o main.o thread.o logger.o rwlock.o connection.o \
    picohttpparser.o http.o jsmn.o db.o list.o memory_pool.o misc.o \
    handlers.o utf.o

veryrelease: export EXTRA_CFLAGS=-O3 -D__LOG_SIMPLE__
veryrelease: clean $(OBJS)
	mkdir -p $(BIN_DIR)
	gcc $(OBJS) -lpthread -o $(BIN_DIR)/server

release: export EXTRA_CFLAGS=-O3 -D__LOG_SIMPLE__ -D__STATS__
release: clean $(OBJS)
	mkdir -p $(BIN_DIR)
	gcc $(OBJS) -lpthread -o $(BIN_DIR)/server

perf:  export EXTRA_CFLAGS=-O0 -g3 -ggdb3 -fno-inline -D__STATS__
perf:  clean $(OBJS)
	mkdir -p $(BIN_DIR)
	gcc $(OBJS) -lpthread -o $(BIN_DIR)/server


debug:  export EXTRA_CFLAGS=-O0 -D__LOG_DEBUG__ -g3 -ggdb3 -fno-inline -D__STATS__
debug:  clean $(OBJS)
	mkdir -p $(BIN_DIR)
	gcc $(OBJS) -lpthread -o $(BIN_DIR)/server

server.o: server.c
	gcc $(CFLAGS) -c server.c
	ar -cvq server.a server.o

main.o: main.c
	gcc $(CFLAGS) -c main.c
	ar -cvq main.a main.o

thread.o: thread.c
	gcc $(CFLAGS) -c thread.c
	ar -cvq thread.a thread.o

logger.o: logger.c
	gcc $(CFLAGS) -c logger.c
	ar -cvq logger.a logger.o

rwlock.o: rwlock.c
	gcc $(CFLAGS) -c rwlock.c
	ar -cvq rwlock.a rwlock.o

connection.o: connection.c
	gcc $(CFLAGS) -c connection.c
	ar -cvq connection.a connection.o

picohttpparser.o: picohttpparser.c
	gcc $(CFLAGS) -c picohttpparser.c
	ar -cvq picohttpparser.a picohttpparser.o

http.o: http.c
	gcc $(CFLAGS) -c http.c
	ar -cvq http.a http.o

jsmn.o: jsmn.c
	gcc $(CFLAGS) -c jsmn.c
	ar -cvq jsmn.a jsmn.o

db.o: db.c
	gcc $(CFLAGS) -c db.c
	ar -cvq db.a db.o

list.o: list.c
	gcc $(CFLAGS) -c list.c
	ar -cvq list.a list.o

memory_pool.o: memory_pool.c
	gcc $(CFLAGS) -c memory_pool.c
	ar -cvq memory_pool.a memory_pool.o

misc.o: misc.c
	gcc $(CFLAGS) -c misc.c
	ar -cvq misc.a misc.o

handlers.o: handlers.c
	gcc $(CFLAGS) -c handlers.c
	ar -cvq handlers.a handlers.o

utf.o: utf.c
	gcc $(CFLAGS) -c utf.c
	ar -cvq utf.a utf.o

clean:
	rm -rf $(BIN_DIR)
	rm -f *.a
	rm -f *.o
