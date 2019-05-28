# Makefile for client

CC=gcc -Wall
PWD=`pwd`
BIN=../../bin/

default: crash

obj:
	cd $(OBJ)
		$(CC) -c $(PWD)/*.c

crash: crash.o utils.o
		$(CC) -o $(BIN)crash crash.o utils.o

crash.o: crash.c
		$(CC) -c crash.c

utils.o: utils.c
		$(CC) -c utils.c

clean:
		rm *.o
		rm $(BIN)*
