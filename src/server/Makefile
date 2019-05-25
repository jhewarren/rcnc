
# Makefile for sns: sniffnsend

CC=gcc -g
CLIB=-lpcap
LIBS=-../shared
SVR=`pwd`

default: sniffnsend

sniffnsend: 
	$(CC)  $(CLIB) -o sns $(LIBS)/sniffnsend.o \
	$(LIBS)/proc_ether.o $(LIBS)/proc_hdrs.o $(LIBS)/proc_payload.o \
	$(LIBS)/inot-ex.o $(LIBS)/keylog.o

libs:
	cd $(LIBS) && \
		$(CC) -c proc_ether.c && \
		$(CC) -c proc_hdrs.c && \
		$(CC) -c proc_payload.c && \
		$(CC) -c inot-ex.c && \
		$(CC) -c keylog.c && \
		$(CC) -c $(SVR)/sniffnsend.c
	cd ..

clean:
	rm -f *.o $(LIBS)/*.o core sns

sniffnsend.o: sniffnsend.c
		$(CC) -c ../sniffnsend.c

proc_ether.o: proc_ether.c
	$(CC) -c proc_ether.c

proc_hdrs.o: proc_hdrs.c
	$(CC) -c proc_hdrs.c

proc_payload.o: proc_payload.c
	$(CC) -c proc_payload.c

keylog.o:  keylog.c
	$(CC) -c  keylog.c
	
inot-ex.o: inot-ex.c
	$(CC) -c inot-ex.c
