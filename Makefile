CC = gcc
LIBS = -lpthread -lpcap -lnet

all:
	$(CC) -g -c convert.c $(LIBS)
	$(CC) -g -c libnet.c $(LIBS)

	$(CC) -g -o libnet  libnet.o convert.o $(LIBS)
	
	rm *.o