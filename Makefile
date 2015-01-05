SHELL=/bin/bash
CC=gcc
SRCS=pkt_clone.c
OBJS=pkt_clone.o
CFLAGS=-std=c99 -pedantic -Wall -g -D_GNU_SOURCE
LFLAGS=-lpcap
PROGRAM=pkt_clone

.PHONY: depend clean

$(PROGRAM): $(SRCS) $(OBJS)
	$(CC) $(CFLAGS) $(LFLAGS) $(OBJS) -o $(PROGRAM)

$(OBJS): %.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	-rm -f $(OBJS) $(PROGRAM) *.out

# DO NOT DELETE
#
# pkt_clone.c pkt_clone.o
