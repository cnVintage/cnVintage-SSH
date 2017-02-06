CC = gcc
CCX = g++
CFLAGS = -Wall -O2 -std=gnu++11 -D KEYS_FOLDER="\"$(shell pwd)/../build/\"" -D SHELL="\"$(shell pwd)/../build/shell\""
OBJS = server.o
PROG = sshd
LDFLAGS = -lssh -lutil
DEST = ../build
all: $(PROG)

$(PROG): $(OBJS)
	$(CCX) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)
	mkdir -p $(DEST)
	cp -r $(PROG) $(DEST)

%.o: %.cpp
	$(CCX) $(CFLAGS) -c $<

clean:
	rm -f *.o $(DEST)/$(PROG) $(PROG)
