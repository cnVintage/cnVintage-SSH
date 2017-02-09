CC = gcc
CCX = g++
CFLAGS = -Wall -O2 -std=c11 -D KEYS_FOLDER="\"$(shell pwd)/../build/\"" -D SHELL="\"$(shell pwd)/../build/shell\"" -D PORT=\"2022\"
OBJS = server.o flarum-login.o
PROG = sshd
LDFLAGS = -lssh -lutil -lcurl
DEST = ../build

CFLAGS += -g
LDFLAGS += -g

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)
	mkdir -p $(DEST)
	cp -r $(PROG) $(DEST)

%.o: %.cpp
	$(CCX) $(CFLAGS) -c $<

clean:
	rm -f *.o $(DEST)/$(PROG) $(PROG)
