CC = gcc
CCX = g++
CFLAGS = -Wall -std=c11 -D KEYS_FOLDER="\"$(shell pwd)/../build/\"" -D SHELL="\"$(shell pwd)/../build/shell\"" -D PORT=\"2022\" -D _GNU_SOURCE 
OBJS = server.o flarum-login.o
PROG = sshd
LDFLAGS = -lssh -lutil -lcurl
DEST = ../build

ifeq ($(DEBUG), FALSE)
	CFLAGS += -O2
else
	CFLAGS += -O0 -g
endif

ifeq ($(shell uname), Darwin)
	CFLAGS += -DHAVE_UTIL_H
endif

all: $(PROG)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)
	mkdir -p $(DEST)
	cp -r $(PROG) $(DEST)

%.o: %.cpp
	$(CCX) $(CFLAGS) -c $<

clean:
	rm -f *.o $(DEST)/$(PROG) $(PROG)
