CC = gcc
CXX = g++
CFLAGS = -Wall -std=c11
OBJS = server.o flarum-login.o
PROG = sshd
LDFLAGS = -lssh -lutil -lcurl
DEST = ../build

CFLAGS += -DKEYS_FOLDER="\"$(shell pwd)/../build/\""
CFLAGS += -DSHELL="\"$(shell pwd)/../build/shell\""
CFLAGS += -DPORT=\"2022\"
CFLAGS += -D_GNU_SOURCE

ifeq ($(DEBUG), FALSE)
	CFLAGS += -O2
	CFLAGS += -DFLARUM_URL=\"https://www.cnvintage.org\"
else
	CFLAGS += -O0 -g
	CFLAGS += -DFLARUM_URL=\"http://ntzyz-solaris.lan\"
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
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o $(DEST)/$(PROG) $(PROG)
