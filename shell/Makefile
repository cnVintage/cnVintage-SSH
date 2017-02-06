CC = gcc
CCX = g++
CFLAGS = -Wall -O2 -std=gnu++11
OBJS = main.o handlers.o
PROG = shell
LDFLAGS = -lreadline
DEST = ../build
all: $(PROG)

$(PROG): $(OBJS)
	$(CCX) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)
	mkdir -p $(DEST)
	cp -r $(PROG) $(DEST)/

%.o: %.cpp
	$(CCX) $(CFLAGS) -c $<

clean:
	rm -f *.o $(DEST)/$(PROG) $(PROG)
