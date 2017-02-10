CC = gcc
CXX = g++
CFLAGS = -Wall -O2 -std=gnu++11
OBJS = main.o handlers.o
PROG = shell
LDFLAGS = -lreadline
DEST = ../build
all: $(PROG)

$(PROG): $(OBJS)
	$(CXX) $(CFLAGS) $(OBJS) -o $@ $(LDFLAGS) $(LDLIBS)
	mkdir -p $(DEST)
	cp -r $(PROG) $(DEST)/

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $<

clean:
	rm -f *.o $(DEST)/$(PROG) $(PROG)
