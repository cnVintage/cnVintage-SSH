MAKE = make

.PHONY: all

all:
	$(MAKE) -C sshd
	$(MAKE) -C shell

clean:
	$(MAKE) -C sshd clean
	$(MAKE) -C shell clean