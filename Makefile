MAKE = make

.PHONY: all

all:
	$(MAKE) -C sshd
	$(MAKE) -C shell
	./generate-key.sh
	
clean:
	$(MAKE) -C sshd clean
	$(MAKE) -C shell clean

distclean:
	$(MAKE) -C sshd clean
	$(MAKE) -C shell clean
	rm -rf ./build	
