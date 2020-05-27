obj-m := server.o
KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
all:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) clean

install:
	make
	gcc client.c -o client.o
	sudo mknod /dev/ckq c 124 0
	sudo chmod 777 /dev/ckq
	sudo dmesg -c > /dev/null
	sudo insmod server.ko

uninstall:
	make clean
	sudo rm -f /dev/ckq
	sudo rmmod server.ko
