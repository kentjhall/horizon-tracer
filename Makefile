KERNEL_PATH ?= /lib/modules/$(shell uname -r)/build

obj-m += horizon_tracer.o
horizon_tracer-objs := tracer.o overrides.o

all:
	make -C $(KERNEL_PATH) M=$(PWD) modules

clean:
	make -C $(KERNEL_PATH) M=$(PWD) clean
