horizon-tracer
===========

Linux kernel module for tracing Horizon system calls, scheduler, and likely more
in the future (e.g. I'll make it easy to trace **horizon_servctl** calls for
tracing service interactions), for [Horizon
Linux](https://github.com/kentjhall/horizon-linux) kernel debugging purposes.
Horizon system calls can be overriden using the provided macros in *overrides.c*
(see the example there).

The code is licensed under GPLv2.

This is based on a very helpful [ftrace example
repo](https://github.com/ilammy/ftrace-hook).

Build/Run
------------

Install the required dependencies:
```
# apt install build-essential linux-headers-$(uname -r)
```

Then run:
```
$ make
```

And install the module:
```
# insmod horizon_tracer.ko
```

Observe trace output while a Horizon task is running:
```
# dmesg -w
```

And when you're done, remove the module:
```
# rmmod horizon_tracer.ko
```
