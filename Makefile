ifeq ($(KGSL_MODULE_ROOT),)
CUR_MKFILE = $(abspath $(lastword $(MAKEFILE_LIST)))
KGSL_MODULE_ROOT = $(dir $(CUR_MKFILE))
endif

KBUILD_OPTIONS+=KGSL_PATH=$(KGSL_MODULE_ROOT)

SRC := $(shell pwd)

all:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) modules $(KBUILD_OPTIONS)

modules_install:
	$(MAKE) M=$(SRC) -C $(KERNEL_SRC) modules_install
%:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) $@ $(KBUILD_OPTIONS)
clean:
	$(MAKE) -C $(KERNEL_SRC) M=$(SRC) clean
