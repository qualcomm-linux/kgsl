ifeq ($(KGSL_MODULE_ROOT),)
KGSL_MODULE_ROOT=$(KERNEL_SRC)/$(M)
endif

KBUILD_OPTIONS+=KGSL_PATH=$(KGSL_MODULE_ROOT)

all: modules

modules_install:
	$(MAKE) INSTALL_MOD_STRIP=1 -C $(KERNEL_SRC) M=$(M) modules_install

clean:
	rm -f *.cmd *.d *.mod *.o *.ko *.mod.c *.mod.o Module.symvers modules.order

%:
	$(MAKE) -C $(KERNEL_SRC) M=$(M) $@ $(KBUILD_OPTIONS)
