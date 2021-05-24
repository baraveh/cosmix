include ../Defines.mk 
	  
.PHONY: clean all
		 
ifneq ($(SDK_BUILD), -DSDK_BUILD)
all:
	$(MAKE) -C common $@;
	$(MAKE) -C suvm $@;
	$(MAKE) -C storage $@;
	$(MAKE) -C oram $@;
	$(MAKE) -C address_sanitizer $@;
	$(CLANG_PATH)/llvm-link common/common.bc suvm/suvm_runtime.bc storage/storage_runtime.bc oram/oram.bc address_sanitizer/address_sanitizer.bc -o mstores.bc 
	
else
all:
	$(MAKE) -C common $@;
	$(MAKE) -C suvm $@;
	$(MAKE) -C address_sanitizer $@;
endif
					  
clean:
	$(MAKE) -C common clean;
	$(MAKE) -C suvm clean;
	$(MAKE) -C storage clean;
	$(MAKE) -C oram clean;
	$(MAKE) -C address_sanitizer clean;
	rm -rf *.bc
