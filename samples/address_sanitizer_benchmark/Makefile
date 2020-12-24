include ../../Defines.mk

current_dir = $(shell pwd)

all : address_sanitizer

cosmix:
	make -C ../../pass -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" SUVM_MIN_PTR_SIZE="-DSUVM_MIN_PTR_SIZE=1" SUVM_MAX_PTR_SIZE="-DSUVM_MAX_PTR_SIZE=1073741824" ORAM_BITS="-DORAM_BITS=28";
	make -C ../../runtime -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" SUVM_MIN_PTR_SIZE="-DSUVM_MIN_PTR_SIZE=1" SUVM_MAX_PTR_SIZE="-DSUVM_MAX_PTR_SIZE=1073741824" ORAM_BITS="-DORAM_BITS=28";
	make -C ../../mstores -f Makefile SDK_BUILD="-DSCONE_BUILD" NO_COUNTERS="-DNO_COUNTERS" RELEASE_BUILD="-DRELEASE_BUILD" SUVM_MIN_PTR_SIZE="-DSUVM_MIN_PTR_SIZE=1" SUVM_MAX_PTR_SIZE="-DSUVM_MAX_PTR_SIZE=1073741824" ORAM_BITS="-DORAM_BITS=28";

address_sanitizer: test.c cosmix
	$(LLVM_BIN)/clang -O3 -emit-llvm -c test.c "-DADDRESS_SANITIZER_TEST" -o test.bc
	$(LLVM_BIN)/llvm-link test.bc ../../runtime/cosmix_runtime.bc ../../mstores/address_sanitizer/address_sanitizer.bc ../../mstores/common/common.bc -o test_wrappers.bc
	$(LLVM_BIN)/opt < test_wrappers.bc -gvn -gvn-hoist -gvn-sink -loop-simplify -licm > test_loop_simplify.bc
	$(LLVM_BIN)/opt -load ../../pass/cosmix.so < test_loop_simplify.bc -cosmix -replace_all_allocators=false -code_analysis=false -config_file=$(current_dir)/address_sanitizer.json > test_inst.bc
	$(LLVM_BIN)/opt -O3 < test_inst.bc > test_opt.bc
	$(LLVM_BIN)/llc -relocation-model=pic -filetype=obj test_opt.bc -o test.o
	g++ test.o -o address_sanitizer


clean:
	make -C ../../pass -f Makefile clean &> /dev/null;
	make -C ../../runtime -f Makefile clean &> /dev/null;
	rm -rf *.bc *.o *.log *.bin address_sanitizer
