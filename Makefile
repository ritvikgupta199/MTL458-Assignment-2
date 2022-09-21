# Sets COMPILER to the default compiler for OSX and other systems
# taken from https://stackoverflow.com/questions/24563150/makefile-with-os-dependent-compiler
UNAME := $(shell uname)
ifeq ($(UNAME), Darwin)
	COMPILER = clang 
else
	COMPILER = gcc
endif

run:
	./mmu
clean:
	rm -f mmu
build:
	rm -f mmu
	$(COMPILER) mmu.c -o mmu
all:
	rm -f mmu
	$(COMPILER) mmu.c -o mmu
	./mmu