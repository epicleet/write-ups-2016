all: nimstdlib.sig
nimstdlib: nimstdlib.nim
	nim c -d:release --opt:size --cpu:mips --os:linux $<
nimstdlib.a: nimstdlib
	mips-openwrt-linux-ar qf $@ nimcache/*.o
	mips-openwrt-linux-ranlib $@
nimstdlib.sig: nimstdlib.a
	pelf nimstdlib.a
	sigmake nimstdlib.pat nimstdlib.sig
clean:
	rm -f nimstdlib.exc nimstdlib.pat nimstdlib.sig
	rm -f nimstdlib nimstdlib.a
	rm -rf nimcache
