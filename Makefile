all: lynxdec lynxenc lynxverify

lynxdec: lynxdec.c sizes.h keys.h
	gcc -g -O0 lynxdec.c -o lynxdec -l ssl

lynxenc: lynxenc.c sizes.h keys.h
	gcc -g -O0 lynxenc.c -o lynxenc -l ssl

lynxverify: lynxverify.c sizes.h keys.h loaders.h
	gcc -g -O0 lynxverify.c -o lynxverify

clean:
	rm -rf lynxdec
	rm -rf lynxenc
	rm -rf lynxverify
