all: lynxdec lynxenc

lynxdec: lynxdec.c sizes.h keys.h
	gcc -gstabs+ -O0 lynxdec.c -o lynxdec -l ssl

lynxenc: lynxenc.c sizes.h keys.h
	gcc -gstabs+ -O0 lynxenc.c -o lynxenc -l ssl

clean:
	rm -rf lynxdec
	rm -rf lynxenc
