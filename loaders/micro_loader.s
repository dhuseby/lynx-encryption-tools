; Micro Loader
; Copyright (C) 2009 David Huseby <dave@linuxprogrammer.org>
;
; This is a bare minimum Atari Lynx loader.


.psc02                  ; turn on 65SC02 instruction set

        RCART_0 = $fcb2 ; cart data register
        IODIR   = $fd8a ; I/O direction register
        IODAT   = $fd8b ; I/O data registers
        SERCTL  = $fd8c ; serial control register
        MAPCTL  = $fff9 ; memory map control register
        EXE     = $0300 ; location where exe goes

.org    $0200

        ; 1. force Mikey to be in memory
        stz MAPCTL      ; make sure Mikey access is enabled

        ; 2. set IODIR the way Mikey ROM does
        lda #3          ; a = 00000011
        sta IODIR       ; set up I/O dir register

        ; 3. set ComLynx to open collector
        lda #4          ; a = 00000100
        sta SERCTL      ; set the ComLynx to open collector

        ; 4. make sure the ROM is powered on
        lda #8          ; a = 00001000
        sta IODAT       ; set the ROM power to on

        ; 5. read in 256 bytes from the cart and store it in $0300
        ldx #0          ; x = 0
rloop:  lda RCART_0     ; read a byte from the cart
        sta EXE,X       ; EXE[X] = a
        inx             ; x++
        bne rloop       ; loops until x wraps (i.e. 256 times)
        
        ; 6. jump to the cart executable
        jmp EXE         ; run the executable
