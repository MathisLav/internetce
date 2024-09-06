; SHA256


; ******* equates *******
; RomCalls
?_frameset             :=     000012Ch
?_frameset0            :=     0000130h

; Commands
?SHA256_CTRL_BEGIN     :=   0Ah
?SHA256_CTRL_CONTINUE  :=   0Eh
; SHA256 ports offsets
?shaCtrl               :=  00h  ; 1 byte
?shaBusy               :=  01h  ; 1 byte
?shaEnable             :=  09h  ; 1 byte
?shaBlock              :=  10h  ; 40h bytes
?shaState              :=  60h  ; 20h bytes
; SHA256 ports addresses
?mpShaRange		       :=     0E10000h
?mpShaCtrl		       :=     mpShaRange + shaCtrl
?mpShaBusy             :=     mpShaRange + shaBusy
?mpShaEnable           :=     mpShaRange + shaEnable
?mpShaBlock		       :=     mpShaRange + shaBlock
?mpShaState		       :=     mpShaRange + shaState



; For a "Hello" hash -> takes ~4_000 cycles + flash_(un)lock calls
; All inclusive, it takes ~17_000 cycles
; For a 150-chars hash -> takes ~7_800 cycles + flash_(un)lock calls
; All inclusive, it takes ~30_000 cycles
	section .text
    public _sha256
_sha256:
    ; ix+6: src
    ; ix+9: size
    ; ix+12: dst (must be 32-byte long)
    di
    ld hl, -128  ; 128=Max needed size for the buffer
    call _frameset
    call _flash_unlock  ; 12923 cycles

    ld iy, mpShaRange
    ld (iy+shaEnable), 1
    ld (iy+shaCtrl), 10h
    ld (iy+shaCtrl), 0

    ld hl, (ix+9)
    add hl, hl  ; nb bytes -> nb bits (x8)
    add hl, hl
    add hl, hl
    ld (total_size), hl

    ld a, SHA256_CTRL_BEGIN
    ld (next_command), a

.common_loop:
    ld hl, (ix+9)
    ld de, 64
    or a, a
    sbc hl, de
    jr c, .end_loop
    ld (ix+9), hl
    ld hl, (ix+6)
    call round_sha256
    ld (ix+6), hl
    jr .common_loop

.end_loop:
    add hl, de  ; -> HL (L) remainder
    ld bc, 0
    ld c, l
    ld a, 64 - (1 + 8)  ; 8 -> size space, 1 -> 0x80
    sub a, c
    ld l, 64-4
    jr nc, .one_round_left
    ld l, 128-4
.one_round_left:
    ex af, af'

    ; L -> buffer_size
    ; BC -> remaining data size
    ; IX-128 -> buffer
    lea de, ix-128
    xor a, a
    cp a, c
    ld a, l
    jr z, .no_data
    ld hl, (ix+6)
    ldir
.no_data:
    ex de, hl
    ld (hl), 0x80
    inc hl
    lea de, ix-128
    or a, a
    sbc hl, de  ; HL -> copied size (BC before ldir)
    sub a, l
    ld c, a  ; BC -> remaining buffer size
    add hl, de  ; HL -> First byte to 0
    ld (hl), 0
    ex de, hl
    sbc hl, hl  ; c flag reset by add
    add hl, de
    inc de
    ldir
    ; de -> points to msb of total size field (DE=HL+1)
    ld hl, (total_size)
    ld a, (total_size+2)
    ex de, hl
    ld (hl), a
    inc hl
    ld (hl), d
    inc hl
    ld (hl), e

    ; BUFFER COMPLETED!
    lea hl, ix-128
    call round_sha256
    ex af, af'  ; c flag set -> two rounds
    call c, round_sha256

    ld a, 9
    ld (mpShaCtrl), a

    ld iy, (ix+12)  ; 24    ; 3
    ld hl, mpShaState  ; 16 ; 4
    ld b, 32/4      ; 8     ; 2
.copy_dest:
    ld a, (hl)      ; 8     ; 1
    ld (iy+3), a    ; 14    ; 3
    inc hl          ; 4     ; 1
    ld a, (hl)      ; ...
    ld (iy+2), a
    inc hl
    ld a, (hl)
    ld (iy+1), a
    inc hl
    ld a, (hl)
    ld (iy), a
    inc hl
    lea iy, iy+4    ; 12    ; 3
    djnz .copy_dest ; 13/8

    xor a, a
    ld (mpShaEnable), a

    call _flash_lock ; 299 cycles
    ld sp, ix
    pop ix
    ei
    ret


; cycles: 1727 + k*25  ->  1727*(1000/64) 25_905 cycles for ~1KB -> OK
; size: 56 B -> OK
; Input:
;   HL: data (64 bytes in "big-endian")
; Output:
;   HL: in(HL) + 64
round_sha256:
    ; 1627 / 34
    ld iy, 0    ; 20            ; 5
    add iy, sp  ; 8             ; 2
    ld sp, hl   ; 4             ; 1
    ld hl, mpShaBlock  ; 16     ; 4
    ld a, 64/4  ; 8             ; 2
.round.loop:            ; 1547
    pop bc      ; 16            ; 1
    dec sp      ; 4             ; 1
    pop de      ; 16            ; 1
    dec sp      ; 4             ; 1
    ld (hl), d  ; 6             ; 1
    inc hl      ; 4             ; 1
    ld (hl), e  ; 6             ; 1
    inc hl      ; 4             ; 1
    ld (hl), b  ; 6             ; 1
    inc hl      ; 4             ; 1
    ld (hl), c  ; 6             ; 1
    inc hl      ; 4             ; 1
    dec a       ; 4             ; 1
    jr nz, .round.loop ; 13/8   ; 2
    or a, a     ; 4             ; 1
    sbc hl, hl  ; 8             ; 1
    add hl, sp  ; 4             ; 1
    ld sp, iy   ; 8             ; 2

    ; 56 / 12
    ld a, (next_command)        ; 16    ; 3
    ld (mpShaCtrl), a           ; 18    ; 4
    ld a, SHA256_CTRL_CONTINUE  ; 8     ; 2
    ld (next_command), a        ; 14    ; 3

    ; 44 + k*25 / 10
    ex de, hl           ; 4     ; 1
    ld hl, mpShaBusy    ; 16    ; 4
.wait:
    bit 3, (hl)         ; 12    ; 2
    jr nz, .wait        ; 13/8  ; 2
    ex de, hl           ; 4     ; 1
    ret


; data
next_command:   db 0
total_size:     db 0,0,0


; external calls
extern _flash_unlock
extern _flash_lock
