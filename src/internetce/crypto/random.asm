; Random Number Generator
; Using memory bus noise to output "pretty-good" random numbers (best we can do)


; void fill_urandom(void *dst, unsigned int size);
	section .text
    public _fill_urandom
_fill_urandom:
    ; Warning: max 1Mio generated at once
    ; Adding a little more entropy
    or a, a
    sbc hl, hl
    ld a, R
    ld l, a
    ld de, 0xC00000
    add hl, de

    pop iy
    pop bc
    pop de
    push de
    push bc
    push iy
    ldir
    ret


; uint32_t urandom();
    public _urandom
_urandom:
    ; Adding a little more entropy
    or a, a
    sbc hl, hl
    ld a, R
    ld l, a
    ld de, 0xD65800
    add hl, de

    ld e, (hl)
    inc hl
    ld hl, (hl)
    ret

    public _test
_test:
    ld b, 8
    ld hl, 0xf20020
    ld c, 0
.loop:
    ld a, (hl)  ; 8
    and a, 1    ; 8
    or a, c     ; 4
    sla a       ; 8
    ld c, a     ; 4
    djnz .loop  ; 13
    ret
