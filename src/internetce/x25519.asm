; Numbers are stored little endian (LSB first)
; Planned duration taken by x25519_scalarmult: 4s

include "mult256.asm"

?_frameset0            :=     0000130h


; --------------------- START SECTION .TEXT ---------------------

    section .text

    public _x25519_scalarmult
_x25519_scalarmult:
    ; Warning: scalar modified in place
    ; IX+6 -> scalar k
    ; IX+9 -> result point
    di
    call _frameset0  ; reset carry flag
    push ix

    ; clamping scalar
    ld iy, (ix+6)
    ld a, 0xf8
    and a, (iy+0)
    ld (iy+0), a
    ld a, 0x7f
    and a, (iy+31)
    or a, 0x40
    ld (iy+31), a

    ; a=u, b=v, c=x, d=y
    ld hl, point_u
    ld (pointer_a), hl
    ld hl, point_v
    ld (pointer_b), hl
    ld hl, point_x
    ld (pointer_c), hl
    ld hl, point_y
    ld (pointer_d), hl

    ; 0-ing a, b, c, d
    sbc hl, hl
    ex de, hl
    sbc hl, hl
    add hl, sp
    ld sp, point_y + 33
    ld b, 11
.zero_space:
repeat 4        ; 3*4*11 == 4*33 == 132
    push de
end repeat
    djnz .zero_space
    ld sp, hl

    ; a[0] = d[0] = 1
    ld a, 1
    ld (point_u), a
    ld (point_y), a
    ; b[0] = 9
    ld a, 9
    ld (point_v), a

    ld a, 255
    lea hl, iy+31  ; from MSB to LSB
    rl (hl)  ; skipping bit 256 (always reset)
.scalar_mult_loop:
    ex af, af'

    ; Swapping (or not) A/B, C/D
    xor a, a
    ld b, (hl)
    rl b
    push hl
    swap25519
    
    ld iy, point_e
    ld ix, (pointer_a)
    ld de, (pointer_c)
    call x25519_add  ; fadd(e, a, c)
    
    ld iy, (pointer_a)
    ; (pointer_a) is already in IX
    ld de, (pointer_c)
    call x25519_sub  ; fsub(a, a, c)
    
    ld iy, (pointer_c)
    ld ix, (pointer_b)
    ld de, (pointer_d)
    call x25519_add  ; fadd(c, b, d)

    ld iy, (pointer_b)
    ; (pointer_b) is already in IX
    ld de, (pointer_d)
    call x25519_sub  ; fsub(b, b, d)

    ld de, (pointer_d)
    ld ix, point_e
    lea iy, ix
    call x25519_mult  ; fmul(d, e, e)
    
    ld de, point_f
    ld ix, (pointer_a)
    lea iy, ix
    call x25519_mult  ; fmul(f, a, a)

    ld iy, (pointer_a)
    lea de, iy
    ld ix, (pointer_c)
    call x25519_mult  ; fmul(a, c, a)

    ld de, (pointer_c)
    ld ix, (pointer_b)
    ld iy, point_e
    call x25519_mult  ; fmul(c, b, e)

    ; point_e is already set in IY
    ld ix, (pointer_a)
    ld de, (pointer_c)
    call x25519_add  ; fadd(e, a, c)

    ; (pointer_a) is already set in IX
    lea iy, ix
    ld de, (pointer_c)
    call x25519_sub  ; fadd(a, a, c)

    ld de, (pointer_b)
    ; (pointer_a) is already set in IX
    ; (pointer_a) is already set in IY
    call x25519_mult  ; fmul(b, a, a)

    ld iy, (pointer_c)
    ld ix, (pointer_d)
    ld de, point_f
    call x25519_sub  ; fsub(c, d, f)

    ld de, (pointer_a)
    ld ix, (pointer_c)
    call x25519_mult121665  ; fmul_121665(a, c)

    ld iy, (pointer_a)
    lea ix, iy
    ld de, (pointer_d)
    call x25519_add  ; fadd(a, a, d)

    ld ix, (pointer_c)
    lea de, ix
    ; (pointer_a) is already set in IY
    call x25519_mult  ; fmul(c, c, a)

    ld de, (pointer_a)
    ld ix, (pointer_d)
    ld iy, point_f
    call x25519_mult  ; fmul(a, d, f)

    ld de, (pointer_d)
    ld ix, (pointer_b)
    ld iy, data_x9_point  ; TODO making fast mult by 9 ?
    call x25519_mult  ; fmul(d, b, x)

    ld de, (pointer_c)
    ld ix, point_e
    lea iy, ix
    call x25519_mult  ; fmul(b, e, e)

    ; Swapping back (or not) A/B, C/D
    xor a, a
    pop ix
    rl (ix+0)
    swap25519

    lea hl, ix
    ex af, af'
    ; a = 1 [8] ?
    ; if a matches .....000 this means HL must be decremented
    tst a, 7
    jr z, .take_next
    dec a
    jp nz, .scalar_mult_loop  ; if A == 0 it will go in take_next

.end_loop:
    x25519_mult_inverse point_x  ; finverse(c)  => (pointer_c) equals to point_x

    ld iy, point_u  ; equals to (pointer_a)
    lea de, iy
    ; (pointer_c) is already set in IX
    call x25519_mult  ; fmul(a, c, a)

    pop ix
    ld de, (ix+9)
    ld hl, point_u
    ld bc, 32
    ldir

    pop ix
    ei
    ret
.take_next:
    dec hl
    dec a
    jp .scalar_mult_loop


; 315 cycles according to CEmu
; 248 cycles in theory
macro swap25519?
    ; If carry flag is set: exchange A/B, C/D
    ; Otherwise, "do nothing"
    ; Precondition: A == 0 !!!
    rla
    ld e, a
    add a, e
    add a, e  ; A = [bit0]*3
    ; For A/B
    sbc hl, hl
    ex de, hl
    ld e, a
    ld hl, pointer_a
    ld bc, (hl)
    add hl, de
    ld de, (hl)
    ld (hl), bc
    ld (pointer_a), de
    ; For C/D
    sbc hl, hl
    ex de, hl
    ld e, a
    ld hl, pointer_c
    ld bc, (hl)
    add hl, de
    ld de, (hl)
    ld (hl), bc
    ld (pointer_c), de
end macro


; 01DB41
; Size: 229 bytes
x25519_mult121665:
    ; IX: src
    ; DE: dst
    or a, a
    sbc hl, hl
    add hl, sp  ; reset carry flag
    exx

    sbc hl, hl
    ld sp, tmp_buffer_end
repeat 12  ; only needing 255(op1)+17(op2)+5(19)=277 bits => 35 bytes
    push hl
end repeat

    ld sp, tmp_buffer

    ld d, (ix+0)
	ld e, 0x41
	mlt de
	pop hl
	add hl, de
	push hl
	inc sp

	ld bc, (ix+0)
	ld e, c
	ld d, 0xdb
	mlt de
	ex de, hl
	ld c, 0x41
	mlt bc
	add hl, bc
	pop de
	add hl, de
	push hl
	inc sp

    lea de, ix
    or a, a
    exx
    ld b, 30
.mult121665_loop:
    exx
    sbc hl, hl
    ld a, (de)
	ld l, a
    inc de
    ld a, (de)
    ld c, a
	ld b, 0xdb
	mlt bc
	add hl, bc
    inc de
    ld a, (de)
	ld c, a
	ld b, 0x41
	mlt bc
	add hl, de
	pop de
	add hl, de
	push hl
	inc sp
    inc de
    exx
    djnz .mult121665_loop
    exx

    sbc hl, hl
    ld c, (ix+30)
    ld l, c
	ld e, (ix+31)
	ld d, 0xdb
	mlt de
	add hl, de
	pop de
	add hl, de
	push hl
	inc sp

    sbc hl, hl
	ld c, (ix+31)
    ld l, c
	pop de
	add hl, de  ;IY+33
	push hl

    exx
    ld sp, hl  ; restore SP
    exx

    ; modulo on only 17 bits x19 -> 17+5=22 bits of carry <24
    ld ix, tmp_buffer
    lea hl, ix+31
    ld a, (hl)
    rla  ; bit 7 of (hl) in carry flag
    res 7, (hl)
    inc hl
    ld d, (hl)
    rl d
    ld a, 19
    ld e, a  ; 19
    mlt de
    inc hl
    ld b, (hl)
    rl b
    ld c, a  ; 19
    mlt bc
    ; BC*256
    push bc
    dec sp
    pop bc
    inc sp
    ld c, 0
    ; -----
    ex de, hl
    ex af, af'  ; saving carry
    add hl, bc
    ex af, af'
    ex de, hl
    inc hl
    ld c, (hl)
    rl c
    ld b, a  ; 19
    mlt bc  ; only C should be non-0
    ; BC*65536
    ld (ix+50), c  ; ix+50 == saferam
    ld hl, (ix+48)
    ld l, 0
    ld h, l
    ; -----
    add hl, de

    ld a, 2
.repeat_carry:
    ld de, (ix+0)
    add hl, de
    ld (ix+0), hl
    ld b, 10
    ld de, 0  ; carry must be preserved so not using sbc
.carry_loop:
    ld hl, (ix)
    adc hl, de  ; DE == 0
    ld (ix), hl
    lea ix, ix+3
    djnz .carry_loop

    ; bit 256 may remain set
    dec a
    jr z, .no_more_carry

    sbc hl, hl
    ld b, (ix+31)
    rl b
    res 7, (ix+31)
    rl l
    ld h, 19
    mlt hl
    jr .repeat_carry
.no_more_carry:

    ld ix, tmp_buffer
    jq modulo_last_step


macro x25519_mult_inverse point
    ld ix, point
    lea hl, ix
    ld de, tmp_buffer
    ld bc, 32
    ldir  ; tmp_buffer contains a copy of point

    lea iy, ix
    ld a, 254
.inverse_loop:
    ex af, af'
    lea ix, iy
    lea de, iy
    call x25519_mult
    cp a, 5
    jr z, .bit_0
    cp a, 3
    jr z, .bit_0
    lea de, iy
    ld ix, tmp_buffer
    call x25519_mult
.bit_0:
    ex af, af'
    dec a
    jr nz, .inverse_loop
end macro


; x25519_square:
;     ; TODO making fast square
;     ret

; 749 cycles with call/ret without modulo and mult
; 55_069 cycles in total
; 3053 multiplications -> 3.5sec with mult and inverses
; 8823 bytes with tmp_buffer and ret
x25519_mult:
    ; IX -> OP1
    ; IY -> OP2
    ; DE -> RES
    ; destroys IX, save IY
    or a, a
    sbc hl, hl
    add hl, sp  ; reset carry flag
    exx

    ; Set RES to 0 (244 cycles / 28 Bytes)
    sbc hl, hl
    ld sp, tmp_buffer_end
repeat 22
    push hl
end repeat

    ; Do the mult
    ; SP, IX, IY are set beforehand
    mult256

    ld ix, tmp_buffer
    exx
    ld sp, hl
    exx
    x25519_modulo
    exx
    
    ; 402 cycles
    ; 51 bytes
    ; IX == the result
    ; DE == the destination
    ; HL == SP
    ex de, hl
    ld bc, 33
    add hl, bc
    ld sp, hl
iterate idx, 30, 27, 24, 21, 18, 15, 12, 9, 6, 3, 0
    ld bc, (ix+idx)
    push bc
end iterate

    ex de, hl
    ld sp, hl
    ret


; 5014 cycles
; 185 bytes
macro x25519_modulo?
    ; IX+0/65
    ; First phase: IX+32/63 - 1bit is multiplied by 19 and shifted 1 byte to the right to make room for IX+0/31->32
    xor a, a
    ex af, af'
    or a, a
    ld b, 32
    ld c, 19
    lea hl, ix+31
    ld e, (hl)
    rl e
    res 7, (hl)
    inc hl
    ld e, (hl)
    ld (hl), 0 ; shifting op2 -> making room for 33 bits
.loop_modulo:
    rl e
    ex af, af'
    ld d, c
    mlt de
    adc a, e
    inc hl
    ld e, (hl)
    ld (hl), a
    ld a, d
    ex af, af'
    djnz .loop_modulo
    ex af, af'

    lea de, ix+33
    lea iy, ix
    call x25519_add

    ; The modulo can still be > 255 bits (max 263 bits)
    lea hl, ix+31
    ld a, (hl)
    rla
    res 7, (hl)
    inc hl
    ld d, (hl)
    ld (hl), 0
    rl d
    ld e, 19
    mlt de

    sbc hl, hl  ; carry flag should be reset by rl
    ex de, hl
    ld bc, (ix+0)
    add hl, bc
    ld (ix+0), hl
iterate idx, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30
    ld hl, (ix+idx)
    adc hl, de  ; DE == 0
    ld (ix+idx), hl
end iterate

    ; Number can still be between 2**255-19 and 2**255
    ; Substract the number by 2**255-19:
    ;   - if the carry flag is reset, then keeping the result
    ;   - otherwise the number is unchanged
    ; After this, IX might have changed
modulo_last_step:
    lea hl, ix
    lea de, ix+33
    ld a, 0xde
    sub a, (hl)
    ld (de), a
    inc hl
    inc de
    ld c, 0xff
    ld b, 2
.inv_loop:  ; adding 8+13+8 -> 29 cycles but winning 60B
repeat 15
    ld a, c
    sbc a, (hl)
    ld (de), a
    inc hl
    inc de
end repeat
    djnz .inv_loop
    ld a, 0x7f
    sbc a, (hl)
    ld (de), a

    ; if carry -> number was > than 2**255-19
    rl b  ; Before: B == 0
    ld c, 33
    mlt bc
    add ix, bc
end macro


x25519_sub:
    ; IX first operand
    ; DE second operand
    ; IY destination
    ; Precondition: no add or sub before, because (DE) must be lower than 2**255-19
    or a, a
    sbc hl, hl
    add hl, de
    x25519_inv
    ; the ADD is following


; cycles: 758 (without modulo and call/ret)
; size: 107 bytes (no ret)
x25519_add:
    ; ix -> one BIG number (32 B with 1 byte to 0 at the end)
    ; de -> one BIG number (32 B with 1 byte to 0 at the end)
    ; iy -> BIG number destination (32 B with 1 byte to 0 at the end)
    or a, a         ; 4
    sbc hl, hl      ; 8
    add hl, sp      ; 4
    ex de, hl       ; 4

    ld sp, hl       ; 4
iterate idx, 0, 3, 6, 9, 12, 15, 18, 21, 24, 27, 30
    ld hl, (ix+idx) ; 24
    pop bc          ; 16
    adc hl, bc      ; 8
    ld (iy+idx), hl ; 18
end iterate

    ex de, hl       ; 4
    ld sp, hl       ; 4
    ret


; cycles: 745
; Size: 75 bytes
macro x25519_inv?
    ; HL -> number
    ld a, 0xde
    sub a, (hl)
    ld (hl), a
    inc hl
    ld c, 0xff
    ld b, 2
.inv_loop:  ; adding 8+13+8 -> 29 cycles but winning 60B
repeat 15
    ld a, c
    sbc a, (hl)
    ld (hl), a
    inc hl
end repeat
    djnz .inv_loop
    ld a, 0x7f
    sbc a, (hl)
    ld (hl), a
end macro


    extern _mult256

; ---------------------- END SECTION .TEXT ----------------------


; --------------------- START SECTION .DATA ---------------------

    section .data
; These are pointers to point_uvxy
pointer_a:
    db 0,0,0
pointer_b:
    db 0,0,0
pointer_c:
    db 0,0,0
pointer_d:
    db 0,0,0

; These are the actual points (only x coordinate)
point_u:
    db 33 dup (0)
point_v:
    db 33 dup (0)
point_x:
    db 33 dup (0)
point_y:
    db 33 dup (0)
point_e:
    db 33 dup (0)
point_f:
    db 33 dup (0)
tmp_buffer:
    db 66 dup (0)  ; 33*2
tmp_buffer_end:

    private tmp_buffer
    private tmp_buffer_end
    private point_u
    private point_v
    private point_x
    private point_y
    private point_e
    private point_f
    private pointer_a
    private pointer_b
    private pointer_c
    private pointer_d

; ---------------------- END SECTION .DATA ----------------------


; -------------------- START SECTION .RODATA --------------------

    section .rodata
data_x9_point:
    db 9
    db 32 dup (0)

    private data_x9_point

; --------------------- END SECTION .RODATA ---------------------
