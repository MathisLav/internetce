; For now:
; 1 block = 174K cycles
; 62 blocks (1KB of data) = 10M cycles =  0.2 sec
; That's OK, the most expansive operation is gcm_mult (~120K cyckes)


; ******* equates *******
; RomCalls
?_frameset             :=     000012Ch


    section .text

    public _compute_round_keys
_compute_round_keys:
    ; IX+6 -> key space (176 B, the 16 first bytes are the original key)
    ; Cost: 10011 Cycles (< 1ms) -> OK
    ; Size: 10*4 + 44 = 84 Bytes
    di
    pop hl
    pop iy
    push iy
    push hl
    ld b, 10
    ld c, 1
    ld de, cipher_LUT
    or a, a  ; reset carry flag
.round:
    ; sub_rot
    iterate <src,dst>, 0,3, 1,0, 2,1, 3,2
        ld a, (iy+12+src)   ; 16
        sbc hl, hl          ; 8     ; carry flag ?
        ld l, a             ; 4
        add hl, de          ; 4
        ld a, (hl)          ; 8
        if dst = 0
            xor a, c        ; 4
        end if
        ld l, (iy+dst)      ; 16
        xor a, l            ; 4
        ld (iy+16+dst), a   ; 14
    end iterate

    sla c                   ; 8
    jr c, .gf256_overflow   ; 8/13
.suit_oveflow:

    exx   ; save DE/BC      ; 4
    ld a, 12                ; 8
    lea bc, iy+4            ; 12
    lea hl, iy+16           ; 12
    lea de, iy+20           ; 12
.inner_round:
    ex af, af'              ; 4
    ld a, (bc)              ; 8
    xor a, (hl)             ; 8
    ld (de), a              ; 6
    ex af, af'              ; 4
    inc hl                  ; 4
    inc de                  ; 4
    inc bc                  ; 4
    dec a                   ; 4
    jr nz, .inner_round     ; 13/8
    exx
    
    lea iy, iy+16           ; 12
    djnz .round             ; 13/8
    ei
    ret
.gf256_overflow:
    ld c, 0x1b              ; 8
    or a, a  ; reset c flag for sbc
    jr .suit_oveflow        ; 12


    public _cipher_aes128gcm
_cipher_aes128gcm:
    ; IX+6(in): round keys
    ; IX+9(in): plaintext
    ; IX+12(in): length_plaintext
    ; IX+15(in): IV (12 bytes)
    ; IX+18(in): AAD (less than 16 bytes)
    ; IX+21(in): length_aad
    ; IX+24(out): tag
    ; IX+27(out): ciphertext
    ld hl, -16*4-1  ; -65=is_ciphering(1), -64=tmp_ciphered(16), -48=tmp_tag(16), -32=H_vector(16), -16=IV_counter(16)
    call _frameset
    ld (ix-65), 1  ; is_ciphering = 1
    jr aes128gcm


    public _decipher_aes128gcm
_decipher_aes128gcm:
    ; IX+6(in): round keys
    ; IX+9(in): ciphertext
    ; IX+12(in): length_ciphertext (without tag and AAD)
    ; IX+15(in): IV (12 bytes)
    ; IX+18(in): AAD (less than 16 bytes)
    ; IX+21(in): length_aad
    ; IX+24(in): tag
    ; IX+27(out): plaintext (valid only if the TAG check succeeded)
    ; return 0 on success, 1 on failed TAG check
    ld hl, -16*4-1  ; -65=is_ciphering(1), -64=tmp_ciphered(16), -48=tmp_tag(16), -32=H_vector(16), -16=IV_counter(16)
    call _frameset
    ld (ix-65), 0  ; is_ciphering = 0
    jr aes128gcm


aes128gcm:
    ; -65=is_ciphering(1), -64=tmp_ciphered(16), -48=tmp_tag(16), -32=H_vector(16), -16=IV_counter(16)
    ; IX+6(in): round keys
    ; IX+9(in): sourcetext
    ; IX+12(in): length_sourcetext
    ; IX+15(in): IV (12 bytes)
    ; IX+18(in): AAD (less than 16 bytes)
    ; IX+21(in); length_aad
    ; IX+24(in/out): tag (out on cipher, in on decipher)
    ; IX+27(out): desttext
    ; If on decipher mode, return 0 on success, 1 on failed TAG check
    di
    ; counter to 1
    xor a, a
    sbc hl, hl
    ld (ix-4), hl   ; IX-4 (32b): counter
    inc a
    ld (ix-1), a

    ; copying IV
    lea de, ix-16
    ld hl, (ix+15)
    ld bc, 12
    ldir  ; set C to 0

    ; Computing H as aes128(0, key)
    ld hl, ciphered_block  ; only using this area because it is not used, but this is unrelated to its primary function
    ld (hl), c  ; C is 0
    ld de, ciphered_block+1
    ld bc, 15
    ldir  ; All 0s
    ld de, (ix+6)  ; round keys
    lea iy, ix-32  ; H_vector
    ld hl, ciphered_block
    call aes128_single_block

    ; Start tag computing (AAD * H)
    ; Padding AAD to 16 bytes
    ld bc, (ix+21)  ; length_aad
    or a, a
    sbc hl, hl
    sbc hl, bc
    jr nz, .non_null_aad

    lea hl, ix-48  ; tag destination
    ld (hl), c  ; 0
    lea de, ix-48+1
    ld bc, 15
    ldir
    jr .suit_no_aad

.non_null_aad:
    ld de, ciphered_block  ; idem, used as temporary storage area
    ld hl, (ix+18)  ; AAD
    ldir
    ld a, 16
    sub a, (ix+21)
    jr z, .no_copy  ; ok to do that because AAD is not a secret
    ld c, a
    sbc hl, hl
    add hl, de
    ld (hl), 0
    inc de
    dec c
    jr z, .no_copy  ; idem
    ldir
.no_copy:
    ld hl, ciphered_block
    lea de, ix-32  ; H
    lea iy, ix-48  ; tag destination
    call gcm_mult
.suit_no_aad:

    ; Set DE to the number of AES blocks to process (=ceiling(length/16))
    or a, a
    sbc hl, hl
    ld bc, (ix+12)  ; length
    sbc hl, bc
    jp z, .no_source_data

    ld a, c
    repeat 4
        srl b
        rr c
    end repeat
    and a, 1111b
    jr nz, .gcm_loop
    dec bc

.gcm_loop:
    exx  ; to save BC

    ; incrementing counter in big endian style
    ; counter cannot be bigger than 2**16 as TLS records are at most 14KB
    ld d, (ix-2)
    ld e, (ix-1)
    inc de
    ld (ix-2), d
    ld (ix-1), e

    ld de, (ix+6)  ; round keys
    lea iy, ix-64  ; tmp_ciphered
    lea hl, ix-16  ; IV_counter
    call aes128_single_block

    exx  ; BC is remaining blocks
    ld hl, -1
    add hl, bc
    jr nc, .last_round
    push hl

    lea hl, ix-64  ; tmp_ciphered
    ld de, (ix+9)  ; sourcetext
    ld bc, (ix+27)  ; desttext
    call gcm_add

    ld de, (ix+9)  ; sourcetext
    bit 0, (ix-65)  ; is_ciphering
    jr z, .tag_processing
    ld de, (ix+27)  ; desttext
.tag_processing:
    lea hl, ix-48  ; current tag
    lea bc, ix-48
    call gcm_add

    lea hl, ix-48  ; tag
    lea de, ix-32  ; H
    lea iy, ix-48
    call gcm_mult

    ld bc, 16
    ld hl, (ix+9)
    add hl, bc
    ld (ix+9), hl
    ld hl, (ix+27)
    add hl, bc
    ld (ix+27), hl

    pop bc
    jr .gcm_loop

.last_round:
    lea hl, ix-64  ; tmp_ciphered
    ld de, (ix+9)  ; sourcetext
    ld bc, (ix+27)  ; desttext
    call .gcm_add_partial

    ld de, (ix+9)  ; sourcetext
    bit 0, (ix-65)  ; is_ciphering
    jr z, .tag_processing_last
    ld de, (ix+27)  ; desttext
.tag_processing_last:

    lea hl, ix-48  ; current tag
    lea bc, ix-48
    call .gcm_add_partial

    lea hl, ix-48  ; tag
    lea de, ix-32  ; H
    lea iy, ix-48
    call gcm_mult

.no_source_data:
    ; ghash on length(aad) || length_sourcetext
    ld iy, ciphered_block  ; only using this area because it is not used, but this is unrelated to its primary function
    lea hl, iy
    ld (hl), c  ; 0
    lea de, iy+1
    ld bc, 15
    ldir
    ld a, (ix+21)  ; length_aad in bits (max=8*16=128: only one byte)
    sla a
    rla
    rla
    ld (iy+7), a
    ld de, (ix+12)  ; length_sourcetext in bits (max=8*AES_MAX_BLOCK_SIZE=2^15: at most 2 bytes)
    repeat 3  ; *8
        sla e
        rl d
    end repeat
    ld (iy+15), e
    ld (iy+14), d

    lea hl, iy
    lea de, ix-48  ; current tag
    lea bc, ix-48
    call gcm_add

    lea hl, ix-48  ; tag
    lea de, ix-32  ; H
    lea iy, ix-48  ; current tag buffer
    call gcm_mult

    or a, a
    sbc hl, hl
    ld (ix-3), hl  ; no more than 2^12/16=256 blocks
    inc (ix-1)
    lea hl, ix-16  ; IV
    ld de, (ix+6)  ; round keys
    lea iy, ix-64  ; tmp_ciphered
    call aes128_single_block
    lea hl, ix-64
    lea de, ix-48  ; tmp_tag

    bit 0, (ix-65)  ; is_ciphering
    jr z, .check_tag
.handle_tag_cipher:
    ; Copying the tag on the right place
    ld bc, (ix+24)
    call gcm_add

.finish:
    ld sp, ix
    pop ix
    ei
    ret

.check_tag:
    ; Checking the tag with the one provided
    lea bc, ix-48  ; tmp_tag
    call gcm_add

    ld bc, (ix+24)
    lea hl, ix-48
    ld e, 0
    ld a, 16
.loop_tag_check:  ; constant time
    ex af, af'
    ld a, (bc)
    sub a, (hl)
    or a, e
    ld e, a
    inc hl
    inc bc
    ex af, af'
    dec a
    jr nz, .loop_tag_check
    or a, a
    sbc hl, hl
    sub a, e  ; carry flag is set if E is not 0
    adc a, e
    ld l, a
    ; From here, HL is 0 only if the tag check succeded, 1 otherwise
    jr .finish

.gcm_add_partial:
    ; call gcm_add to only add (length_sourcetext % 16) times
    ld a, (ix+12)  ; length_sourcetext
    and a, 1111b
    jr z, gcm_add
    exx
    sub a, 16
    neg
    add a, a  ; x6
    ld b, a
    add a, a
    add a, b
    ld (.jump_add_smc), a
    exx
    jr $
.jump_add_smc = $-1

; Warning, do not put any code in there

; cycles: 544
gcm_add:
    ; HL, DE: input
    ; BC: output
    ; Post-condition: BC, DE, HL are +16
    repeat 16  ; The way gcm_add is written is important. If any change, .gcm_loop.last_round must be changed too
        ld a, (de)
        xor a, (hl)
        ld (bc), a
        inc hl
        inc de
        inc bc
    end repeat
    ret


; cycles: 119_584 cycles
gcm_mult:
    ; p = a * b
    ; HL -> a
    ; DE -> b
    ; IY -> p
    push ix
    ld ix, gcm_mult_buffer
    push de
    lea de, ix
    ld bc, 16
    ldir
    pop de

    ; IY to 0
    or a, a
    sbc hl, hl
    ld (iy+0), hl
    ld (iy+3), hl
    ld (iy+6), hl
    ld (iy+9), hl
    ld (iy+12), hl
    ld (iy+15), l

    ld b, 16
.outer_loop:
    ld a, (de)
    exx
    ld c, a
    lea de, ix

    repeat 8
        rl c
        sbc a, a ; if carry = 1, ff, else 00
        ld b, a
        lea hl, iy
        xor16B_masked

        lea hl, ix
        rr16B

        lea hl, ix
        sbc a, a  ; carry set or reset by rr16B
        and a, 0xE1
        xor a, (hl)
        ld (hl), a
        ex de, hl
    end repeat

    exx
    inc de
    dec b
    jp nz, .outer_loop
    pop ix
    ret


; cycles: 300
macro rr16B?
    ; HL input
    ; carry flag set of reset according to the last bit of the input
    srl (hl)
    repeat 15
        inc hl
        rr (hl)
    end repeat
end macro


; cycles: 536
macro xor16B_masked
    ; DE/HL inputs
    ; B mask
    ; HL output
    iterate idx, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
        ld a, (de)
        and a, b
        xor a, (hl)
        ld (hl), a
        if idx <> 15
            inc hl
            inc de
        end if
    end iterate
end macro



aes128_single_block:
    ; Cost: 41508 Cycles -> 0.8 ms pour un bloc -> 80ms pour un payload de 1500o (OK)
    ; Size: 520(code) + 256(LUT) = 776 bytes for cipher.
    ; Inputs:
    ;   - HL -> source buffer
    ;   - IY -> dest_buffer
    ;   - DE -> round keys
    ; Outputs:
    ;   - IY
    push ix
    call add_round_key_move
    ld c, 10                ; 8
.aes_loop:
    push de
    sub_bytes_shift_row
    dec c                   ; 4
    jp z, .last_round       ; 17/16
    mix_columns
    pop de
    add_round_key
    jp .aes_loop            ; 17
.last_round:
    pop de
    ld hl, ciphered_block
    call add_round_key_move
    pop ix
    ret


; Input:
;   - IY: buffer
; Output:
;   - The content of ciphered_block is modified
macro sub_bytes_shift_row?
    ; Cost: 36 + 50*16 = 836 cycles
    ; Size: 9 + 10*16 = 169 bytes
    ld ix, ciphered_block   ; 20        ; 5     ; warning: IX must stay unchanged, it is used as input to mix_columns
    ld de, cipher_LUT   ; 16        ; 4

    iterate <in,out>,  0,0, 1,13, 2,10, 3,7,  4,4, 5,1, 6,14, 7,11,  8,8, 9,5, 10,2, 11,15,  12,12, 13,9, 14,6, 15,3
        ;      ==> 50
        sbc hl, hl      ; 8         ; 2     ; nc because of add_round_key's xor (and following or)
        ld l, (iy+in)   ; 16        ; 3
        add hl, de      ; 4         ; 1
        ld a, (hl)      ; 8         ; 1
        ld (ix+out), a  ; 14        ; 3
    end iterate
end macro

; Input:
;   - IX: source buffer
;   - IY: dest buffer
macro mix_columns?
    ; Cost: 2751 cycles
    ; Size: 161 bytes
    ; !! IX has been set to ciphered_block beforehand
    ld e, 0x1b                      ; 8
    ld b, 4                         ; 8

.loop_col:
    iterate <index,c0,c1,c2,c3>,  0,2,3,1,1,    1,1,2,3,1,    2,1,1,2,3,    3,3,1,1,2
        ld l, 0                     ; 8
        iterate <row_index,ci>,  0,c0,  1,c1,  2,c2,  3,c3
            if ci = 2 ; a << 1 & (a?7 & 0x1b)
                ld h, (ix+row_index)    ; 16
                sla h               ; 8
                sbc a, a            ; 4     ; 0 on nc, ff on carry
                and a, e            ; 4
                xor a, h            ; 4
            else if ci = 3 ; a << 1 & (a?7 & 0x1b) xor a
                ld h, (ix+row_index)    ; 16
                ld d, h             ; 4
                sla h               ; 8
                sbc a, a            ; 4     ; 0 on nc, ff on carry
                and a, e            ; 4
                xor a, h            ; 4
                xor a, d            ; 4
            else
                ld a, (ix+row_index)    ; 16
            end if
            xor a, l                ; 4
            ld l, a                 ; 4
        end iterate
        ld (iy+index), l          ; 14
    end iterate
    lea iy, iy+4
    lea ix, ix+4
    dec b                           ; 4
    jp nz, .loop_col                ; 17/16
    lea iy, iy-16
end macro


; Input:
;   - IY: current buffer
;   - DE: current round key
; Output:
;   - DE = Next round key address
macro add_round_key?
    ; The 11 round keys shall be computed before starting the AES calculation
    ; Cost: 30*16 + 12 = 492
    ; Size: 4 + 5*16 = 82
    lea hl, iy          ; 12
    repeat 16
        ; ==> 30
        ld a, (de)          ; 8
        xor a, (hl)         ; 8
        ld (hl), a          ; 6
        inc hl              ; 4
        inc de              ; 4
    end repeat
end macro


; Input:
;   - HL: source buffer
;   - IY: dest buffer
;   - DE: current round key
; Output:
;   - DE = Next round key address
add_round_key_move:
    ; The 11 round keys shall be computed before starting the AES calculation
    ; Cost: 34*16 + 12 = 556
    ; Size: 4 + 6*16 = 100
    lea bc, iy              ; 12
    repeat 16
        ; ==> 34
        ld a, (de)          ; 8
        xor a, (hl)         ; 8
        ld (bc), a          ; 6
        inc hl              ; 4
        inc de              ; 4
        inc bc              ; 4
    end repeat
    ret



cipher_LUT:
    db 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76
    db 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0
    db 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15
    db 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75
    db 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84
    db 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf
    db 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8
    db 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2
    db 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73
    db 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb
    db 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79
    db 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08
    db 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a
    db 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e
    db 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf
    db 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16

ciphered_block:
    db 16 dup (0)

gcm_mult_buffer:
    db 16 dup (0)
