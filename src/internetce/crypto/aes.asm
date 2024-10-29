; Target: 7680 cycles per iteration for a 16-byte block

; TODO:
;   - normalement j'ai testé les deux premières itérations _compute_round_keys c'est ok (pour ce que je comprends de l'algo)
;   - Donc mtn il faut tester le _cipher_aes128
;   - puis faire le decipher


; ******* equates *******
; RomCalls
?_frameset0            :=     0000130h


    section .text

    public _compute_round_keys
_compute_round_keys:
    ; IX+6 -> key space (172 B, the 16 first bytes are the original key)
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
    jr .suit_oveflow        ; 12

    public _cipher_aes128
_cipher_aes128:
    ; LIMITATION: size < 4096
    ; Inputs:
    ;   IX+3 -> src
    ;   IX+6 -> size
    ;   IX+9 -> dst (should be at least size + tag length)
    ;   IX+12 -> round keys buffer
    di
    call _frameset0         ; 100

    ld hl, (ix+3)
    ld bc, (ix+6)
    ld de, (ix+9)
    ldir            ; not cool -> 8+BC*7 -> 7008 for a 1KB block
    
    ld bc, (ix+6)
    ld a, c
    ; warning: the 4 lower bits should be 0
    repeat 4  ; 2**4 = /16
        srl b
        rra
    end repeat  ; at this time, B should be equal to 0 (<4096)
    
    ld de, (ix+12)
    ld iy, (ix+9)
.aes_block_loop:
    ex af, af'
    push de
    aes128_single_block     ; destroys IX
    pop de
    ex af, af'
    dec a
    jp nz, .aes_block_loop

    pop ix                  ; 20
    ei
    ret


macro aes128_single_block?
    ; Cost: 41508 Cycles -> 0.8 ms pour un bloc -> 80ms pour un payload de 1500o (OK)
    ; Size: 520(code) + 256(LUT) = 776 bytes for cipher.
    ; Inputs:
    ;   - IY -> source/dest buffer
    ;   - DE -> round keys
    ; Outputs:
    ;   - content of IY modified
    ld c, 10                ; 8
.aes_loop:
    add_round_key
    sub_bytes_shift_row
    dec c                   ; 4
    jp z, .last_round       ; 17/16
    mix_columns
    jp .aes_loop            ; 17
.last_round:
    add_round_key_last
end macro
    

; Input:
;   - IY: buffer
; Output:
;   - The content of tmp_buffer is modified
macro sub_bytes_shift_row?
    ; Cost: 44 + 50*16 = 844 cycles
    ; Size: 11 + 9*16 = 155 bytes
    exx                 ; 4         ; 1     ; Saving DE
    ld ix, tmp_buffer   ; 20        ; 5
    ld de, cipher_LUT   ; 16        ; 4

    iterate <in,out>,  0,0, 1,13, 2,10, 3,7,  4,4, 5,1, 6,14, 7,11,  8,8, 9,5, 10,2, 11,15,  12,12, 13,1, 14,6, 15,3
        ;      ==> 50
        sbc hl, hl      ; 8         ; 1     ; nc because of add_round_key's xor (and following add)
        ld l, (iy+in)   ; 16        ; 3
        add hl, de      ; 4         ; 1
        ld a, (hl)      ; 8         ; 1
        ld (ix+out), a  ; 14        ; 3
    end iterate

    exx                 ; 4         ; 1
end macro


macro mix_columns?
    ; Cost: 3031 cycles
    ; Size: 171 bytes
    exx                             ; 4
    ld d, 0xff                      ; 8
    ld e, 0x1b                      ; 8
    exx                             ; 4
    or a, a                         ; 4
    sbc hl, hl                      ; 8
    add hl, sp                      ; 4     ; resets c flag
    ld b, 4                         ; 8
    ld sp, tmp_buffer               ; 16

.loop_col:
    exx                             ; 4
    iterate <index,c0,c1,c2,c3>,  0,2,3,1,1,    1,1,2,3,1,    2,1,1,2,3,    3,3,1,1,2
        sbc hl, hl                  ; 8     ; c reset
        ld c, l                     ; 4
        add hl, sp                  ; 4
        iterate ci,  c0,c1,c2,c3
            if ci = 2 ; a << 1 & (a?7 & 0x1b)
                ld b, (hl)          ; 8
                sla b               ; 8
                ld a, d             ; 4
                sbc a, a            ; 4     ; 0 on nc, ff on carry
                and a, e            ; 4
                xor a, b            ; 4
            else if ci = 3 ; a << 1 & (a?7 & 0x1b) xor a
                ld b, (hl)          ; 8
                ld ixl, b           ; 8
                sla b               ; 8
                ld a, d             ; 4
                sbc a, a            ; 4     ; 0 on nc, ff on carry
                and a, e            ; 4
                xor a, b            ; 4
                xor a, ixl          ; 8
            else
                ld a, (hl)          ; 8
            end if
            xor a, c                ; 4     ; resets c flag
            ld c, a                 ; 4
            inc hl                  ; 4
        end iterate
        ld (iy+index), c            ; 14
    end iterate
    inc sp                          ; 4
    inc sp                          ; 4
    inc sp                          ; 4
    inc sp                          ; 4
    exx                             ; 4
    dec b                           ; 4
    jp nz, .loop_col                ; 17/16

    ld sp, hl                       ; 4
end macro


; Input:
;   - HL: current buffer
;   - DE: current round key
; Output:
;   - Changed HL content
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
;   - IY: target buffer
;   - DE: current round key
; Output:
;   - Changed target buffer
macro add_round_key_last?
    ; This function exists because the result must be in the argument buffer, which is not because of the parity of rounds
    ; Cost: 34*16 + 28 = 572
    ; Size: 6 + 6*16 = 102
    ld hl, tmp_buffer   ; 16
    lea bc, iy          ; 12

    repeat 16
        ; ==> 34
        ld a, (de)          ; 8
        xor a, (hl)         ; 8
        ld (bc), a          ; 6
        inc hl              ; 4
        inc de              ; 4
        inc bc              ; 4
    end repeat
end macro


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

tmp_buffer:
    db 16 dup (0)
