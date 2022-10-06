; *******************************************
; * Author: Epharius						*
; *	Miscellaneous assembly stuffs 			*
; * You can reuse this code as you wish		*
; *******************************************

	assume	adl=1


; ******* equates *******
AppVarObj		equ		15h
OP1				equ		0D005F8h
_ChkFindSym		equ		002050Ch
_ChkInRam		equ		0021F98h
_Arc_Unarc		equ		0021448h
_OP1ToOP6		equ		00202E8h
_OP6ToOP1		equ		00202C4h
_EnoughMem		equ		002051Ch
_DelVarArc		equ		0021434h
_DelMem			equ		0020590h
_InsertMem		equ		0020514h


	section .text
	public _MoveToArc
_MoveToArc:
	call __frameset0
	ld hl,(ix+6)
	ld de,OP1+1
	ld bc,9
	ldir
	ld a,AppVarObj
	ld (OP1),a
	call _OP1ToOP6
	call _ChkFindSym
	ld hl,0
	pop ix
	ret c
	call _ChkInRam
	ret nz
	call _Arc_Unarc
	call _OP6ToOP1
	call _ChkFindSym
	ex de,hl
	ret


	section .text
	public _MoveToRam
_MoveToRam:
	call __frameset0
	ld hl,(ix+6)
	ld de,OP1+1
	ld bc,9
	ldir
	ld a,AppVarObj
	ld (OP1),a
	call _OP1ToOP6
	call _ChkFindSym
	ld hl,0
	pop ix
	ret c
	call _ChkInRam
	ret z
	call _Arc_Unarc
	call _OP6ToOP1
	call _ChkFindSym
	ex de,hl
	ret


	section .text
	public _os_EnoughMem
_os_EnoughMem:
	pop de
	pop hl
	push hl
	push de
	call _EnoughMem
	ld hl,0
	ret c
	inc hl
	ret


	section .text
	public _os_DelVarArc
_os_DelVarArc:
	call __frameset0
	ld a,(ix+6)
	ld hl,(ix+9)
	ld (OP1),a
	ld de,OP1+1
	ld bc,9
	ldir
	call _ChkFindSym
	pop ix
	jr c,.err_not_found
	call _DelVarArc
	ld hl,1
	ret
.err_not_found:
	or a
	sbc hl,hl
	ret

	section .text
	public _ResizeAppVar
_ResizeAppVar:
	; @warning	The AppVar must reside in RAM
	; @return	1 if the resizing happened, 0 if not
	; @note		This code can easily be used for other types of variable by replacing ld a,AppVarObj by ld a,whatyouwant
	call __frameset0
	ld a,AppVarObj
	ld (OP1),a
	ld hl,(ix+6)
	ld de,OP1+1
	ld bc,9
	ldir
	call _ChkFindSym
	ld hl,0
	jq c,.quit ; return 0
	call _ChkInRam
	jq nz,.quit ; return 0
	ex de,hl
	ld e,(hl)
	inc hl
	ld d,(hl)
	ld c,(ix+9) ; BCU is already 0
	ld b,(ix+10)
	ld (hl),b
	dec hl
	ld (hl),c
	push de
	ex de,hl
	or a
	sbc hl,bc
	pop ix
	jr z,.quit ; return 0
	push ix
	jq nc,.shrinkSize

	push de
	ex de,hl
	or a
	sbc hl,hl
	sbc hl,de
	ex de,hl
	pop hl
	pop bc
	add hl,bc
	ex de,hl
	call _InsertMem
	ld hl,1
	pop ix
	ret ; return 1

.shrinkSize:
	ex de,hl
	add hl,bc
	inc hl
	inc hl
	call _DelMem
	pop de ; reset stack
	ld hl,1

.quit:
	pop ix
	ret


	extern __frameset0
