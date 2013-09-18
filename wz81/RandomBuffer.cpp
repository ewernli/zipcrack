//#include "stdafx.h"
#include <stdlib.h>
#include "RandomBuffer.hpp"
#include <memory.h>

/*	Buffer TEMP
	Temporary buffer used while initializing P1  
*/

int p[0xc7]; // 4*0xC7 = 31C

/*	Buffer P2 
	size: 3F1h
	random data are withdrawn from this buffer
*/

int buff[0x64+0x38d];

/*	Buffer P1
	size: 64h
	Data within this buffer are generated from a 28-bit seed
*/

int p3[0x64];

/*  ptr
	pointer inside P2
*/

int* ptr;

void save_buffers( int* p1, int* p2, int* p_3)
{
	memcpy( p1, p, 4*P1SIZE);
	memcpy( p2, buff, 4*P2SIZE);
	memcpy( p_3, p3, 4*P3SIZE);
}

void restore_buffers( int* p1, int* p2, int* p_3)
{
	memcpy( p, p1, 4*P1SIZE);
	memcpy( buff, p2, 4*P2SIZE);
	memcpy( p3, p_3, 4*P3SIZE);
}

void initialize_P1(int seed)
{
	_asm {
		mov		eax, seed	; eax = seed
		lea		eax, [eax+2]
		and		eax, 3FFFFFFEh
		mov		esi, 64h	; esi = 0x64
		lea		ecx, p

	$loop:
		mov		[ecx], eax	; *ptr = seed
		shl		eax,1		; seed = seed >> 1
		add		ecx, 4		; ptr+=4
		cmp		eax, 40000000h
		jl		$jump
		sub		eax, 3FFFFFFEh
	$jump:
		dec		esi
		jnz		$loop	
	}

	_asm{
		mov		ecx, 63h	; ecx = 0x63
		xor		eax, eax	; eax = 0
		lea		edi, [p + 31Ch - 18Ch]	; ! byte
		repe stosd
							; repeat ecx times
							; [edi] <- eax, edi++
	}
	_asm{
		; [p+1] ++
		mov		ecx, [p + 31Ch - 318h]	
		inc		ecx
		mov		[p + 31Ch - 318h],ecx	

		mov		esi, 45h	; do 0x45 times the big loop
		mov		ebx, seed
		and		ebx, 3FFFFFFFh
	}


	/* big loop */

	_asm{

	$BIGLOOP:

		lea		ecx, [p + 31Ch - 4h]
		lea		eax, [p + 31Ch - 190h]
		mov		edx, 63h
		
		;swapping
	$L1:
		mov		edi, [eax]
		sub		eax, 4
		mov		[ecx], edi
		sub		ecx, 8
		dec		edx
		jnz		$L1
	}

	_asm{
		lea		eax, [p + 31Ch - 4h]
		lea		ecx, [p + 31Ch - 318h]
		mov		edx, 44h

		;swapping with mask
	$L2:
		mov		edi, [eax]
		and		edi, 3FFFFFFEh
		mov		[ecx], edi
		sub		eax, 8
		add		ecx, 8
		dec		edx
		jnz		$L2
	}

	_asm{
		lea		eax, [p + 31Ch - 194h]
		mov		edx, 63h
		
	$L3:
		mov		ecx, [eax + 190h] ; p + 31c - 4 -i
		test	cl, 1
		jz		$J3
		mov		edi, [eax + 94h] ; p + 31c -100 -i
		sub		edi, ecx
		and		edi, 3FFFFFFFh
		mov		[eax+94h], edi
		mov		ecx, [eax]
		sub		ecx, [eax + 190h]
		and		ecx, 3FFFFFFFh
		mov		[eax], ecx
	$J3:
		sub		eax, 4
		dec		edx
		jnz		$L3
	}

	_asm{
		test	bl,	1
		jz		$JUMP4

		;-- swapping
			lea		eax, [p + 31Ch - 18Ch]
			mov		ecx, 64h
		$L4:	
			mov		edx, [eax-4]
			mov		[eax],edx
			add		eax, 0FFFFFFFCh  ; eax = eax - 4
			dec		ecx
			jnz		$L4
		;-- end swap

		mov		eax, [p + 31Ch - 18Ch]
		test	al, 1
		mov		[p], eax
		jz		$JUMP4

		mov		ecx, [p + 31Ch - 288h]
		sub		ecx, eax
		and		ecx, 3FFFFFFFh
		mov		[p + 31Ch - 288h], ecx

	$JUMP4:

		; ebx = seed & esi =0 0x45
		; while (ebx!=0) shift ebx and loop
		; once ebx = 0, start decrementing esi
		;
		; loop until ebx = 0
		; loop 0x45 times

		test	ebx, ebx
		jz		$BIG_DEC
		sar		ebx, 1
		jmp		$BIG_SAR
	$BIG_DEC:
		dec		esi
	$BIG_SAR:
		test	esi, esi
		jnz		$BIGLOOP

	}

	/* copy first 0x64 bytes from P1 to P3 */

	_asm{
		mov		ecx, 25h
		lea		esi, [p]
		lea		edi, [p3+3Fh*4]
		repe movsd
		mov		ecx, 3fh
		lea		esi, [p + 31ch - 288h]
		lea		edi, [p3]
		repe movsd
	}

}

void initialize_P2()
{
	/* copy first 0x64 bytes from P3 to P2 */
	_asm{
		mov		ecx, 64h
		lea		esi, [p3]
		lea		edi, [buff]
		repe movsd
	}

	/*	extends buffer P2 from 0x64 to 0x3F1 and randomize */

	_asm{
		mov		ecx, 38Dh
		lea		eax, [buff]
		mov		edi, 3F1h	
	$L_FILL:
		mov		edx, [eax]
		mov		ebx, [eax + 0FCh]
		sub		edx,ebx
		and		edx, 3FFFFFFFh
		mov		[eax + 94h + 0FCh], edx  ; 190h = 64h * 4
		add		eax, 4
		dec		ecx
		jnz		$L_FILL
	}


	/*	overwrie buffer P3 first 0x64 bytes with 
		randomized values from P2						*/

	_asm{
		lea		ecx, [buff + edi*4 -94h] ; [buff + 3f1*4 - 25*4]
		lea		eax, [p3]
		mov		edi, 25h	; 25h*4 = 94h
	$L_X:
		mov		edx, [ecx - 0FCh]
		mov		ebx, [ecx]
		sub		edx, ebx
		and		edx, 3FFFFFFFh
		mov		[eax], edx
		add		eax, 4
		add		ecx, 4
		dec		edi
		jnz		$L_X
	}

	_asm{
		lea		eax, [p3 + 25h*4]
		mov		edi, (3F1h + 25h)
		lea		ecx, [buff + edi*4 - 190h] ; [buff + 3f1*4 - 3f*4]
		mov		edi, 3Fh
	$L_Y:
		mov		edx, [ecx]
		mov		esi, [eax - 94h]
		sub		edx, esi
		and		edx, 3FFFFFFFh
		mov		[eax], edx
		add		eax, 4
		add		ecx, 4
		dec		edi
		jnz		$L_Y
	}

	/* ptr indicates to first value of buffer P2 */
	buff[0x64] = 0xFFFFFFFF;
	ptr = buff;
}

