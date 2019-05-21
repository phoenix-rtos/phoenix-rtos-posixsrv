/*
 * Phoenix-RTOS
 *
 * libphoenix
 *
 * vfork for x86
 *
 * Copyright 2019 Phoenix Systems
 * Author: Jan Sikorski
 *
 * This file is part of Phoenix-RTOS.
 *
 * %LICENSE%
 */

#define __ASSEMBLY__


.text

.globl _px_vfork_setjmp_wrapped
.type _px_vfork_setjmp_wrapped, %function
_px_vfork_setjmp_wrapped:

	call px_do_vfork
	test %eax, %eax
	jnz .err

	pop %ecx
	lea _px_vfork_jmpbuf, %eax
	push %eax
	push %ecx

	jmp setjmp

.err:
	ret

.size _px_vfork_setjmp_wrapped, .-_px_vfork_setjmp_wrapped

.data
.globl _px_vfork_jmpbuf

_px_vfork_jmpbuf:
	.space 24, 0xcb
