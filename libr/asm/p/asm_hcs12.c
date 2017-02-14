/* radare - LGPL - Copyright 2017 - condret */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <r_lib.h>
#include "../arch/hcs12/hcs12dis.c"

static int disassemble(RAsm *a, RAsmOp *r_op, const ut8 *buf, int len) {
	int size = hcs12_dis (r_op, buf, len);
	if(size<0) size=0;
	return r_op->size = size;
}

RAsmPlugin r_asm_plugin_hcs12 = {
	.name = "hcs12",
	.desc = "hcs12 microcontroller",
	.arch = "hcs12",
	.license = "LGPL3",
	.bits = 16,
	.endian = R_SYS_ENDIAN_LITTLE,
	.disassemble = &disassemble,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_ASM,
	.data = &r_asm_plugin_hcs12,
	.version = R2_VERSION
};
#endif
