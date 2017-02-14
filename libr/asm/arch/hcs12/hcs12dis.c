/* radare - LGPL - Copyright 2017 condret */

#include <r_types.h>
#include <r_util.h>
#include <r_asm.h>
#include <string.h>


static int hcs12_dis (RAsmOp *op, ut8 *buf, int len) {
	int size = 0;
	if (!op || !buf) {
		return -1;
	}
	switch (buf[0]) {
		case 0x47:
			strcpy (op->buf_asm, "asra");
			size = 1;
			break;
		case 0x57:
			strcpy (op->buf_asm, "asrb");
			size = 1;
			break;
	}
	return size;
}
