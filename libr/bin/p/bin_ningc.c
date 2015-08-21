/* radare - LGPL - 2013 - 2015 - condret@runas-racer.com */

#include <r_types.h>
#include <r_util.h>
#include <r_lib.h>
#include <r_bin.h>
#include <string.h>
#include "../format/nin/ngc.h"

static int check (RBinFile *arch);
static int check_gc_magic (const ut8 *buf, ut64 length);

static Sdb* get_sdb (RBinObject *o) {
	if (!o) return NULL;
	//struct r_bin_[NAME]_obj_t *bin = (struct r_bin_r_bin_[NAME]_obj_t *) o->bin_obj;
	//if (bin->kv) return kv;
	return NULL;
}

static void * load_bytes(RBinFile *arch, const ut8 *buf, ut64 sz, ut64 loadaddr, Sdb *sdb){
	return R_NOTNULL;
}

static int check(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	return check_gc_magic (bytes, sz);

}

static int check_gc_magic(const ut8 *buf, ut64 length) {
	ut8 magic[4];		//ut32 would be faster but i'm too tired to do the host-endian-check
	if (!buf || length < (0x1c+4)) {
		return 0;
	}
	memcpy (magic, buf+0x1c, 4);
	return (!memcmp (gc_magic_bytes, magic, 4))? 1: 0;
}

static int load(RBinFile *arch) {
	const ut8 *bytes = arch ? r_buf_buffer (arch->buf) : NULL;
	ut64 sz = arch ? r_buf_size (arch->buf): 0;
	if (!arch || !arch->o) return R_FALSE;
	arch->o->bin_obj = load_bytes (arch, bytes, sz, arch->o->loadaddr, arch->sdb);
	return check_gc_magic (bytes, sz);
}

static int destroy(RBinFile *arch) {
	r_buf_free (arch->buf);
	arch->buf = NULL;
	return R_TRUE;
}

static ut64 baddr(RBinFile *arch) {
	return 0LL;
}

static RBinInfo* info(RBinFile *arch) {
	RBinInfo *ret = R_NEW0 (RBinInfo);

	if (!ret)
		return NULL;

	if (!arch || !arch->buf) {
		free (ret);
		return NULL;
	}
	ret->type = strdup ("Nintendo GameCube image");
	ret->file = calloc (sizeof(ut8), 64);
	r_buf_read_at (arch->buf, 0x20, ret->file, 64);
	ret->file[63] = 0;
	ret->machine = strdup ("GameCube");
	ret->os = strdup ("Linux");
	ret->arch = strdup ("ppc");
	ret->has_va = 1;
	ret->bits = 32;
	ret->big_endian = 0;
	ret->dbg_info = 0;
	return ret;
}




struct r_bin_plugin_t r_bin_plugin_ningc = {
	.name = "ningc",
	.desc = "GameCube image format r_bin plugin",
	.license = "LGPL3",
	.init = NULL,
	.fini = NULL,
	.get_sdb = &get_sdb,
	.load = &load,
	.load_bytes = &load_bytes,
	.destroy = &destroy,
	.check = &check,
	.check_bytes = &check_gc_magic,
	.baddr = &baddr,
	.boffset = NULL,
	.binsym = NULL,
	.entries = NULL,
	.sections = NULL,
	.symbols = NULL,
	.imports = NULL,
	.strings = NULL,
	.info = &info,
	.fields = NULL,
	.libs = NULL,
	.relocs = NULL,
	.mem = NULL,
	.dbginfo = NULL,
	.create = NULL,
	.write = NULL,
};

#ifndef CORELIB
struct r_lib_struct_t radare_plugin = {
	.type = R_LIB_TYPE_BIN,
	.data = &r_bin_plugin_ningc,
	.version = R2_VERSION
};
#endif
