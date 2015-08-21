OBJ_NINGC=bin_ningc.o

STATIC_OBJ+=${OBJ_NINGC}
TARGET_NINGC=bin_ningc.${EXT_SO}

ALL_TARGETS+=${TARGET_NINGC}

${TARGET_NINGC}: ${OBJ_NINGC}
	${CC} $(call libname,bin_ningc) ${CFLAGS} \
		${OBJ_NINGC} \
		$(LINK) $(LDFLAGS)
