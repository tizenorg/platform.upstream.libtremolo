ACLOCAL_AMFLAGS='-I m4'

lib_LTLIBRARIES = libtremolo.la

installlibtremolodir = $(includedir)/tremolo
installlibtremolo_HEADERS = tremolo_vorbisdec_api.h

libtremolo_la_LIBADD  = $(MMCOMMON_LIBS)
libtremolo_la_CFLAGS = $(MMCOMMON_CFLAGS) -DMMF_LOG_OWNER=0x020 -DMMF_DEBUG_PREFIX=\"MMF-SOUND\"

libtremolo_la_SOURCES = \
	bitwise.c \
	codebook.c \
	dsp.c \
	floor0.c \
	floor1.c \
	floor_lookup.c \
	framing.c \
	mapping0.c \
	mdct.c \
	res012.c \
	info.c \
	vorbisfile.c \
	tremolo_vorbisdec.c \
	tremolo_vorbisdec_api.c

#if ARMv5
#libtremolo_la_SOURCES += \
#	ASM/bitwiseARM.s \
#	ASM/dpen.s \
#	ASM/floor1ARM.s \
#	ASM/mdctARM.s
#libtremolo_la_CFLAGS += -D_ARM_ASSEM_
#else
libtremolo_la_CFLAGS += -DONLY_C
#endif

pcfiles = libtremolo.pc
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = $(pcfiles)
EXTRA_DIST = $(pcfiles)
