source=glob.c
root-rel=../

include ../Rules

#conf-src=$(srcdir)/conf
#conf-fragments=$(conf-src)/confbase.Y $(srcdir)/sysdep/unix/config.Y $(srcdir)/sysdep/unix/krt.Y $(srcdir)/sysdep/linux/netlink.Y  $(addsuffix /config.Y,$(static-dir-paths))

ifdef DEBUG
BISON_DEBUG=-t
#FLEX_DEBUG=-d
endif

glob.h: glob.c

depend: glob.h
