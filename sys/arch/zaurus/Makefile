#	$NetBSD: Makefile,v 1.4 2008/10/25 22:27:38 apb Exp $

# Makefile for zaurus tags file and boot blocks

TZAURUS=	../zaurus/tags
SZAURUS=	../zaurus/zaurus/*.[ch] ../zaurus/include/*.h \
		../zaurus/dev/*.[ch]
AZAURUS=	../zaurus/zaurus/*.S ../zaurus/dev/*.S

# Directories in which to place tags links
DZAURUS=	include

.include "../../kern/Make.tags.inc"

tags:
	-ctags -wdtf ${TZAURUS} ${SZAURUS} ${COMM}
	egrep "^ENTRY(.*)|^ALTENTRY(.*)" ${AZAURUS} | \
	    ${TOOL_SED} -e \
		"s;\([^:]*\):\([^(]*\)(\([^, )]*\)\(.*\);\3 \1 /^\2(\3\4$$/;" \
	    >> ${TZAURUS}
	sort -o ${TZAURUS} ${TZAURUS}

links:
	-for i in ${DZAURUS}; do \
	    cd $$i && rm -f tags; ln -s ../tags tags; done

SUBDIR=	compile include stand

.include <bsd.subdir.mk>
