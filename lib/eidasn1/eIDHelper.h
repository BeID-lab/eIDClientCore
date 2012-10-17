/*
 * Copyright (C) 2012 Bundesdruckerei GmbH
 */

#if !defined(__EIDHELPER_INCLUDED__)
#define __EIDHELPER_INCLUDED__

/**
 */
inline bool operator==(OBJECT_IDENTIFIER_t a, OBJECT_IDENTIFIER_t b)
{
	if (a.size != b.size)
		return false;

	return (0 == memcmp(a.buf, b.buf, b.size));
}

/**
 */
inline OBJECT_IDENTIFIER_t makeOID(const char *oidValue)
{
	long tempArcs[1];
	long *tempArcs2 = 0x00;
	long *realArcs = 0x00;
	int realLength = OBJECT_IDENTIFIER_parse_arcs(oidValue, -1, tempArcs, 1, 0x00);

	if (realLength > 1) {
		tempArcs2 = new long[realLength];
		OBJECT_IDENTIFIER_parse_arcs(oidValue, -1, tempArcs2, realLength, 0x00);
		realArcs = tempArcs2;

	} else {
		realArcs = &tempArcs[0]; // This should never be happen ...
	}

	OBJECT_IDENTIFIER_t oid;
	oid.buf  = 0x00;
	oid.size = 0;
	OBJECT_IDENTIFIER_set_arcs(&oid, realArcs, sizeof(unsigned long), realLength);

	if (0x00 != tempArcs2)
		delete [] tempArcs2;

	return oid;
}

#endif
