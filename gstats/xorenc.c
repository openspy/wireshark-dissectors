#include "xorenc.h"

#define DOXCODE(b, l, e) \
	enc = e;             \
	xcode_buf(b, (int)(l));

static char enc1[16] = "GameSpy3D";
static char enc3[16] = {'\0', 'r', 'o', 'j', 'e', 'c', 't', 'A', 'p', 'h', 'e', 'x', '\0'};
static char *enc = enc1;

static void xcode_buf(char *buf, int len)
{
	int i;
	char *pos = enc;

	for (i = 0; i < len; i++)
	{
		buf[i] ^= *pos++;
		if (*pos == 0)
			pos = enc;
	}
}
