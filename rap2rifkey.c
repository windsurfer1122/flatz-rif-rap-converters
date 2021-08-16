// (c) flatz

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "common.h"
#include "tools.h"

static int load_from_file(const char *name, u8 *data, u32 length);
static int rap_to_klicensee(u8 *rap_key, u8 *klicensee);

int main(int argc, char *argv[])
{
	struct keylist *klist = NULL;
	struct rif *rif = NULL;
	FILE *fp = NULL;
	int i;

	u8 rap_key[16];
	u8 klicensee[16];

	if (argc < 3) {
		printf("usage: rap2rifkey <rap file> <rif key file>\n");
		return 0;
	}

	klist = keys_get(KEY_NPDRM);
	if (klist == NULL) {
		fail("no key found");
		goto fail;
	}

	if (load_from_file(argv[1], rap_key, sizeof(rap_key)) < 0) {
		fail("unable to load rap file");
		goto fail;
	}

	memset(klicensee, 0, sizeof(klicensee));
	rap_to_klicensee(rap_key, klicensee);

	fp = fopen(argv[2], "wb");
	if (fp == NULL) {
		fail("unable to create rif key file");
		goto fail;
	}
	fwrite(klicensee, sizeof(klicensee), 1, fp);
	fclose(fp);

	return 0;

fail:
	if (fp != NULL) {
		fclose(fp);
	}

	if (klist != NULL) {
		if (klist->keys != NULL)
			free(klist->keys);
		free(klist);
	}

	return 0;
}

static int load_from_file(const char *path, u8 *data, u32 length)
{
	FILE *fp = NULL;
	u32 read;
	int ret = -1;
	fp = fopen(path, "rb");
	if (fp == NULL)
		goto fail;
	read = fread(data, length, 1, fp);
	if (read != 1)
		goto fail;
	ret = 0;
fail:
	if (fp != NULL)
		fclose(fp);
	return ret;
}

static int rap_to_klicensee(u8 *rap_key, u8 *klicensee)
{
	static u8 rap_initial_key[16] = {
		0x86, 0x9F, 0x77, 0x45, 0xC1, 0x3F, 0xD8, 0x90, 0xCC, 0xF2, 0x91, 0x88, 0xE3, 0xCC, 0x3E, 0xDF
	};
	static u8 pbox[16] = {
		0x0C, 0x03, 0x06, 0x04, 0x01, 0x0B, 0x0F, 0x08, 0x02, 0x07, 0x00, 0x05, 0x0A, 0x0E, 0x0D, 0x09
	};
	static u8 e1[16] = {
		0xA9, 0x3E, 0x1F, 0xD6, 0x7C, 0x55, 0xA3, 0x29, 0xB7, 0x5F, 0xDD, 0xA6, 0x2A, 0x95, 0xC7, 0xA5
	};
	static u8 e2[16] = {
		0x67, 0xD4, 0x5D, 0xA3, 0x29, 0x6D, 0x00, 0x6A, 0x4E, 0x7C, 0x53, 0x7B, 0xF5, 0x53, 0x8C, 0x74
	};

	int round_num;
	int i;

	u8 key[16];
	aes128(rap_initial_key, rap_key, key);

	for (round_num = 0; round_num < 5; ++round_num) {
		for (i = 0; i < 16; ++i) {
			int p = pbox[i];
			key[p] ^= e1[p];
		}
		for (i = 15; i >= 1; --i) {
			int p = pbox[i];
			int pp = pbox[i - 1];
			key[p] ^= key[pp];
		}
		int o = 0;
		for (i = 0; i < 16; ++i) {
			int p = pbox[i];
			u8 kc = key[p] - o;
			u8 ec2 = e2[p];
			if (o != 1 || kc != 0xFF) {
				o = kc < ec2 ? 1 : 0;
				key[p] = kc - ec2;
			} else if (kc == 0xFF) {
				key[p] = kc - ec2;
			} else {
				key[p] = kc;
			}
		}
	}

	memcpy(klicensee, key, sizeof(key));
	return 0;
}
