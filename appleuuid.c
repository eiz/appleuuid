/*
 * appleuuid
 * Copyright (c) 2016 Mackenzie Straight. See LICENSE for details.
 */

#include <stdio.h>

#include "sha1.h"

static int parse(const char *str, uint8_t uuid[16])
{
    int n = 0;

    sscanf(str,
        "%2hhx%2hhx%2hhx%2hhx-"
        "%2hhx%2hhx-"
        "%2hhx%2hhx-"
        "%2hhx%2hhx-"
        "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%n",
        &uuid[0], &uuid[1], &uuid[2], &uuid[3],
        &uuid[4], &uuid[5],
        &uuid[6], &uuid[7],
        &uuid[8], &uuid[9],
        &uuid[10], &uuid[11], &uuid[12], &uuid[13], &uuid[14], &uuid[15], &n);

    return n == 36 && !str[36];
}

static void reverse(uint8_t *buf, int len)
{
    uint8_t *s, *e;

    for (s = buf, e = buf + (len - 1); s < e; ++s, --e) {
        uint8_t v = *s;

        *s = *e;
        *e = v;
    }
}

uint8_t prefix[] =
{
    0x2A, 0x06, 0x19, 0x90, 0xD3, 0x8D, 0x44, 0x40,
    0xA1, 0x39, 0xC4, 0x97, 0x70, 0x37, 0x65, 0xAC
};

int main(int argc, const char *argv[])
{
    uint8_t uuid[16] = {};
    uint8_t hash[20] = {};
    SHA1_CTX context;
    const char *uuidstr;
    int swapin = 0, swapout = 0;
    int i;

    if (argc < 2) {
        fprintf(stderr,
            "Syntax: %s [-b] [-B] <uuid>\n\n"
            "   -b      Byte-swap first 3 UUID input fields.\n",
            "   -B      Byte-swap first 3 UUID output fields.\n",
            argv[0]);
        return 1;
    }

    for (i = 1; i < argc; ++i) {
        if (!strcmp(argv[i], "-b")) {
            swapin = 1;
        } else if (!strcmp(argv[i], "-B")) {
            swapout = 1;
        } else {
            uuidstr = argv[i];
        }
    }

    if (!uuidstr) {
        fprintf(stderr, "No GUID specified.\n");
        return 1;
    }


    if (!parse(uuidstr, uuid)) {
        fprintf(stderr, "Invalid UUID syntax.\n");
        return 1;
    }

    if (swapin) {
        reverse(uuid, 4);
        reverse(uuid+4, 2);
        reverse(uuid+6, 2);
    }

    SHA1Init(&context);
    SHA1Update(&context, prefix, sizeof(prefix));
    SHA1Update(&context, uuid, sizeof(uuid));
    SHA1Final(hash, &context);
    hash[6] &= 0x0F;
    hash[6] |= 0x50;
    hash[8] &= 0x3F;
    hash[8] |= 0x80;

    if (swapin) {
        reverse(hash, 4);
        reverse(hash+4, 2);
        reverse(hash+6, 2);
    }

    printf(
        "%02X%02X%02X%02X-"
        "%02X%02X-"
        "%02X%02X-"
        "%02X%02X-"
        "%02X%02X%02X%02X%02X%02X\n",
        hash[0], hash[1], hash[2], hash[3],
        hash[4], hash[5],
        hash[6], hash[7],
        hash[8], hash[9],
        hash[10], hash[11], hash[12], hash[13], hash[14], hash[15]);
    return 0;
}
