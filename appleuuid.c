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
    int little = 0;

    if (argc != 2 && argc != 3) {
        fprintf(stderr,
            "Syntax: %s [-l] <uuid>\n\n"
            "   -l      Interpret first 3 UUID fields as little-endian.\n",
            argv[0]);
        return 1;
    }

    if (argc == 3 && strcmp(argv[1], "-l")) {
        fprintf(stderr, "Invalid option.\n");
        return 1;
    }

    uuidstr = argc == 3 ? argv[2] : argv[1];
    little = argc == 3;

    if (!parse(uuidstr, uuid)) {
        fprintf(stderr, "Invalid UUID syntax.\n");
        return 1;
    }

    if (little) {
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
