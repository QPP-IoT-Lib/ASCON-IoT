#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "api.h"
#include "crypto_aead.h"

static int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static unsigned char *decode_hex(const char *hex, size_t *len) {
    size_t n = strlen(hex);

    if (n % 2 != 0) {
        fprintf(stderr, "hex length must be even\n");
        exit(2);
    }

    *len = n / 2;

    unsigned char *out = malloc(*len ? *len : 1);
    if (!out) {
        perror("malloc");
        exit(2);
    }

    for (size_t i = 0; i < *len; i++) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            fprintf(stderr, "invalid hex input\n");
            exit(2);
        }

        out[i] = (unsigned char)((hi << 4) | lo);
    }

    return out;
}

static void print_hex(const unsigned char *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
}

static void require_16(const char *name, size_t len) {
    if (len != 16) {
        fprintf(stderr, "%s must be exactly 16 bytes\n", name);
        exit(2);
    }
}

static int encrypt_mode(
    const char *key_hex,
    const char *nonce_hex,
    const char *ad_hex,
    const char *pt_hex
) {
    size_t key_len, nonce_len, ad_len, pt_len;

    unsigned char *key = decode_hex(key_hex, &key_len);
    unsigned char *nonce = decode_hex(nonce_hex, &nonce_len);
    unsigned char *ad = decode_hex(ad_hex, &ad_len);
    unsigned char *pt = decode_hex(pt_hex, &pt_len);

    require_16("key", key_len);
    require_16("nonce", nonce_len);

    unsigned char *out = malloc(pt_len + CRYPTO_ABYTES);
    if (!out) {
        perror("malloc");
        return 2;
    }

    unsigned long long out_len = 0;

    int rc = crypto_aead_encrypt(
        out,
        &out_len,
        pt,
        pt_len,
        ad,
        ad_len,
        NULL,
        nonce,
        key
    );

    if (rc != 0) {
        fprintf(stderr, "crypto_aead_encrypt failed: %d\n", rc);
        return 3;
    }

    if (out_len != pt_len + CRYPTO_ABYTES) {
        fprintf(stderr, "unexpected ciphertext length\n");
        return 3;
    }

    printf("CT=");
    print_hex(out, pt_len);
    printf("\nTAG=");
    print_hex(out + pt_len, CRYPTO_ABYTES);
    printf("\n");

    free(out);
    free(pt);
    free(ad);
    free(nonce);
    free(key);

    return 0;
}

static int decrypt_mode(
    const char *key_hex,
    const char *nonce_hex,
    const char *ad_hex,
    const char *ct_hex,
    const char *tag_hex
) {
    size_t key_len, nonce_len, ad_len, ct_len, tag_len;

    unsigned char *key = decode_hex(key_hex, &key_len);
    unsigned char *nonce = decode_hex(nonce_hex, &nonce_len);
    unsigned char *ad = decode_hex(ad_hex, &ad_len);
    unsigned char *ct = decode_hex(ct_hex, &ct_len);
    unsigned char *tag = decode_hex(tag_hex, &tag_len);

    require_16("key", key_len);
    require_16("nonce", nonce_len);
    require_16("tag", tag_len);

    unsigned char *combined = malloc(ct_len + tag_len);
    unsigned char *pt = malloc(ct_len ? ct_len : 1);

    if (!combined || !pt) {
        perror("malloc");
        return 2;
    }

    memcpy(combined, ct, ct_len);
    memcpy(combined + ct_len, tag, tag_len);

    unsigned long long pt_len = 0;

    int rc = crypto_aead_decrypt(
        pt,
        &pt_len,
        NULL,
        combined,
        ct_len + tag_len,
        ad,
        ad_len,
        nonce,
        key
    );

    if (rc != 0) {
        printf("AUTHFAIL\n");
    } else {
        printf("PT=");
        print_hex(pt, pt_len);
        printf("\n");
    }

    free(pt);
    free(combined);
    free(tag);
    free(ct);
    free(ad);
    free(nonce);
    free(key);

    return rc == 0 ? 0 : 3;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr,
            "usage:\n"
            "  %s enc KEY NONCE AD PT\n"
            "  %s dec KEY NONCE AD CT TAG\n",
            argv[0], argv[0]
        );
        return 2;
    }

    if (strcmp(argv[1], "enc") == 0) {
        if (argc != 6) {
            fprintf(stderr, "invalid enc arguments\n");
            return 2;
        }

        return encrypt_mode(
            argv[2],
            argv[3],
            argv[4],
            argv[5]
        );
    }

    if (strcmp(argv[1], "dec") == 0) {
        if (argc != 7) {
            fprintf(stderr, "invalid dec arguments\n");
            return 2;
        }

        return decrypt_mode(
            argv[2],
            argv[3],
            argv[4],
            argv[5],
            argv[6]
        );
    }

    fprintf(stderr, "unknown mode: %s\n", argv[1]);
    return 2;
}
