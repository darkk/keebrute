/*
 * Brute-force application to tests passwords for KeePass kdb files, kdbx are
 * not supported. Only AES-encrypted files are supported at the moment.
 * Key-files are not supported, but support for key-files is trivial to add.
 *
 * The logic is deducted from file src/format/KeePass1Reader.cpp
 * (KeepassX-2.0-alpha source code), so it inherits the license:
 *
 *  Copyright (C) 2012 Felix Geyer <debfx@fobos.de>
 *  Copyright (C) 2012 Leonid Evdokimov <leon@darkk.net.ru>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 2 or (at your option)
 *  version 3 of the License.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * OpenSSL may be not the fastest AES library for ECB mode (16-bytes block).
 * See "AES Speed" discussion in openssl-users@:
 * - http://comments.gmane.org/gmane.comp.encryption.openssl.user/38051
 * - http://www.mail-archive.com/openssl-users@openssl.org/msg60637.html
 * OTOH, speed_limit affects only CBC mode, so the claim above may be invalid.
 *
 * 63s for 3072 passwords with 50000 rounds and 4400 payload bytes
 * 1 thread:  48.75 pass/s
 * 2 threads: 91.34
 * 3 threads: 93.19
 * 4 threads: 98.35
 * These numbers make perfect sence on Intel(R) Core(TM) i7-2620M CPU @ 2.70GHz
 * with 2 cores (4 CPUs, HT turned on).
 */
#include <stdio.h>
#include <err.h>
#include <stdlib.h>
#include <stdint.h>
#include <endian.h>
#include <assert.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

static const int key_debug = 0;
static const size_t max_passlen = 128;

uint32_t read_le_32(FILE* fd)
{
    uint32_t value;
    if (fread(&value, sizeof(value), 1, fd) != 1)
        err(EXIT_FAILURE, "Can't read value from file");
    return le32toh(value);
}

void read_blob(FILE* fd, uint8_t* buf, size_t buf_len)
{
    if (fread(buf, buf_len, 1, fd) != 1)
        err(EXIT_FAILURE, "Can't read value from file");
}

void print_oct_blob(FILE* fd, const uint8_t* buf, size_t buf_len)
{
    size_t i;
    for (i = 0; i < buf_len; ++i) {
        if (isprint(buf[i]))
            fputc(buf[i], fd);
        else
            printf("\\%o", buf[i]);
    }
}

void read_magic(FILE* fd)
{
    uint32_t sign1 = read_le_32(fd);
    uint32_t sign2 = read_le_32(fd);
    if (sign1 != 0x9AA2D903 || sign2 != 0xB54BFB65)
        errx(EXIT_FAILURE, "Magic number mismatch");
}

void reader_key(
        uint8_t finalKey[32],
        const uint8_t* pass, const size_t passlen,
        const uint8_t master_seed[16],
        const uint8_t transform_seed[32], uint32_t transform_rounds)
{
    uint8_t rawKey[32];
    SHA256(pass, passlen, rawKey);
    // if not keyfile:  rawKey = SHA256(password)
    // if not password: rawKey = derived_sha256(keyfile)
    // else:            rawKey = SHA256(SHA256(password) || derived_sha256(keyfile))
    if (key_debug) {
        printf("rawKey(): ");
        print_oct_blob(stdout, rawKey, 32);
        printf("\n");
    }

    AES_KEY aes_key;
    AES_set_encrypt_key(transform_seed, 32*8/*256*/, &aes_key);

    uint32_t i;
    for (i = 0; i < transform_rounds; ++i) {
        AES_encrypt(rawKey,      rawKey,      &aes_key); // in and out can overlap, block size = 128bit
        AES_encrypt(rawKey + 16, rawKey + 16, &aes_key);
    }
    // rawKey is now transformed key
    if (key_debug) {
        printf("transformed: ");
        print_oct_blob(stdout, rawKey, 32);
        printf("\n");
    }

    uint8_t concat[48];
    memcpy(concat, master_seed, 16);
    SHA256(rawKey, 32, concat+16);

    if (key_debug) {
        printf("key.transform(): ");
        print_oct_blob(stdout, concat+16, 32);
        printf("\n");
    }

    SHA256(concat, 48, finalKey);

    if (key_debug) {
        printf("finalKey: ");
        print_oct_blob(stdout, finalKey, 32);
        printf("\n");
    }
}

struct keepass_data {
    uint8_t transform_seed[32];
    uint8_t master_seed[16];
    uint8_t enc_iv[16];
    uint8_t content_hash[32];
    uint32_t transform_rounds;
    size_t payload_len;
    uint8_t *payload;
};

void load_keepass(struct keepass_data* kd, const char* fname)
{
    FILE* fd = fopen(fname, "rb");

    read_magic(fd);

    uint32_t enc_flags = read_le_32(fd);
    printf("Enc flags: 0x%.8x, Rijndael (0x02): %s, Twofish (0x08): %s\n",
            enc_flags,
            enc_flags & 2 ? "yes" : "no",
            enc_flags & 8 ? "yes" : "no");

    uint32_t version = read_le_32(fd);
    if ( (version & 0xFFFFFF00) != (0x00030002 & 0xFFFFFF00) )
        err(EXIT_FAILURE, "Unsupported version: %.8x", version);

    read_blob(fd, kd->master_seed, sizeof(kd->master_seed));
    read_blob(fd, kd->enc_iv, sizeof(kd->enc_iv));

    uint32_t num_groups = read_le_32(fd);
    uint32_t num_entries = read_le_32(fd);
    printf("Fun plaintext in headers -- num_groups: %u, num_entries: %u\n", num_groups, num_entries);

    read_blob(fd, kd->content_hash, sizeof(kd->content_hash));
    read_blob(fd, kd->transform_seed, sizeof(kd->transform_seed));

    kd->transform_rounds = read_le_32(fd);
    printf("transform_rounds: %u\n", kd->transform_rounds);

    // keyfile is not supported yet
    if (!(enc_flags & 2))
        err(EXIT_FAILURE, "Only Rijndael/AES-encrypted kdb's are supported.");

    long payload_pos = ftell(fd);
    fseek(fd, 0, SEEK_END);
    long eof_pos = ftell(fd);
    fseek(fd, payload_pos, SEEK_SET);

    kd->payload_len = eof_pos - payload_pos;
    printf("%zu bytes of encrypted payload\n", kd->payload_len);
    if ((kd->payload_len % 16) != 0)
        err(EXIT_FAILURE, "Broken file? Payload has non-int number of 128-bit blocks");

    kd->payload = malloc(kd->payload_len);
    read_blob(fd, kd->payload, kd->payload_len);

    if (key_debug) {
        printf("master_seed: ");
        print_oct_blob(stdout, kd->master_seed, 16);
        printf("\nenc_iv: ");
        print_oct_blob(stdout, kd->enc_iv, 16);
        printf("\ncontent_hash: ");
        print_oct_blob(stdout, kd->content_hash, 32);
        printf("\ntransform_seed: ");
        print_oct_blob(stdout, kd->transform_seed, 32);
        printf("\n");
    }
    fclose(fd);
}

int is_good_password(const struct keepass_data* kd, const char* pass, size_t passlen)
{
    uint8_t finalKey[32];
    reader_key(finalKey, pass, passlen, kd->master_seed, kd->transform_seed, kd->transform_rounds);

    AES_KEY aes_key;
    AES_set_decrypt_key(finalKey, 32*8, &aes_key);

    uint8_t enc_iv_copy[16];
    memcpy(enc_iv_copy, kd->enc_iv, 16);

    uint8_t plaintext[kd->payload_len];
    AES_cbc_encrypt(kd->payload, plaintext, kd->payload_len, &aes_key, enc_iv_copy, AES_DECRYPT);

    // PKCS7 padding
    const size_t plaintext_len = kd->payload_len - plaintext[kd->payload_len-1];
    if (plaintext_len >= kd->payload_len) {
        // err(EXIT_FAILURE, "Bad padding - plaintext_len: %zu for payload_len: %zu", plaintext_len, kd->payload_len);
        return 0;
    }

    uint8_t plaintext_hash[32];
    SHA256(plaintext, plaintext_len, plaintext_hash);
    return (memcmp(plaintext_hash, kd->content_hash, 32) == 0);
}

struct shared_state {
    pthread_mutex_t mtx;
    const struct keepass_data* kd;
    int done;
    unsigned int passcnt;
};

void* thread(void* arg)
{
    struct shared_state* state = arg;
    const struct keepass_data *kd = state->kd;

    uint8_t passbuf[max_passlen];
    unsigned int passcnt = 0;
    for (;;) {
        pthread_mutex_lock(&state->mtx);
        char *got = fgets(passbuf, sizeof(passbuf), stdin);
        if (state->done)
            got = NULL;
        pthread_mutex_unlock(&state->mtx);

        if (!got)
            break;

        size_t passlen = strlen(passbuf);
        while (passlen > 0 && passbuf[passlen-1] == '\x0d' || passbuf[passlen-1] == '\x0a')
            passlen--;

        if (passlen) {
            passcnt++;
            if (is_good_password(kd, passbuf, passlen)) {
                pthread_mutex_lock(&state->mtx);
                state->done = 1;
                pthread_mutex_unlock(&state->mtx);

                printf("Good password: \"");
                print_oct_blob(stdout, passbuf, passlen);
                printf("\"\n");
                break;
            }
        }
    }

    pthread_mutex_lock(&state->mtx);
    state->passcnt += passcnt;
    pthread_mutex_unlock(&state->mtx);

    return NULL;
}

int main(int argc, const char* argv[]) {
    if (argc != 2 && argc != 3)
        errx(EXIT_FAILURE, "Usage: %s <filename> [thread_count]", argv[0]);

    struct keepass_data* kd = malloc(sizeof(struct keepass_data));
    load_keepass(kd, argv[1]);
    const int thread_count = argc == 3 ? atoi(argv[2]) : 1;

    printf("Reading passwords from stdin one-per-line using %d threads...\n", thread_count);

    struct shared_state state;
    memset(&state, 0, sizeof(state));
    pthread_mutex_init(&state.mtx, NULL);
    state.kd = kd;

    struct timeval begin, end, delta;
    gettimeofday(&begin, NULL);

    pthread_t threads[thread_count];
    int i;
    for (i = 0; i < thread_count; i++)
        if (pthread_create(threads+i, NULL, thread, &state) != 0)
            err(EXIT_FAILURE, "pthread_create failed");
    for (i = 0; i < thread_count; i++)
        if (pthread_join(threads[i], NULL) != 0)
            err(EXIT_FAILURE, "pthread_join failed");

    gettimeofday(&end, NULL);
    timersub(&end, &begin, &delta);
    const uint64_t delta_us = delta.tv_sec * 1000000 + delta.tv_usec;
    printf("%u passwords tested within %.1f seconds, %.2f passwords per second.\n",
            state.passcnt,
            1.0*delta_us/1e6,
            1e6*state.passcnt/delta_us);
    return 0;
}
