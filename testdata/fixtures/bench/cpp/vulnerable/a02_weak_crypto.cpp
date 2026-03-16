// Source: CWE-327 - Use of weak cryptographic algorithms (MD5/DES)
// Expected: BATOU-MEM
// OWASP: A02:2021 - Cryptographic Failures

#include <openssl/md5.h>
#include <openssl/des.h>
#include <cstring>

void hashPassword(const char* password) {
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char*)password, strlen(password), digest);
}

void encryptData(const char* key, const char* data) {
    DES_cblock desKey;
    DES_key_schedule schedule;
    memcpy(desKey, key, 8);
    DES_set_key_unchecked(&desKey, &schedule);
}
