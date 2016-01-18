/*
* @Author: mcxiaoke
* @Date:   2016-01-18 16:32:40
* @Last Modified by:   mcxiaoke
* @Last Modified time: 2016-01-18 18:07:19
*/


/**

算法/模式/填充                16字节加密后数据长度        不满16字节加密后长度
AES/CBC/NoPadding             16                          不支持
AES/CBC/PKCS5Padding          32                          16
AES/CBC/ISO10126Padding       32                          16
AES/CFB/NoPadding             16                          原始数据长度
AES/CFB/PKCS5Padding          32                          16
AES/CFB/ISO10126Padding       32                          16
AES/ECB/NoPadding             16                          不支持
AES/ECB/PKCS5Padding          32                          16
AES/ECB/ISO10126Padding       32                          16
AES/OFB/NoPadding             16                          原始数据长度
AES/OFB/PKCS5Padding          32                          16
AES/OFB/ISO10126Padding       32                          16
AES/PCBC/NoPadding            16                          不支持
AES/PCBC/PKCS5Padding         32                          16
AES/PCBC/ISO10126Padding      32                          16

https://www.openssl.org/docs/manmaster/crypto/
https://www.openssl.org/docs/manmaster/crypto/EVP_CipherInit_ex.html
https://www.openssl.org/docs/manmaster/crypto/EVP_CipherUpdate.html
https://www.openssl.org/docs/manmaster/crypto/EVP_EncryptInit.html

**/

#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <assert.h>

#include <openssl/evp.h>

#include "log.h"
#include "common.h"
#include "evp_tests.h"

int data_crypt(const uint8_t* in, const int inlen,
               uint8_t* out, int* outlen,
               const uint8_t* key, const uint8_t* iv,
               int do_encrypt)
{
    EVP_CIPHER_CTX *ctx;
    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                      do_encrypt);
    assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv, do_encrypt);
    if (!EVP_CipherUpdate(ctx, out, outlen, in, inlen))
    {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    if (!EVP_CipherFinal_ex(ctx, out, outlen))
    {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    EVP_CIPHER_CTX_free(ctx);
    return 1;
}

int file_crypt(FILE *in, FILE *out, int do_encrypt)
{
    /* Allow enough space in output buffer for additional block */
    unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    int inlen, outlen;
    EVP_CIPHER_CTX *ctx;
    /* Bogus key and IV: we'd normally set these from
     * another source.
     */
    unsigned char key[] = "0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";

    /* Don't set key or IV right away; we want to check lengths */
    ctx = EVP_CIPHER_CTX_new();
    EVP_CipherInit_ex(ctx, EVP_aes_128_cbc(), NULL, NULL, NULL,
                      do_encrypt);
    assert(EVP_CIPHER_CTX_key_length(ctx) == 16);
    assert(EVP_CIPHER_CTX_iv_length(ctx) == 16);

    /* Now we can set key and IV */
    EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, do_encrypt);

    for (;;)
    {
        inlen = fread(inbuf, 1, 1024, in);
        if (inlen <= 0) break;
        if (!EVP_CipherUpdate(ctx, outbuf, &outlen, inbuf, inlen))
        {
            /* Error */
            EVP_CIPHER_CTX_free(ctx);
            return 0;
        }
        fwrite(outbuf, 1, outlen, out);
    }
    if (!EVP_CipherFinal_ex(ctx, outbuf, &outlen))
    {
        /* Error */
        EVP_CIPHER_CTX_free(ctx);
        return 0;
    }
    fwrite(outbuf, 1, outlen, out);

    EVP_CIPHER_CTX_free(ctx);
    return 1;
}




void evp_aes1() {
    unsigned char key[] = "0123456789abcdeF";
    unsigned char iv[] = "1234567887654321";
    const char* text = "Copyright © 1988-2016 Free Software Foundation, Inc.";
    int len = 0;
    uint8_t* in = hex2bin(text, &len);
    int inlen = len;
    LOGD("in=%s,len=%d", bin2hex(in, inlen, &len), inlen);
    uint8_t temp[inlen];
    int tlen = 0;
    data_crypt(in, inlen, temp, &tlen, key, iv, 1);
    LOGD("out=%s,len=%d", bin2hex(temp, tlen, &len), len);
    uint8_t out[inlen];
    int outlen = 0;
    data_crypt(temp, tlen, out, &outlen, key, iv, 0);
    LOGD("out=%s,len=%d", bin2hex(out, outlen, &len), len);
}

void run() {
    evp_aes1();
}
