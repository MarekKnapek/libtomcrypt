/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */
/**
   @param sha512_224.c
   SHA512/224 hash included in sha512.c
*/

#include "tomcrypt_private.h"

#if defined(LTC_SHA512_224) && defined(LTC_SHA512)

const struct ltc_hash_descriptor sha512_224_portable_desc =
{
    "sha512-224 (portable)",
    15,
    28,
    128,

    /* OID */
   { 2, 16, 840, 1, 101, 3, 4, 2, 5,  },
   9,

    &sha512_224_c_init,
    &sha512_c_process,
    &sha512_224_c_done,
    &sha512_224_c_test,
    NULL
};

/**
   Initialize the hash state
   @param md   The hash state you wish to initialize
   @return CRYPT_OK if successful
*/
int sha512_224_c_init(hash_state * md)
{
    LTC_ARGCHK(md != NULL);

    md->sha512.state = LTC_ALIGN_BUF(md->sha512.state_buf, 32);
    md->sha512.curlen = 0;
    md->sha512.length = 0;
    md->sha512.state[0] = CONST64(0x8C3D37C819544DA2);
    md->sha512.state[1] = CONST64(0x73E1996689DCD4D6);
    md->sha512.state[2] = CONST64(0x1DFAB7AE32FF9C82);
    md->sha512.state[3] = CONST64(0x679DD514582F9FCF);
    md->sha512.state[4] = CONST64(0x0F6D2B697BD44DA8);
    md->sha512.state[5] = CONST64(0x77E36F7304C48942);
    md->sha512.state[6] = CONST64(0x3F9D85A86A1D36C8);
    md->sha512.state[7] = CONST64(0x1112E6AD91D692A1);
    return CRYPT_OK;
}

/**
   Terminate the hash to get the digest
   @param md  The hash state
   @param out [out] The destination of the hash (48 bytes)
   @return CRYPT_OK if successful
*/
int sha512_224_c_done(hash_state * md, unsigned char *out)
{
   unsigned char buf[64];

   LTC_ARGCHK(md  != NULL);
   LTC_ARGCHK(out != NULL);

    if (md->sha512.curlen >= sizeof(md->sha512.buf)) {
       return CRYPT_INVALID_ARG;
    }

   sha512_c_done(md, buf);
   XMEMCPY(out, buf, 28);
#ifdef LTC_CLEAN_STACK
   zeromem(buf, sizeof(buf));
#endif
   return CRYPT_OK;
}

/**
  Self-test the hash
  @return CRYPT_OK if successful, CRYPT_NOP if self-tests have been disabled
*/
int  sha512_224_c_test(void)
{
   return sha512_224_test_desc(&sha512_224_portable_desc, "SHA512-224 portable");
}

#endif /* defined(LTC_SHA512_224) && defined(LTC_SHA512) */
