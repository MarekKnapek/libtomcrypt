/* LibTomCrypt, modular cryptographic library -- Tom St Denis */
/* SPDX-License-Identifier: Unlicense */

/* Based on serpent.cpp - originally written and placed in the public domain by Wei Dai
   https://github.com/weidai11/cryptopp/blob/master/serpent.cpp

   On 2017-10-16 wikipedia says:
   "The Serpent cipher algorithm is in the public domain and has not been patented."
   https://en.wikipedia.org/wiki/Serpent_(cipher)
 */

#include "tomcrypt_private.h"

#ifdef LTC_SERPENT

#define serpent_block_len 16

static int s_serpent_accel_ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey);
static LTC_INLINE int s_serpent_accel_ecb_encrypt_32_bit(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey); /* tdoo */

#define LTC_SERPENT_ACCEL_32_BIT /* todo move somewhere else */
#define LTC_SERPENT_ACCEL_64_BIT /* todo move somewhere else */
#define LTC_SERPENT_ACCEL_128_BIT_X86_SSE2 /* todo move somewhere else */
#define LTC_SERPENT_ACCEL_256_BIT_X86_AVX2 /* todo move somewhere else */
#if 0
#define LTC_SERPENT_ACCEL_512_BIT_X86_AVX512 /* todo move somewhere else */
#endif

#if defined LTC_SERPENT_ACCEL_64_BIT
#if defined _M_IX86
#define LTC_SERPENT_ACCEL_64_BIT_X86_MMX
#else
#define LTC_SERPENT_ACCEL_64_BIT_PLAIN
#endif
#endif


#if \
  defined LTC_SERPENT_ACCEL_32_BIT || \
  defined LTC_SERPENT_ACCEL_64_BIT_PLAIN || \
  defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX || \
  defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2 || \
  defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2 || \
  defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512 || \
  0
#define LTC_SERPENT_ACCEL 1
#else
#define LTC_SERPENT_ACCEL 0
#endif

const struct ltc_cipher_descriptor serpent_desc = {
   "serpent",
   25,                  /* cipher_ID */
   16, 32, serpent_block_len, 32,      /* min_key_len, max_key_len, block_len, default_rounds */
   &serpent_setup,
   &serpent_ecb_encrypt,
   &serpent_ecb_decrypt,
   &serpent_test,
   &serpent_done,
   &serpent_keysize,
   NULL, /*&serpent_accel_ecb_encrypt,*/
   NULL, /*&serpent_accel_ecb_decrypt,*/
   NULL, NULL,
   #if LTC_SERPENT_ACCEL
   &s_serpent_accel_ctr_encrypt,
   #else
   NULL,
   #endif
   NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

/* linear transformation */
#define s_lt(i,a,b,c,d,e)  {                                 \
                            a = ROLc(a, 13);                \
                            c = ROLc(c, 3);                 \
                            d = ROLc(d ^ c ^ (a << 3), 7);  \
                            b = ROLc(b ^ a ^ c, 1);         \
                            a = ROLc(a ^ b ^ d, 5);         \
                            c = ROLc(c ^ d ^ (b << 7), 22); \
                          }

/* inverse linear transformation */
#define s_ilt(i,a,b,c,d,e) {                                 \
                            c = RORc(c, 22);                \
                            a = RORc(a, 5);                 \
                            c ^= d ^ (b << 7);              \
                            a ^= b ^ d;                     \
                            b = RORc(b, 1);                 \
                            d = RORc(d, 7) ^ c ^ (a << 3);  \
                            b ^= a ^ c;                     \
                            c = RORc(c, 3);                 \
                            a = RORc(a, 13);                \
                          }

/* order of output from S-box functions */
#define s_beforeS0(f) f(0,a,b,c,d,e)
#define s_afterS0(f)  f(1,b,e,c,a,d)
#define s_afterS1(f)  f(2,c,b,a,e,d)
#define s_afterS2(f)  f(3,a,e,b,d,c)
#define s_afterS3(f)  f(4,e,b,d,c,a)
#define s_afterS4(f)  f(5,b,a,e,c,d)
#define s_afterS5(f)  f(6,a,c,b,e,d)
#define s_afterS6(f)  f(7,a,c,d,b,e)
#define s_afterS7(f)  f(8,d,e,b,a,c)

/* order of output from inverse S-box functions */
#define s_beforeI7(f) f(8,a,b,c,d,e)
#define s_afterI7(f)  f(7,d,a,b,e,c)
#define s_afterI6(f)  f(6,a,b,c,e,d)
#define s_afterI5(f)  f(5,b,d,e,c,a)
#define s_afterI4(f)  f(4,b,c,e,a,d)
#define s_afterI3(f)  f(3,a,b,e,c,d)
#define s_afterI2(f)  f(2,b,d,e,c,a)
#define s_afterI1(f)  f(1,a,b,c,e,d)
#define s_afterI0(f)  f(0,a,d,b,e,c)

/* The instruction sequences for the S-box functions
 * come from Dag Arne Osvik's paper "Speeding up Serpent".
 */

#define s_s0(i, r0, r1, r2, r3, r4) { \
   r3 ^= r0;   \
   r4 = r1;    \
   r1 &= r3;   \
   r4 ^= r2;   \
   r1 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r4;   \
   r4 ^= r3;   \
   r3 ^= r2;   \
   r2 |= r1;   \
   r2 ^= r4;   \
   r4 = ~r4;   \
   r4 |= r1;   \
   r1 ^= r3;   \
   r1 ^= r4;   \
   r3 |= r0;   \
   r1 ^= r3;   \
   r4 ^= r3;   \
}

#define s_i0(i, r0, r1, r2, r3, r4) { \
   r2 = ~r2;   \
   r4 = r1;    \
   r1 |= r0;   \
   r4 = ~r4;   \
   r1 ^= r2;   \
   r2 |= r4;   \
   r1 ^= r3;   \
   r0 ^= r4;   \
   r2 ^= r0;   \
   r0 &= r3;   \
   r4 ^= r0;   \
   r0 |= r1;   \
   r0 ^= r2;   \
   r3 ^= r4;   \
   r2 ^= r1;   \
   r3 ^= r0;   \
   r3 ^= r1;   \
   r2 &= r3;   \
   r4 ^= r2;   \
}

#define s_s1(i, r0, r1, r2, r3, r4) { \
   r0 = ~r0;   \
   r2 = ~r2;   \
   r4 = r0;    \
   r0 &= r1;   \
   r2 ^= r0;   \
   r0 |= r3;   \
   r3 ^= r2;   \
   r1 ^= r0;   \
   r0 ^= r4;   \
   r4 |= r1;   \
   r1 ^= r3;   \
   r2 |= r0;   \
   r2 &= r4;   \
   r0 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r0;   \
   r0 &= r2;   \
   r0 ^= r4;   \
}

#define s_i1(i, r0, r1, r2, r3, r4) { \
   r4 = r1;    \
   r1 ^= r3;   \
   r3 &= r1;   \
   r4 ^= r2;   \
   r3 ^= r0;   \
   r0 |= r1;   \
   r2 ^= r3;   \
   r0 ^= r4;   \
   r0 |= r2;   \
   r1 ^= r3;   \
   r0 ^= r1;   \
   r1 |= r3;   \
   r1 ^= r0;   \
   r4 = ~r4;   \
   r4 ^= r1;   \
   r1 |= r0;   \
   r1 ^= r0;   \
   r1 |= r4;   \
   r3 ^= r1;   \
}

#define s_s2(i, r0, r1, r2, r3, r4) { \
   r4 = r0;    \
   r0 &= r2;   \
   r0 ^= r3;   \
   r2 ^= r1;   \
   r2 ^= r0;   \
   r3 |= r4;   \
   r3 ^= r1;   \
   r4 ^= r2;   \
   r1 = r3;    \
   r3 |= r4;   \
   r3 ^= r0;   \
   r0 &= r1;   \
   r4 ^= r0;   \
   r1 ^= r3;   \
   r1 ^= r4;   \
   r4 = ~r4;   \
}

#define s_i2(i, r0, r1, r2, r3, r4) { \
   r2 ^= r3;   \
   r3 ^= r0;   \
   r4 = r3;    \
   r3 &= r2;   \
   r3 ^= r1;   \
   r1 |= r2;   \
   r1 ^= r4;   \
   r4 &= r3;   \
   r2 ^= r3;   \
   r4 &= r0;   \
   r4 ^= r2;   \
   r2 &= r1;   \
   r2 |= r0;   \
   r3 = ~r3;   \
   r2 ^= r3;   \
   r0 ^= r3;   \
   r0 &= r1;   \
   r3 ^= r4;   \
   r3 ^= r0;   \
}

#define s_s3(i, r0, r1, r2, r3, r4) { \
   r4 = r0;    \
   r0 |= r3;   \
   r3 ^= r1;   \
   r1 &= r4;   \
   r4 ^= r2;   \
   r2 ^= r3;   \
   r3 &= r0;   \
   r4 |= r1;   \
   r3 ^= r4;   \
   r0 ^= r1;   \
   r4 &= r0;   \
   r1 ^= r3;   \
   r4 ^= r2;   \
   r1 |= r0;   \
   r1 ^= r2;   \
   r0 ^= r3;   \
   r2 = r1;    \
   r1 |= r3;   \
   r1 ^= r0;   \
}

#define s_i3(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r0;   \
   r0 &= r4;   \
   r4 ^= r3;   \
   r3 |= r1;   \
   r3 ^= r2;   \
   r0 ^= r4;   \
   r2 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r1;   \
   r4 ^= r2;   \
   r2 &= r3;   \
   r1 |= r3;   \
   r1 ^= r2;   \
   r4 ^= r0;   \
   r2 ^= r4;   \
}

#define s_s4(i, r0, r1, r2, r3, r4) { \
   r1 ^= r3;   \
   r3 = ~r3;   \
   r2 ^= r3;   \
   r3 ^= r0;   \
   r4 = r1;    \
   r1 &= r3;   \
   r1 ^= r2;   \
   r4 ^= r3;   \
   r0 ^= r4;   \
   r2 &= r4;   \
   r2 ^= r0;   \
   r0 &= r1;   \
   r3 ^= r0;   \
   r4 |= r1;   \
   r4 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r2;   \
   r2 &= r3;   \
   r0 = ~r0;   \
   r4 ^= r2;   \
}

#define s_i4(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 &= r3;   \
   r2 ^= r1;   \
   r1 |= r3;   \
   r1 &= r0;   \
   r4 ^= r2;   \
   r4 ^= r1;   \
   r1 &= r2;   \
   r0 = ~r0;   \
   r3 ^= r4;   \
   r1 ^= r3;   \
   r3 &= r0;   \
   r3 ^= r2;   \
   r0 ^= r1;   \
   r2 &= r0;   \
   r3 ^= r0;   \
   r2 ^= r4;   \
   r2 |= r3;   \
   r3 ^= r0;   \
   r2 ^= r1;   \
}

#define s_s5(i, r0, r1, r2, r3, r4) { \
   r0 ^= r1;   \
   r1 ^= r3;   \
   r3 = ~r3;   \
   r4 = r1;    \
   r1 &= r0;   \
   r2 ^= r3;   \
   r1 ^= r2;   \
   r2 |= r4;   \
   r4 ^= r3;   \
   r3 &= r1;   \
   r3 ^= r0;   \
   r4 ^= r1;   \
   r4 ^= r2;   \
   r2 ^= r0;   \
   r0 &= r3;   \
   r2 = ~r2;   \
   r0 ^= r4;   \
   r4 |= r3;   \
   r2 ^= r4;   \
}

#define s_i5(i, r0, r1, r2, r3, r4) { \
   r1 = ~r1;   \
   r4 = r3;    \
   r2 ^= r1;   \
   r3 |= r0;   \
   r3 ^= r2;   \
   r2 |= r1;   \
   r2 &= r0;   \
   r4 ^= r3;   \
   r2 ^= r4;   \
   r4 |= r0;   \
   r4 ^= r1;   \
   r1 &= r2;   \
   r1 ^= r3;   \
   r4 ^= r2;   \
   r3 &= r4;   \
   r4 ^= r1;   \
   r3 ^= r0;   \
   r3 ^= r4;   \
   r4 = ~r4;   \
}

#define s_s6(i, r0, r1, r2, r3, r4) { \
   r2 = ~r2;   \
   r4 = r3;    \
   r3 &= r0;   \
   r0 ^= r4;   \
   r3 ^= r2;   \
   r2 |= r4;   \
   r1 ^= r3;   \
   r2 ^= r0;   \
   r0 |= r1;   \
   r2 ^= r1;   \
   r4 ^= r0;   \
   r0 |= r3;   \
   r0 ^= r2;   \
   r4 ^= r3;   \
   r4 ^= r0;   \
   r3 = ~r3;   \
   r2 &= r4;   \
   r2 ^= r3;   \
}

#define s_i6(i, r0, r1, r2, r3, r4) { \
   r0 ^= r2;   \
   r4 = r2;    \
   r2 &= r0;   \
   r4 ^= r3;   \
   r2 = ~r2;   \
   r3 ^= r1;   \
   r2 ^= r3;   \
   r4 |= r0;   \
   r0 ^= r2;   \
   r3 ^= r4;   \
   r4 ^= r1;   \
   r1 &= r3;   \
   r1 ^= r0;   \
   r0 ^= r3;   \
   r0 |= r2;   \
   r3 ^= r1;   \
   r4 ^= r0;   \
}

#define s_s7(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 &= r1;   \
   r2 ^= r3;   \
   r3 &= r1;   \
   r4 ^= r2;   \
   r2 ^= r1;   \
   r1 ^= r0;   \
   r0 |= r4;   \
   r0 ^= r2;   \
   r3 ^= r1;   \
   r2 ^= r3;   \
   r3 &= r0;   \
   r3 ^= r4;   \
   r4 ^= r2;   \
   r2 &= r0;   \
   r4 = ~r4;   \
   r2 ^= r4;   \
   r4 &= r0;   \
   r1 ^= r3;   \
   r4 ^= r1;   \
}

#define s_i7(i, r0, r1, r2, r3, r4) { \
   r4 = r2;    \
   r2 ^= r0;   \
   r0 &= r3;   \
   r2 = ~r2;   \
   r4 |= r3;   \
   r3 ^= r1;   \
   r1 |= r0;   \
   r0 ^= r2;   \
   r2 &= r4;   \
   r1 ^= r2;   \
   r2 ^= r0;   \
   r0 |= r2;   \
   r3 &= r4;   \
   r0 ^= r3;   \
   r4 ^= r1;   \
   r3 ^= r4;   \
   r4 |= r0;   \
   r3 ^= r2;   \
   r4 ^= r2;   \
}

/* key xor */
#define s_kx(r, a, b, c, d, e) { \
   a ^= k[4 * r + 0];   \
   b ^= k[4 * r + 1];   \
   c ^= k[4 * r + 2];   \
   d ^= k[4 * r + 3];   \
}

#define s_lk(r, a, b, c, d, e) { \
   a = k[(8-r)*4 + 0];  \
   b = k[(8-r)*4 + 1];  \
   c = k[(8-r)*4 + 2];  \
   d = k[(8-r)*4 + 3];  \
}

#define s_sk(r, a, b, c, d, e) { \
   k[(8-r)*4 + 4] = a;  \
   k[(8-r)*4 + 5] = b;  \
   k[(8-r)*4 + 6] = c;  \
   k[(8-r)*4 + 7] = d;  \
}

#define s_setup_key s_serpent_setup_key
static int s_setup_key(const unsigned char *key, int keylen, int rounds, ulong32 *k)
{
   int i;
   ulong32 t;
   ulong32 k0[8] = { 0 }; /* zero-initialize */
   ulong32 a, b, c, d, e;

   for (i = 0; i < 8 && i < keylen/4; ++i) {
      LOAD32L(k0[i], key + i * 4);
   }
   if (keylen < 32) {
      k0[keylen/4] |= (ulong32)1 << ((keylen%4)*8);
    }

   t = k0[7];
   for (i = 0; i < 8; ++i) {
      k[i] = k0[i] = t = ROLc(k0[i] ^ k0[(i+3)%8] ^ k0[(i+5)%8] ^ t ^ 0x9e3779b9 ^ i, 11);
   }
   for (i = 8; i < 4*(rounds+1); ++i) {
      k[i] = t = ROLc(k[i-8] ^ k[i-5] ^ k[i-3] ^ t ^ 0x9e3779b9 ^ i, 11);
   }
   k -= 20;

   for (i = 0; i < rounds/8; i++) {
      s_afterS2(s_lk);  s_afterS2(s_s3);  s_afterS3(s_sk);
      s_afterS1(s_lk);  s_afterS1(s_s2);  s_afterS2(s_sk);
      s_afterS0(s_lk);  s_afterS0(s_s1);  s_afterS1(s_sk);
      s_beforeS0(s_lk); s_beforeS0(s_s0); s_afterS0(s_sk);
      k += 8*4;
      s_afterS6(s_lk); s_afterS6(s_s7); s_afterS7(s_sk);
      s_afterS5(s_lk); s_afterS5(s_s6); s_afterS6(s_sk);
      s_afterS4(s_lk); s_afterS4(s_s5); s_afterS5(s_sk);
      s_afterS3(s_lk); s_afterS3(s_s4); s_afterS4(s_sk);
   }
   s_afterS2(s_lk); s_afterS2(s_s3); s_afterS3(s_sk);

   return CRYPT_OK;
}

static int s_dec_block(const unsigned char *in, unsigned char *out, const ulong32 *k)
{
   ulong32 a, b, c, d, e;
   unsigned int i;

   LOAD32L(a, in + 0);
   LOAD32L(b, in + 4);
   LOAD32L(c, in + 8);
   LOAD32L(d, in + 12);
   e = 0; LTC_UNUSED_PARAM(e); /* avoid scan-build warning */
   i = 4;
   k += 96;

   s_beforeI7(s_kx);
   goto start;

   do {
      c = b;
      b = d;
      d = e;
      k -= 32;
      s_beforeI7(s_ilt);
start:
                      s_beforeI7(s_i7); s_afterI7(s_kx);
      s_afterI7(s_ilt); s_afterI7(s_i6); s_afterI6(s_kx);
      s_afterI6(s_ilt); s_afterI6(s_i5); s_afterI5(s_kx);
      s_afterI5(s_ilt); s_afterI5(s_i4); s_afterI4(s_kx);
      s_afterI4(s_ilt); s_afterI4(s_i3); s_afterI3(s_kx);
      s_afterI3(s_ilt); s_afterI3(s_i2); s_afterI2(s_kx);
      s_afterI2(s_ilt); s_afterI2(s_i1); s_afterI1(s_kx);
      s_afterI1(s_ilt); s_afterI1(s_i0); s_afterI0(s_kx);
   } while (--i != 0);

   STORE32L(a, out + 0);
   STORE32L(d, out + 4);
   STORE32L(b, out + 8);
   STORE32L(e, out + 12);

   return CRYPT_OK;
}

int serpent_setup(const unsigned char *key, int keylen, int num_rounds, symmetric_key *skey)
{
   int err;

   LTC_ARGCHK(key  != NULL);
   LTC_ARGCHK(skey != NULL);

   if (num_rounds != 0 && num_rounds != 32) return CRYPT_INVALID_ROUNDS;
   if (keylen != 16 && keylen != 24 && keylen != 32) return CRYPT_INVALID_KEYSIZE;

   err = s_setup_key(key, keylen, 32, skey->serpent.k);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 14 + sizeof(int));
#endif
   return err;
}

int serpent_ecb_encrypt(const unsigned char *pt, unsigned char *ct, const symmetric_key *skey)
{
   int err = s_serpent_accel_ecb_encrypt_32_bit(pt, ct, 1, skey);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
#endif
   return err;
}

int serpent_ecb_decrypt(const unsigned char *ct, unsigned char *pt, const symmetric_key *skey)
{
   int err = s_dec_block(ct, pt, skey->serpent.k);
#ifdef LTC_CLEAN_STACK
   burn_stack(sizeof(ulong32) * 5 + sizeof(int));
#endif
   return err;
}

void serpent_done(symmetric_key *skey)
{
   LTC_UNUSED_PARAM(skey);
}

int serpent_keysize(int *keysize)
{
   LTC_ARGCHK(keysize != NULL);

   if (*keysize >= 32) { *keysize = 32; }
   else if (*keysize >= 24) { *keysize = 24; }
   else if (*keysize >= 16) { *keysize = 16; }
   else return CRYPT_INVALID_KEYSIZE;
   return CRYPT_OK;
}

static LTC_INLINE void s_serpent_accel_ctr_increment_counter_be(unsigned char *counter)
{
  int i;
  int idx;

  for (i = 0; i != serpent_block_len; ++i) {
    idx = (serpent_block_len - 1) - i;
    ++counter[idx];
    if (counter[idx] != 0x00) {
      break;
    }
  }
}

static LTC_INLINE void s_serpent_accel_ctr_increment_counter_le(unsigned char *counter)
{
  int i;
  int idx;

  for (i = 0; i != serpent_block_len; ++i) {
    idx = i;
    ++counter[idx];
    if (counter[idx] != 0x00) {
      break;
    }
  }
}

static LTC_INLINE void s_serpent_accel_ctr_increment_counter_generic(unsigned char *counter, int mode)
{
    if (mode == CTR_COUNTER_LITTLE_ENDIAN) {
      s_serpent_accel_ctr_increment_counter_le(counter);
    } else {
      s_serpent_accel_ctr_increment_counter_be(counter);
    }
}

#define s_apply_order_00(fnc) fnc( 0, a, b, c, d, e)
#define s_apply_order_01(fnc) fnc( 1, c, b, d, a, e)
#define s_apply_order_02(fnc) fnc( 2, e, d, a, c, b)
#define s_apply_order_03(fnc) fnc( 3, b, d, e, c, a)
#define s_apply_order_04(fnc) fnc( 4, c, a, d, b, e)
#define s_apply_order_05(fnc) fnc( 5, a, d, b, e, c)
#define s_apply_order_06(fnc) fnc( 6, c, a, d, e, b)
#define s_apply_order_07(fnc) fnc( 7, d, b, a, e, c)
#define s_apply_order_08(fnc) fnc( 8, c, a, e, d, b)
#define s_apply_order_09(fnc) fnc( 9, e, a, d, c, b)
#define s_apply_order_10(fnc) fnc(10, b, d, c, e, a)
#define s_apply_order_11(fnc) fnc(11, a, d, b, e, c)
#define s_apply_order_12(fnc) fnc(12, e, c, d, a, b)
#define s_apply_order_13(fnc) fnc(13, c, d, a, b, e)
#define s_apply_order_14(fnc) fnc(14, e, c, d, b, a)
#define s_apply_order_15(fnc) fnc(15, d, a, c, b, e)
#define s_apply_order_16(fnc) fnc(16, e, c, b, d, a)
#define s_apply_order_17(fnc) fnc(17, b, c, d, e, a)
#define s_apply_order_18(fnc) fnc(18, a, d, e, b, c)
#define s_apply_order_19(fnc) fnc(19, c, d, a, b, e)
#define s_apply_order_20(fnc) fnc(20, b, e, d, c, a)
#define s_apply_order_21(fnc) fnc(21, e, d, c, a, b)
#define s_apply_order_22(fnc) fnc(22, b, e, d, a, c)
#define s_apply_order_23(fnc) fnc(23, d, c, e, a, b)
#define s_apply_order_24(fnc) fnc(24, b, e, a, d, c)
#define s_apply_order_25(fnc) fnc(25, a, e, d, b, c)
#define s_apply_order_26(fnc) fnc(26, c, d, b, a, e)
#define s_apply_order_27(fnc) fnc(27, e, d, c, a, b)
#define s_apply_order_28(fnc) fnc(28, a, b, d, e, c)
#define s_apply_order_29(fnc) fnc(29, b, d, e, c, a)
#define s_apply_order_30(fnc) fnc(30, a, b, d, c, e)
#define s_apply_order_31(fnc) fnc(31, d, e, b, c, a)
#define s_apply_order_32(fnc) fnc(32, a, b, c, d, e)
#define s_apply_key(i, ra, rb, rc, rd, re) do{                                            \
  s_do_xor(ra, s_do_broadcast(k[i * 4 + 0])); s_do_xor(rb, s_do_broadcast(k[i * 4 + 1])); \
  s_do_xor(rc, s_do_broadcast(k[i * 4 + 2])); s_do_xor(rd, s_do_broadcast(k[i * 4 + 3])); \
}while(0)
#define s_apply_ln_tr_key(i, ra, rb, rc, rd, re) do{                                                                                  \
  s_do_rol(ra, 13);                                                                                                                   \
  s_do_rol(rc, 3);                            s_do_xor(rb, ra);                           s_do_shl(re, ra, 3);                        \
  s_do_xor(rd, rc);                           s_do_xor(rb, rc);                                                                       \
  s_do_rol(rb, 1);                            s_do_xor(rd, re);                                                                       \
  s_do_rol(rd, 7);                            s_do_assign(re, rb);                                                                    \
  s_do_xor(ra, rb);                           s_do_shl(re, re, 7);                        s_do_xor(rc, rd);                           \
  s_do_xor(ra, rd);                           s_do_xor(rc, re);                           s_do_xor(rd, s_do_broadcast(k[i * 4 + 3])); \
  s_do_xor(rb, s_do_broadcast(k[i * 4 + 1])); s_do_rol(ra, 5);                            s_do_rol(rc, 22);                           \
  s_do_xor(ra, s_do_broadcast(k[i * 4 + 0])); s_do_xor(rc, s_do_broadcast(k[i * 4 + 2]));                                             \
}while(0)
#define s_enc_0(i, ra, rb, rc, rd, re) do{                 \
  s_do_assign(re, rd);                                     \
  s_do_or (rd, ra);    s_do_xor(ra, re); s_do_xor(re, rc); \
  s_do_not(re, re);    s_do_xor(rd, rb); s_do_and(rb, ra); \
  s_do_xor(rb, re);    s_do_xor(rc, ra); s_do_xor(ra, rd); \
  s_do_or (re, ra);    s_do_xor(ra, rc); s_do_and(rc, rb); \
  s_do_xor(rd, rc);    s_do_not(rb, rb); s_do_xor(rc, re); \
  s_do_xor(rb, rc);                                        \
}while(0)
#define s_enc_1(i, ra, rb, rc, rd, re) do{                 \
  s_do_assign(re, rb);                                     \
  s_do_xor(rb, ra);    s_do_xor(ra, rd); s_do_not(rd, rd); \
  s_do_and(re, rb);    s_do_or (ra, rb); s_do_xor(rd, rc); \
  s_do_xor(ra, rd);    s_do_xor(rb, rd); s_do_xor(rd, re); \
  s_do_or (rb, re);    s_do_xor(re, rc); s_do_and(rc, ra); \
  s_do_xor(rc, rb);    s_do_or (rb, ra); s_do_not(ra, ra); \
  s_do_xor(ra, rc);    s_do_xor(re, rb);                   \
}while(0)
#define s_enc_2(i, ra, rb, rc, rd, re) do{                 \
  s_do_not(rd, rd);                                        \
  s_do_xor(rb, ra); s_do_assign(re, ra); s_do_and(ra, rc); \
  s_do_xor(ra, rd); s_do_or (rd, re);    s_do_xor(rc, rb); \
  s_do_xor(rd, rb); s_do_and(rb, ra);    s_do_xor(ra, rc); \
  s_do_and(rc, rd); s_do_or (rd, rb);    s_do_not(ra, ra); \
  s_do_xor(rd, ra); s_do_xor(re, ra);    s_do_xor(ra, rc); \
  s_do_or (rb, rc);                                        \
}while(0)
#define s_enc_3(i, ra, rb, rc, rd, re) do{                 \
  s_do_assign(re, rb);                                     \
  s_do_xor(rb, rd);    s_do_or (rd, ra); s_do_and(re, ra); \
  s_do_xor(ra, rc);    s_do_xor(rc, rb); s_do_and(rb, rd); \
  s_do_xor(rc, rd);    s_do_or (ra, re); s_do_xor(re, rd); \
  s_do_xor(rb, ra);    s_do_and(ra, rd); s_do_and(rd, re); \
  s_do_xor(rd, rc);    s_do_or (re, rb); s_do_and(rc, rb); \
  s_do_xor(re, rd);    s_do_xor(ra, rd); s_do_xor(rd, rc); \
}while(0)
#define s_enc_4(i, ra, rb, rc, rd, re) do{                 \
  s_do_assign(re, rd);                                     \
  s_do_and(rd, ra);    s_do_xor(ra, re);                   \
  s_do_xor(rd, rc);    s_do_or (rc, re); s_do_xor(ra, rb); \
  s_do_xor(re, rd);    s_do_or (rc, ra);                   \
  s_do_xor(rc, rb);    s_do_and(rb, ra);                   \
  s_do_xor(rb, re);    s_do_and(re, rc); s_do_xor(rc, rd); \
  s_do_xor(re, ra);    s_do_or (rd, rb); s_do_not(rb, rb); \
  s_do_xor(rd, ra);                                        \
}while(0)
#define s_enc_5(i, ra, rb, rc, rd, re) do{                 \
  s_do_assign(re, rb); s_do_or (rb, ra);                   \
  s_do_xor(rc, rb);    s_do_not(rd, rd); s_do_xor(re, ra); \
  s_do_xor(ra, rc);    s_do_and(rb, re); s_do_or (re, rd); \
  s_do_xor(re, ra);    s_do_and(ra, rd); s_do_xor(rb, rd); \
  s_do_xor(rd, rc);    s_do_xor(ra, rb); s_do_and(rc, re); \
  s_do_xor(rb, rc);    s_do_and(rc, ra);                   \
  s_do_xor(rd, rc);                                        \
}while(0)
#define s_enc_6(i, ra, rb, rc, rd, re) do{                 \
  s_do_assign(re, rb);                                     \
  s_do_xor(rd, ra);    s_do_xor(rb, rc); s_do_xor(rc, ra); \
  s_do_and(ra, rd);    s_do_or (rb, rd); s_do_not(re, re); \
  s_do_xor(ra, rb);    s_do_xor(rb, rc);                   \
  s_do_xor(rd, re);    s_do_xor(re, ra); s_do_and(rc, ra); \
  s_do_xor(re, rb);    s_do_xor(rc, rd); s_do_and(rd, rb); \
  s_do_xor(rd, ra);    s_do_xor(rb, rc);                   \
}while(0)
#define s_enc_7(i, ra, rb, rc, rd, re) do{                 \
  s_do_not(rb, rb);                                        \
  s_do_assign(re, rb); s_do_not(ra, ra); s_do_and(rb, rc); \
  s_do_xor(rb, rd);    s_do_or (rd, re); s_do_xor(re, rc); \
  s_do_xor(rc, rd);    s_do_xor(rd, ra); s_do_or (ra, rb); \
  s_do_and(rc, ra);    s_do_xor(ra, re); s_do_xor(re, rd); \
  s_do_and(rd, ra);    s_do_xor(re, rb);                   \
  s_do_xor(rc, re);    s_do_xor(rd, rb); s_do_or (re, ra); \
  s_do_xor(re, rb);                                        \
}while(0)

static LTC_INLINE int s_serpent_accel_ecb_encrypt_32_bit(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
  #define blocks_at_a_time (32 / 32)
  #define s_do_broadcast(x) ((ulong32)(x))
  #define s_do_xor(a, b) a ^= b
  #define s_do_and(a, b) a &= b
  #define s_do_or(a, b) a |= b
  #define s_do_not(a, b) a =~ b
  #define s_do_assign(a, b) a = b
  #define s_do_rol(x, i) x = ROLc(x, i)
  #define s_do_shl(a, b, c) a = b << c
  #define s_do_load_one(ptr) ((ulong32)(                   \
    ((ulong32)(((ulong32)((ptr)[0])) << (0 * CHAR_BIT))) | \
    ((ulong32)(((ulong32)((ptr)[1])) << (1 * CHAR_BIT))) | \
    ((ulong32)(((ulong32)((ptr)[2])) << (2 * CHAR_BIT))) | \
    ((ulong32)(((ulong32)((ptr)[3])) << (3 * CHAR_BIT))) | \
    0))
  #define s_do_store_one(x, ptr) do{                                                    \
    (ptr)[0] = ((unsigned char)(((ulong32)(((ulong32)(x)) >> (0 * CHAR_BIT))) & 0xff)); \
    (ptr)[1] = ((unsigned char)(((ulong32)(((ulong32)(x)) >> (1 * CHAR_BIT))) & 0xff)); \
    (ptr)[2] = ((unsigned char)(((ulong32)(((ulong32)(x)) >> (2 * CHAR_BIT))) & 0xff)); \
    (ptr)[3] = ((unsigned char)(((ulong32)(((ulong32)(x)) >> (3 * CHAR_BIT))) & 0xff)); \
  }while(0)
  #define s_do_load_four(ra, rb, rc, rd, bytes) do{ \
    const unsigned char *ptr;                       \
    ptr = ((const unsigned char*)(bytes));          \
    ra = s_do_load_one(&ptr[0 * sizeof(ulong32)]);  \
    rb = s_do_load_one(&ptr[1 * sizeof(ulong32)]);  \
    rc = s_do_load_one(&ptr[2 * sizeof(ulong32)]);  \
    rd = s_do_load_one(&ptr[3 * sizeof(ulong32)]);  \
  }while(0)
  #define s_do_store_four(ra, rb, rc, rd, bytes) do{ \
    unsigned char *ptr;                              \
    ptr = ((unsigned char*)(bytes));                 \
    s_do_store_one(ra, &ptr[0 * sizeof(ulong32)]);   \
    s_do_store_one(rb, &ptr[1 * sizeof(ulong32)]);   \
    s_do_store_one(rc, &ptr[2 * sizeof(ulong32)]);   \
    s_do_store_one(rd, &ptr[3 * sizeof(ulong32)]);   \
  }while(0)

  const unsigned char *in;
  unsigned char *out;
  const ulong32* k;
  unsigned long iblock;
  ulong32 a, b, c, d, e;

  LTC_ARGCHK(pt);
  LTC_ARGCHK(ct);
  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  in = pt;
  out = ct;
  k = &skey->serpent.k[0];
  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    s_do_load_four(a, b, c, d, in);
    s_apply_order_00(s_apply_key);
    s_apply_order_00(s_enc_0); s_apply_order_01(s_apply_ln_tr_key);
    s_apply_order_01(s_enc_1); s_apply_order_02(s_apply_ln_tr_key);
    s_apply_order_02(s_enc_2); s_apply_order_03(s_apply_ln_tr_key);
    s_apply_order_03(s_enc_3); s_apply_order_04(s_apply_ln_tr_key);
    s_apply_order_04(s_enc_4); s_apply_order_05(s_apply_ln_tr_key);
    s_apply_order_05(s_enc_5); s_apply_order_06(s_apply_ln_tr_key);
    s_apply_order_06(s_enc_6); s_apply_order_07(s_apply_ln_tr_key);
    s_apply_order_07(s_enc_7); s_apply_order_08(s_apply_ln_tr_key);
    s_apply_order_08(s_enc_0); s_apply_order_09(s_apply_ln_tr_key);
    s_apply_order_09(s_enc_1); s_apply_order_10(s_apply_ln_tr_key);
    s_apply_order_10(s_enc_2); s_apply_order_11(s_apply_ln_tr_key);
    s_apply_order_11(s_enc_3); s_apply_order_12(s_apply_ln_tr_key);
    s_apply_order_12(s_enc_4); s_apply_order_13(s_apply_ln_tr_key);
    s_apply_order_13(s_enc_5); s_apply_order_14(s_apply_ln_tr_key);
    s_apply_order_14(s_enc_6); s_apply_order_15(s_apply_ln_tr_key);
    s_apply_order_15(s_enc_7); s_apply_order_16(s_apply_ln_tr_key);
    s_apply_order_16(s_enc_0); s_apply_order_17(s_apply_ln_tr_key);
    s_apply_order_17(s_enc_1); s_apply_order_18(s_apply_ln_tr_key);
    s_apply_order_18(s_enc_2); s_apply_order_19(s_apply_ln_tr_key);
    s_apply_order_19(s_enc_3); s_apply_order_20(s_apply_ln_tr_key);
    s_apply_order_20(s_enc_4); s_apply_order_21(s_apply_ln_tr_key);
    s_apply_order_21(s_enc_5); s_apply_order_22(s_apply_ln_tr_key);
    s_apply_order_22(s_enc_6); s_apply_order_23(s_apply_ln_tr_key);
    s_apply_order_23(s_enc_7); s_apply_order_24(s_apply_ln_tr_key);
    s_apply_order_24(s_enc_0); s_apply_order_25(s_apply_ln_tr_key);
    s_apply_order_25(s_enc_1); s_apply_order_26(s_apply_ln_tr_key);
    s_apply_order_26(s_enc_2); s_apply_order_27(s_apply_ln_tr_key);
    s_apply_order_27(s_enc_3); s_apply_order_28(s_apply_ln_tr_key);
    s_apply_order_28(s_enc_4); s_apply_order_29(s_apply_ln_tr_key);
    s_apply_order_29(s_enc_5); s_apply_order_30(s_apply_ln_tr_key);
    s_apply_order_30(s_enc_6); s_apply_order_31(s_apply_ln_tr_key);
    s_apply_order_31(s_enc_7); s_apply_order_32(s_apply_key);
    s_do_store_four(a, b, c, d, out);
    in += blocks_at_a_time * serpent_block_len;
    out += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
  #undef s_do_broadcast
  #undef s_do_xor
  #undef s_do_and
  #undef s_do_or
  #undef s_do_not
  #undef s_do_assign
  #undef s_do_rol
  #undef s_do_shl
  #undef s_do_load_one
  #undef s_do_store_one
  #undef s_do_load_four
  #undef s_do_store_four
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_32_bit(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
  return CRYPT_OK;
}

static LTC_INLINE int s_serpent_accel_ctr_encrypt_32_bit(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
  #define blocks_at_a_time (32 / 32)

  typedef union {
    unsigned char chars[blocks_at_a_time * serpent_block_len];
    ulong32 align;
  } pad_t;

  unsigned long iblock;
  int i;
  pad_t pad;
  int err;
  ulong32 big_int_pad;
  ulong32 big_int_pt;
  ulong32 big_int_ct;

  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    for (i = 0; i != blocks_at_a_time; ++i) {
      s_serpent_accel_ctr_increment_counter_generic(IV, mode);
      XMEMCPY(&pad.chars[i * serpent_block_len], IV, serpent_block_len);
    }
    if ((err = s_serpent_accel_ecb_encrypt_32_bit(&pad.chars[0], &pad.chars[0], blocks_at_a_time, skey)) != CRYPT_OK) {
      return err;
    }
    for (i = 0; i != LTC_ARRAY_SIZE(pad.chars) / sizeof(pad.align); ++i) {
      LOAD32L(big_int_pad, &pad.chars[0] + i * sizeof(ulong32));
      LOAD32L(big_int_pt, pt + i * sizeof(ulong32));
      big_int_ct = big_int_pad ^ big_int_pt;
      STORE32L(big_int_ct, ct + i * sizeof(ulong32));
    }
    pt += blocks_at_a_time * serpent_block_len;
    ct += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
}

#if defined LTC_SERPENT_ACCEL_64_BIT_PLAIN

static LTC_INLINE int s_serpent_accel_ecb_encrypt_64_bit_plain(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
  #define blocks_at_a_time (64 / 32)
  #define s_do_broadcast(x) ((ulong64)(((ulong64)(((ulong64)(((ulong32)(x)))) << 32)) | ((ulong64)(((ulong32)(x))))))
  #define s_do_xor(a, b) a ^= b
  #define s_do_and(a, b) a &= b
  #define s_do_or(a, b) a |= b
  #define s_do_not(a, b) a =~ b
  #define s_do_assign(a, b) a = b
  #define s_do_join(hi, lo) ((ulong64)(((ulong64)(((ulong64)(((ulong32)(hi)))) << 32)) | ((ulong64)(((ulong32)(lo))))))
  #define s_do_extract_any(x, i) ((ulong32)(((ulong64)(x)) >> ((int)(32 * (i)))))
  #define s_do_extract_lo(x) s_do_extract_any(x, 0)
  #define s_do_extract_hi(x) s_do_extract_any(x, 1)
  #define s_do_rol(x, i) x = s_do_join(ROLc(s_do_extract_hi(x), i), ROLc(s_do_extract_lo(x), i))
  #define s_do_shl(a, b, c) a = s_do_join(s_do_extract_hi(b) << c, s_do_extract_lo(b) << c)
  #define s_do_load_one(ptr) ((ulong64)(                 \
    ((ulong64)(((ulong64)((ptr)[0])) << (0 * CHAR_BIT))) | \
    ((ulong64)(((ulong64)((ptr)[1])) << (1 * CHAR_BIT))) | \
    ((ulong64)(((ulong64)((ptr)[2])) << (2 * CHAR_BIT))) | \
    ((ulong64)(((ulong64)((ptr)[3])) << (3 * CHAR_BIT))) | \
    ((ulong64)(((ulong64)((ptr)[4])) << (4 * CHAR_BIT))) | \
    ((ulong64)(((ulong64)((ptr)[5])) << (5 * CHAR_BIT))) | \
    ((ulong64)(((ulong64)((ptr)[6])) << (6 * CHAR_BIT))) | \
    ((ulong64)(((ulong64)((ptr)[7])) << (7 * CHAR_BIT))) | \
    0))
  #define s_do_store_one(x, ptr) do{                                                  \
    (ptr)[0] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (0 * CHAR_BIT))) & 0xff)); \
    (ptr)[1] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (1 * CHAR_BIT))) & 0xff)); \
    (ptr)[2] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (2 * CHAR_BIT))) & 0xff)); \
    (ptr)[3] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (3 * CHAR_BIT))) & 0xff)); \
    (ptr)[4] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (4 * CHAR_BIT))) & 0xff)); \
    (ptr)[5] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (5 * CHAR_BIT))) & 0xff)); \
    (ptr)[6] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (6 * CHAR_BIT))) & 0xff)); \
    (ptr)[7] = ((unsigned char)(((ulong64)(((ulong64)(x)) >> (7 * CHAR_BIT))) & 0xff)); \
  }while(0)
  #define s_do_load_four(ra, rb, rc, rd, bytes) do{ \
    const unsigned char *ptr;                       \
    ulong64 ia, ib, ic, id;                         \
    ulong64 sa, sb, sc, sd;                         \
    ptr = ((const unsigned char*)(bytes));          \
    ia = s_do_load_one(&ptr[0 * sizeof(ulong64)]);  \
    ib = s_do_load_one(&ptr[1 * sizeof(ulong64)]);  \
    ic = s_do_load_one(&ptr[2 * sizeof(ulong64)]);  \
    id = s_do_load_one(&ptr[3 * sizeof(ulong64)]);  \
    sa = ((ia << 32) >> 32) ^ (ic << 32);           \
    sb = (ia >> 32) ^ ((ic >> 32) << 32);           \
    sc = ((ib << 32) >> 32) ^ (id << 32);           \
    sd = (ib >> 32) ^ ((id >> 32) << 32);           \
    ra = sa;                                        \
    rb = sb;                                        \
    rc = sc;                                        \
    rd = sd;                                        \
  }while(0)
  #define s_do_store_four(ra, rb, rc, rd, bytes) do{ \
    ulong64 ia, ib, ic, id;                          \
    ulong64 sa, sb, sc, sd;                          \
    unsigned char* ptr;                              \
    ia = ra;                                         \
    ib = rb;                                         \
    ic = rc;                                         \
    id = rd;                                         \
    ptr = ((unsigned char*)(bytes));                 \
    sa = ((ia << 32) >> 32) ^ (ib << 32);            \
    sb = ((ic << 32) >> 32) ^ (id << 32);            \
    sc = (ia >> 32) ^ ((ib >> 32) << 32);            \
    sd = (ic >> 32) ^ ((id >> 32) << 32);            \
    s_do_store_one(sa, &ptr[0 * sizeof(ulong64)]);   \
    s_do_store_one(sb, &ptr[1 * sizeof(ulong64)]);   \
    s_do_store_one(sc, &ptr[2 * sizeof(ulong64)]);   \
    s_do_store_one(sd, &ptr[3 * sizeof(ulong64)]);   \
  }while(0)

  const unsigned char *in;
  unsigned char *out;
  const ulong32* k;
  unsigned long iblock;
  ulong64 a, b, c, d, e;

  LTC_ARGCHK(pt);
  LTC_ARGCHK(ct);
  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  in = pt;
  out = ct;
  k = &skey->serpent.k[0];
  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    s_do_load_four(a, b, c, d, in);
    s_apply_order_00(s_apply_key);
    s_apply_order_00(s_enc_0); s_apply_order_01(s_apply_ln_tr_key);
    s_apply_order_01(s_enc_1); s_apply_order_02(s_apply_ln_tr_key);
    s_apply_order_02(s_enc_2); s_apply_order_03(s_apply_ln_tr_key);
    s_apply_order_03(s_enc_3); s_apply_order_04(s_apply_ln_tr_key);
    s_apply_order_04(s_enc_4); s_apply_order_05(s_apply_ln_tr_key);
    s_apply_order_05(s_enc_5); s_apply_order_06(s_apply_ln_tr_key);
    s_apply_order_06(s_enc_6); s_apply_order_07(s_apply_ln_tr_key);
    s_apply_order_07(s_enc_7); s_apply_order_08(s_apply_ln_tr_key);
    s_apply_order_08(s_enc_0); s_apply_order_09(s_apply_ln_tr_key);
    s_apply_order_09(s_enc_1); s_apply_order_10(s_apply_ln_tr_key);
    s_apply_order_10(s_enc_2); s_apply_order_11(s_apply_ln_tr_key);
    s_apply_order_11(s_enc_3); s_apply_order_12(s_apply_ln_tr_key);
    s_apply_order_12(s_enc_4); s_apply_order_13(s_apply_ln_tr_key);
    s_apply_order_13(s_enc_5); s_apply_order_14(s_apply_ln_tr_key);
    s_apply_order_14(s_enc_6); s_apply_order_15(s_apply_ln_tr_key);
    s_apply_order_15(s_enc_7); s_apply_order_16(s_apply_ln_tr_key);
    s_apply_order_16(s_enc_0); s_apply_order_17(s_apply_ln_tr_key);
    s_apply_order_17(s_enc_1); s_apply_order_18(s_apply_ln_tr_key);
    s_apply_order_18(s_enc_2); s_apply_order_19(s_apply_ln_tr_key);
    s_apply_order_19(s_enc_3); s_apply_order_20(s_apply_ln_tr_key);
    s_apply_order_20(s_enc_4); s_apply_order_21(s_apply_ln_tr_key);
    s_apply_order_21(s_enc_5); s_apply_order_22(s_apply_ln_tr_key);
    s_apply_order_22(s_enc_6); s_apply_order_23(s_apply_ln_tr_key);
    s_apply_order_23(s_enc_7); s_apply_order_24(s_apply_ln_tr_key);
    s_apply_order_24(s_enc_0); s_apply_order_25(s_apply_ln_tr_key);
    s_apply_order_25(s_enc_1); s_apply_order_26(s_apply_ln_tr_key);
    s_apply_order_26(s_enc_2); s_apply_order_27(s_apply_ln_tr_key);
    s_apply_order_27(s_enc_3); s_apply_order_28(s_apply_ln_tr_key);
    s_apply_order_28(s_enc_4); s_apply_order_29(s_apply_ln_tr_key);
    s_apply_order_29(s_enc_5); s_apply_order_30(s_apply_ln_tr_key);
    s_apply_order_30(s_enc_6); s_apply_order_31(s_apply_ln_tr_key);
    s_apply_order_31(s_enc_7); s_apply_order_32(s_apply_key);
    s_do_store_four(a, b, c, d, out);
    in += blocks_at_a_time * serpent_block_len;
    out += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
  #undef s_do_broadcast
  #undef s_do_xor
  #undef s_do_and
  #undef s_do_or
  #undef s_do_not
  #undef s_do_assign
  #undef s_do_join
  #undef s_do_extract_any
  #undef s_do_extract_lo
  #undef s_do_extract_hi
  #undef s_do_rol
  #undef s_do_shl
  #undef s_do_shl
  #undef s_do_load_one
  #undef s_do_store_one
  #undef s_do_load_four
  #undef s_do_store_four
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_64_bit_plain(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
  return CRYPT_OK;
}

static LTC_INLINE int s_serpent_accel_ctr_encrypt_64_bit_plain(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
  #define blocks_at_a_time (64 / 32)

  typedef union {
    unsigned char chars[blocks_at_a_time * serpent_block_len];
    ulong64 align;
  } pad_t;

  unsigned long iblock;
  int i;
  pad_t pad;
  int err;
  ulong64 big_int_pad;
  ulong64 big_int_pt;
  ulong64 big_int_ct;

  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    for (i = 0; i != blocks_at_a_time; ++i) {
      s_serpent_accel_ctr_increment_counter_generic(IV, mode);
      XMEMCPY(&pad.chars[i * serpent_block_len], IV, serpent_block_len);
    }
    if ((err = s_serpent_accel_ecb_encrypt_64_bit_plain(&pad.chars[0], &pad.chars[0], blocks_at_a_time, skey)) != CRYPT_OK) {
      return err;
    }
    for (i = 0; i != LTC_ARRAY_SIZE(pad.chars) / sizeof(pad.align); ++i) {
      LOAD64L(big_int_pad, &pad.chars[0] + i * sizeof(ulong64));
      LOAD64L(big_int_pt, pt + i * sizeof(ulong64));
      big_int_ct = big_int_pad ^ big_int_pt;
      STORE64L(big_int_ct, ct + i * sizeof(ulong64));
    }
    pt += blocks_at_a_time * serpent_block_len;
    ct += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
}

#endif /* LTC_SERPENT_ACCEL_64_BIT_PLAIN */

#if defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX

#pragma warning(push)
#pragma warning(disable:4799) /* warning C4799: function 'xxx' has no EMMS instruction */

#include <mmintrin.h> /* MMX __m64 _mm_and_si64 _mm_andnot_si64 _mm_cvtsi64_si32 _mm_or_si64 _mm_set1_pi32 _mm_set1_pi8 _mm_set_pi32 _mm_slli_pi32 _mm_srli_pi32 _mm_srli_si64 _mm_unpackhi_pi32 _mm_unpacklo_pi32 _mm_xor_si64 */

#if defined _MSC_VER
#pragma intrinsic(_mm_and_si64)
#pragma intrinsic(_mm_andnot_si64)
#pragma intrinsic(_mm_cvtsi64_si32)
#pragma intrinsic(_mm_or_si64)
#pragma intrinsic(_mm_set1_pi32)
#pragma intrinsic(_mm_set1_pi8)
#pragma intrinsic(_mm_set_pi32)
#pragma intrinsic(_mm_slli_pi32)
#pragma intrinsic(_mm_srli_pi32)
#pragma intrinsic(_mm_srli_si64)
#pragma intrinsic(_mm_unpackhi_pi32)
#pragma intrinsic(_mm_unpacklo_pi32)
#pragma intrinsic(_mm_xor_si64)
#endif

#if !defined (LTC_S_X86_CPUID)
#define LTC_S_X86_CPUID
#if defined _MSC_VER
#include <intrin.h>
#pragma intrinsic(__cpuid)
#endif
static LTC_INLINE void s_x86_cpuid(int* regs, int leaf)
{
#if defined _MSC_VER
  __cpuid(regs, leaf);
#else
  int a, b, c, d;

  a = leaf;
  b = c = d = 0;
  asm volatile ("cpuid"
    :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
    :"a"(a), "c"(c)
  );
  regs[0] = a;
  regs[1] = b;
  regs[2] = c;
  regs[3] = d;
#endif
}
#endif /* LTC_S_X86_CPUID */

static LTC_INLINE int s_serpent_accel_64_bit_mmx_is_supported(void)
{
  static int initialized = 0;
  static int supported = 0;

  if(!initialized) {
    int regs[4];
    int mmx;

    s_x86_cpuid(regs, 1);
    mmx = ((((unsigned int)(regs[3])) >> 23) & 1u) != 0; /* MMX, leaf 1, edx, bit 23 */
    supported = mmx;
    initialized = 1;
  }
  return supported;
}

static LTC_INLINE int s_serpent_accel_ecb_encrypt_64_bit_mmx(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
  #define blocks_at_a_time (64 / 32)
  #define s_do_broadcast(x) _mm_set1_pi32(*((const int *)(&(x))))
  #define s_do_xor(a, b) a = _mm_xor_si64(a, b)
  #define s_do_and(a, b) a = _mm_and_si64(a, b)
  #define s_do_or(a, b) a = _mm_or_si64(a, b)
  #define s_do_not(a, b) a = _mm_andnot_si64(b, _mm_set1_pi8(((char)(0xff))))
  #define s_do_assign(a, b) a = b
  #define s_do_rol(x, i) x = _mm_xor_si64(_mm_slli_pi32(x, i), _mm_srli_pi32(x, 32 - i))
  #define s_do_shl(a, b, c) a = _mm_slli_pi32(b, c)
  #define s_do_load_one(ptr) _mm_set_pi32(((const int *)(ptr))[1], ((const int*)(ptr))[0])
  #define s_do_store_one(x, ptr) do{ ((int*)(ptr))[0] = _mm_cvtsi64_si32(x); ((int*)(ptr))[1] = _mm_cvtsi64_si32(_mm_srli_si64(x, 32)); }while(0)
  #define s_do_load_four(ra, rb, rc, rd, bytes) do{ \
    const unsigned char* ptr;                       \
    __m64 ia, ib, ic, id;                           \
    __m64 sa, sb, sc, sd;                           \
    ptr = ((const unsigned char*)(bytes));          \
    ia = s_do_load_one(&ptr[0 * sizeof(__m64)]);    \
    ib = s_do_load_one(&ptr[1 * sizeof(__m64)]);    \
    ic = s_do_load_one(&ptr[2 * sizeof(__m64)]);    \
    id = s_do_load_one(&ptr[3 * sizeof(__m64)]);    \
    sa = _mm_unpacklo_pi32(ia, ic);                 \
    sb = _mm_unpackhi_pi32(ia, ic);                 \
    sc = _mm_unpacklo_pi32(ib, id);                 \
    sd = _mm_unpackhi_pi32(ib, id);                 \
    ra = sa;                                        \
    rb = sb;                                        \
    rc = sc;                                        \
    rd = sd;                                        \
  }while(0)
  #define s_do_store_four(ra, rb, rc, rd, bytes) do{ \
    __m64 ia, ib, ic, id;                            \
    __m64 sa, sb, sc, sd;                            \
    unsigned char* ptr;                              \
    ia = ra;                                         \
    ib = rb;                                         \
    ic = rc;                                         \
    id = rd;                                         \
    ptr = ((unsigned char*)(bytes));                 \
    sa = _mm_unpacklo_pi32(ia, ib);                  \
    sb = _mm_unpacklo_pi32(ic, id);                  \
    sc = _mm_unpackhi_pi32(ia, ib);                  \
    sd = _mm_unpackhi_pi32(ic, id);                  \
    s_do_store_one(sa, &ptr[0 * sizeof(__m64)]);     \
    s_do_store_one(sb, &ptr[1 * sizeof(__m64)]);     \
    s_do_store_one(sc, &ptr[2 * sizeof(__m64)]);     \
    s_do_store_one(sd, &ptr[3 * sizeof(__m64)]);     \
  }while(0)

  const unsigned char *in;
  unsigned char *out;
  const ulong32* k;
  unsigned long iblock;
  __m64 a, b, c, d, e;

  LTC_ARGCHK(pt);
  LTC_ARGCHK(ct);
  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  in = pt;
  out = ct;
  k = &skey->serpent.k[0];
  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    s_do_load_four(a, b, c, d, in);
    s_apply_order_00(s_apply_key);
    s_apply_order_00(s_enc_0); s_apply_order_01(s_apply_ln_tr_key);
    s_apply_order_01(s_enc_1); s_apply_order_02(s_apply_ln_tr_key);
    s_apply_order_02(s_enc_2); s_apply_order_03(s_apply_ln_tr_key);
    s_apply_order_03(s_enc_3); s_apply_order_04(s_apply_ln_tr_key);
    s_apply_order_04(s_enc_4); s_apply_order_05(s_apply_ln_tr_key);
    s_apply_order_05(s_enc_5); s_apply_order_06(s_apply_ln_tr_key);
    s_apply_order_06(s_enc_6); s_apply_order_07(s_apply_ln_tr_key);
    s_apply_order_07(s_enc_7); s_apply_order_08(s_apply_ln_tr_key);
    s_apply_order_08(s_enc_0); s_apply_order_09(s_apply_ln_tr_key);
    s_apply_order_09(s_enc_1); s_apply_order_10(s_apply_ln_tr_key);
    s_apply_order_10(s_enc_2); s_apply_order_11(s_apply_ln_tr_key);
    s_apply_order_11(s_enc_3); s_apply_order_12(s_apply_ln_tr_key);
    s_apply_order_12(s_enc_4); s_apply_order_13(s_apply_ln_tr_key);
    s_apply_order_13(s_enc_5); s_apply_order_14(s_apply_ln_tr_key);
    s_apply_order_14(s_enc_6); s_apply_order_15(s_apply_ln_tr_key);
    s_apply_order_15(s_enc_7); s_apply_order_16(s_apply_ln_tr_key);
    s_apply_order_16(s_enc_0); s_apply_order_17(s_apply_ln_tr_key);
    s_apply_order_17(s_enc_1); s_apply_order_18(s_apply_ln_tr_key);
    s_apply_order_18(s_enc_2); s_apply_order_19(s_apply_ln_tr_key);
    s_apply_order_19(s_enc_3); s_apply_order_20(s_apply_ln_tr_key);
    s_apply_order_20(s_enc_4); s_apply_order_21(s_apply_ln_tr_key);
    s_apply_order_21(s_enc_5); s_apply_order_22(s_apply_ln_tr_key);
    s_apply_order_22(s_enc_6); s_apply_order_23(s_apply_ln_tr_key);
    s_apply_order_23(s_enc_7); s_apply_order_24(s_apply_ln_tr_key);
    s_apply_order_24(s_enc_0); s_apply_order_25(s_apply_ln_tr_key);
    s_apply_order_25(s_enc_1); s_apply_order_26(s_apply_ln_tr_key);
    s_apply_order_26(s_enc_2); s_apply_order_27(s_apply_ln_tr_key);
    s_apply_order_27(s_enc_3); s_apply_order_28(s_apply_ln_tr_key);
    s_apply_order_28(s_enc_4); s_apply_order_29(s_apply_ln_tr_key);
    s_apply_order_29(s_enc_5); s_apply_order_30(s_apply_ln_tr_key);
    s_apply_order_30(s_enc_6); s_apply_order_31(s_apply_ln_tr_key);
    s_apply_order_31(s_enc_7); s_apply_order_32(s_apply_key);
    s_do_store_four(a, b, c, d, out);
    in += blocks_at_a_time * serpent_block_len;
    out += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
  #undef s_do_broadcast
  #undef s_do_xor
  #undef s_do_and
  #undef s_do_or
  #undef s_do_not
  #undef s_do_assign
  #undef s_do_rol
  #undef s_do_shl
  #undef s_do_load_one
  #undef s_do_store_one
  #undef s_do_load_four
  #undef s_do_store_four
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_64_bit_mmx(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
  return CRYPT_OK;
}

static LTC_INLINE int s_serpent_accel_ctr_encrypt_64_bit_mmx(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
  #define blocks_at_a_time (64 / 32)

  typedef union {
    unsigned char chars[blocks_at_a_time * serpent_block_len];
    __m64 align;
  } pad_t;

  typedef union {
    ulong32 u32s[2];
    __m64 align;
  } big_int_t;

  unsigned long iblock;
  int i;
  pad_t pad;
  int err;
  __m64 big_int_pad;
  big_int_t big_int;
  __m64 big_int_pt;
  __m64 big_int_ct;

  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    for (i = 0; i != blocks_at_a_time; ++i) {
      s_serpent_accel_ctr_increment_counter_generic(IV, mode);
      XMEMCPY(&pad.chars[i * serpent_block_len], IV, serpent_block_len);
    }
    if ((err = s_serpent_accel_ecb_encrypt_64_bit_mmx(&pad.chars[0], &pad.chars[0], blocks_at_a_time, skey)) != CRYPT_OK) {
      return err;
    }
    for (i = 0; i != LTC_ARRAY_SIZE(pad.chars) / sizeof(pad.align); ++i) {
      big_int_pad = _mm_set_pi32(
        *((const int *)(&pad.chars[0] + i * sizeof(__m64) + 1 * sizeof(int))),
        *((const int *)(&pad.chars[0] + i * sizeof(__m64) + 0 * sizeof(int))));
      LOAD32L(big_int.u32s[0], pt + i * sizeof(__m64) + 0 * sizeof(ulong32));
      LOAD32L(big_int.u32s[1], pt + i * sizeof(__m64) + 1 * sizeof(ulong32));
      big_int_pt = _mm_set_pi32(((const int *)(&big_int.u32s[0]))[1], ((const int*)(&big_int.u32s[0]))[0]);
      big_int_ct = _mm_xor_si64(big_int_pad, big_int_pt);
      big_int.u32s[0] = _mm_cvtsi64_si32(big_int_ct);
      big_int.u32s[1] = _mm_cvtsi64_si32(_mm_srli_si64(big_int_ct, 32));
      STORE32L(big_int.u32s[0], ct + i * sizeof(__m64) + 0 * sizeof(ulong32));
      STORE32L(big_int.u32s[1], ct + i * sizeof(__m64) + 1 * sizeof(ulong32));
    }
    pt += blocks_at_a_time * serpent_block_len;
    ct += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
}

#pragma warning(pop)

#endif /* LTC_SERPENT_ACCEL_64_BIT_X86_MMX */

#if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2

#include <emmintrin.h> /* SSE2 __m128i _mm_and_si128 _mm_cmpeq_epi32 _mm_loadu_si128 _mm_or_si128 _mm_set1_epi32 _mm_slli_epi32 _mm_srli_epi32 _mm_storeu_si128 _mm_unpackhi_epi32 _mm_unpackhi_epi64 _mm_unpacklo_epi32 _mm_unpacklo_epi64 _mm_xor_si128 */

#if defined _MSC_VER
#pragma intrinsic(_mm_and_si128)
#pragma intrinsic(_mm_cmpeq_epi32)
#pragma intrinsic(_mm_loadu_si128)
#pragma intrinsic(_mm_or_si128)
#pragma intrinsic(_mm_set1_epi32)
#pragma intrinsic(_mm_slli_epi32)
#pragma intrinsic(_mm_srli_epi32)
#pragma intrinsic(_mm_storeu_si128)
#pragma intrinsic(_mm_unpackhi_epi32)
#pragma intrinsic(_mm_unpackhi_epi64)
#pragma intrinsic(_mm_unpacklo_epi32)
#pragma intrinsic(_mm_unpacklo_epi64)
#pragma intrinsic(_mm_xor_si128)
#endif

#if !defined (LTC_S_X86_CPUID)
#define LTC_S_X86_CPUID
#if defined _MSC_VER
#include <intrin.h>
#pragma intrinsic(__cpuid)
#endif
static LTC_INLINE void s_x86_cpuid(int* regs, int leaf)
{
#if defined _MSC_VER
  __cpuid(regs, leaf);
#else
  int a, b, c, d;

  a = leaf;
  b = c = d = 0;
  asm volatile ("cpuid"
    :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
    :"a"(a), "c"(c)
  );
  regs[0] = a;
  regs[1] = b;
  regs[2] = c;
  regs[3] = d;
#endif
}
#endif /* LTC_S_X86_CPUID */

static LTC_INLINE int s_serpent_accel_128_bit_sse2_is_supported(void)
{
  static int initialized = 0;
  static int supported = 0;

  if(!initialized) {
    int regs[4];
    int sse2;

    s_x86_cpuid(regs, 1);
    sse2 = ((((unsigned int)(regs[3])) >> 26) & 1u) != 0; /* SSE2, leaf 1, edx, bit 26 */
    supported = sse2;
    initialized = 1;
  }
  return supported;
}

static LTC_INLINE int s_serpent_accel_ecb_encrypt_128_bit_sse2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
  #define blocks_at_a_time (128 / 32)
  #define s_do_broadcast(x) _mm_set1_epi32(*((const int *)(&(x))))
  #define s_do_xor(a, b) a = _mm_xor_si128(a, b)
  #define s_do_and(a, b) a = _mm_and_si128(a, b)
  #define s_do_or(a, b) a = _mm_or_si128(a, b)
  #define s_do_not(a, b) a = _mm_xor_si128(b, _mm_cmpeq_epi32(b, b))
  #define s_do_assign(a, b) a = b
  #define s_do_rol(x, i) x = _mm_xor_si128(_mm_slli_epi32(x, i), _mm_srli_epi32(x, 32 - i))
  #define s_do_shl(a, b, c) a = _mm_slli_epi32(b, c)
  #define s_do_load_one(ptr) _mm_loadu_si128(((const __m128i*)(ptr)))
  #define s_do_store_one(x, ptr) _mm_storeu_si128(((__m128i*)(ptr)), x)
  #define s_do_load_four(ra, rb, rc, rd, bytes) {  \
    const unsigned char* ptr;                      \
    __m128i ia, ib, ic, id;                        \
    __m128i ta, tb, tc, td;                        \
    __m128i sa, sb, sc, sd;                        \
    ptr = ((const unsigned char*)(bytes));         \
    ia = s_do_load_one(&ptr[0 * sizeof(__m128i)]); \
    ib = s_do_load_one(&ptr[1 * sizeof(__m128i)]); \
    ic = s_do_load_one(&ptr[2 * sizeof(__m128i)]); \
    id = s_do_load_one(&ptr[3 * sizeof(__m128i)]); \
    ta = _mm_unpacklo_epi32(ia, ib);               \
    tb = _mm_unpacklo_epi32(ic, id);               \
    tc = _mm_unpackhi_epi32(ia, ib);               \
    td = _mm_unpackhi_epi32(ic, id);               \
    sa = _mm_unpacklo_epi64(ta, tb);               \
    sb = _mm_unpackhi_epi64(ta, tb);               \
    sc = _mm_unpacklo_epi64(tc, td);               \
    sd = _mm_unpackhi_epi64(tc, td);               \
    ra = sa;                                       \
    rb = sb;                                       \
    rc = sc;                                       \
    rd = sd;                                       \
  }
  #define s_do_store_four(ra, rb, rc, rd, bytes) { \
    __m128i ia, ib, ic, id;                        \
    __m128i ta, tb, tc, td;                        \
    __m128i sa, sb, sc, sd;                        \
    unsigned char* ptr;                            \
    ia = ra;                                       \
    ib = rb;                                       \
    ic = rc;                                       \
    id = rd;                                       \
    ptr = ((unsigned char*)(bytes));               \
    ta = _mm_unpacklo_epi32(ia, ib);               \
    tb = _mm_unpacklo_epi32(ic, id);               \
    tc = _mm_unpackhi_epi32(ia, ib);               \
    td = _mm_unpackhi_epi32(ic, id);               \
    sa = _mm_unpacklo_epi64(ta, tb);               \
    sb = _mm_unpackhi_epi64(ta, tb);               \
    sc = _mm_unpacklo_epi64(tc, td);               \
    sd = _mm_unpackhi_epi64(tc, td);               \
    s_do_store_one(sa, &ptr[0 * sizeof(__m128i)]); \
    s_do_store_one(sb, &ptr[1 * sizeof(__m128i)]); \
    s_do_store_one(sc, &ptr[2 * sizeof(__m128i)]); \
    s_do_store_one(sd, &ptr[3 * sizeof(__m128i)]); \
  }

  const unsigned char *in;
  unsigned char *out;
  const ulong32* k;
  unsigned long iblock;
  __m128i a, b, c, d, e;

  LTC_ARGCHK(pt);
  LTC_ARGCHK(ct);
  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  in = pt;
  out = ct;
  k = &skey->serpent.k[0];
  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    s_do_load_four(a, b, c, d, in);
    s_apply_order_00(s_apply_key);
    s_apply_order_00(s_enc_0); s_apply_order_01(s_apply_ln_tr_key);
    s_apply_order_01(s_enc_1); s_apply_order_02(s_apply_ln_tr_key);
    s_apply_order_02(s_enc_2); s_apply_order_03(s_apply_ln_tr_key);
    s_apply_order_03(s_enc_3); s_apply_order_04(s_apply_ln_tr_key);
    s_apply_order_04(s_enc_4); s_apply_order_05(s_apply_ln_tr_key);
    s_apply_order_05(s_enc_5); s_apply_order_06(s_apply_ln_tr_key);
    s_apply_order_06(s_enc_6); s_apply_order_07(s_apply_ln_tr_key);
    s_apply_order_07(s_enc_7); s_apply_order_08(s_apply_ln_tr_key);
    s_apply_order_08(s_enc_0); s_apply_order_09(s_apply_ln_tr_key);
    s_apply_order_09(s_enc_1); s_apply_order_10(s_apply_ln_tr_key);
    s_apply_order_10(s_enc_2); s_apply_order_11(s_apply_ln_tr_key);
    s_apply_order_11(s_enc_3); s_apply_order_12(s_apply_ln_tr_key);
    s_apply_order_12(s_enc_4); s_apply_order_13(s_apply_ln_tr_key);
    s_apply_order_13(s_enc_5); s_apply_order_14(s_apply_ln_tr_key);
    s_apply_order_14(s_enc_6); s_apply_order_15(s_apply_ln_tr_key);
    s_apply_order_15(s_enc_7); s_apply_order_16(s_apply_ln_tr_key);
    s_apply_order_16(s_enc_0); s_apply_order_17(s_apply_ln_tr_key);
    s_apply_order_17(s_enc_1); s_apply_order_18(s_apply_ln_tr_key);
    s_apply_order_18(s_enc_2); s_apply_order_19(s_apply_ln_tr_key);
    s_apply_order_19(s_enc_3); s_apply_order_20(s_apply_ln_tr_key);
    s_apply_order_20(s_enc_4); s_apply_order_21(s_apply_ln_tr_key);
    s_apply_order_21(s_enc_5); s_apply_order_22(s_apply_ln_tr_key);
    s_apply_order_22(s_enc_6); s_apply_order_23(s_apply_ln_tr_key);
    s_apply_order_23(s_enc_7); s_apply_order_24(s_apply_ln_tr_key);
    s_apply_order_24(s_enc_0); s_apply_order_25(s_apply_ln_tr_key);
    s_apply_order_25(s_enc_1); s_apply_order_26(s_apply_ln_tr_key);
    s_apply_order_26(s_enc_2); s_apply_order_27(s_apply_ln_tr_key);
    s_apply_order_27(s_enc_3); s_apply_order_28(s_apply_ln_tr_key);
    s_apply_order_28(s_enc_4); s_apply_order_29(s_apply_ln_tr_key);
    s_apply_order_29(s_enc_5); s_apply_order_30(s_apply_ln_tr_key);
    s_apply_order_30(s_enc_6); s_apply_order_31(s_apply_ln_tr_key);
    s_apply_order_31(s_enc_7); s_apply_order_32(s_apply_key);
    s_do_store_four(a, b, c, d, out);
    in += blocks_at_a_time * serpent_block_len;
    out += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
  #undef s_do_broadcast
  #undef s_do_xor
  #undef s_do_and
  #undef s_do_or
  #undef s_do_not
  #undef s_do_assign
  #undef s_do_rol
  #undef s_do_shl
  #undef s_do_load_one
  #undef s_do_store_one
  #undef s_do_load_four
  #undef s_do_store_four
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_128_bit_sse2(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
  return CRYPT_OK;
}

static LTC_INLINE int s_serpent_accel_ctr_encrypt_128_bit_sse2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
  #define blocks_at_a_time (128 / 32)

  typedef union {
    unsigned char chars[blocks_at_a_time * serpent_block_len];
    __m128i align;
  } pad_t;

  unsigned long iblock;
  int i;
  pad_t pad;
  int err;
  __m128i big_int_pad;
  __m128i big_int_pt;
  __m128i big_int_ct;

  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    for (i = 0; i != blocks_at_a_time; ++i) {
      s_serpent_accel_ctr_increment_counter_generic(IV, mode);
      XMEMCPY(&pad.chars[i * serpent_block_len], IV, serpent_block_len);
    }
    if ((err = s_serpent_accel_ecb_encrypt_128_bit_sse2(&pad.chars[0], &pad.chars[0], blocks_at_a_time, skey)) != CRYPT_OK) {
      return err;
    }
    for (i = 0; i != LTC_ARRAY_SIZE(pad.chars) / sizeof(pad.align); ++i) {
      big_int_pad = _mm_load_si128(((const __m128i*)(&pad.chars[0] + i * sizeof(__m128i))));
      big_int_pt = _mm_loadu_si128(((const __m128i*)(pt + i * sizeof(__m128i))));
      big_int_ct = _mm_xor_si128(big_int_pad, big_int_pt);
      _mm_storeu_si128(((__m128i*)(ct + i * sizeof(__m128i))), big_int_ct);
    }
    pt += blocks_at_a_time * serpent_block_len;
    ct += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
}

#endif /* LTC_SERPENT_ACCEL_128_BIT_X86_SSE2 */

#if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2

#include <emmintrin.h> /* AVX2 __m256i _mm256_and_si256 _mm256_cmpeq_epi32 _mm256_load_si256 _mm256_loadu_si256 _mm256_or_si256 _mm256_set1_epi32 _mm256_slli_epi32 _mm256_srli_epi32 _mm256_storeu_si256 _mm256_unpackhi_epi32 _mm256_unpackhi_epi64 _mm256_unpacklo_epi32 _mm256_unpacklo_epi64 _mm256_xor_si256 */

#if defined _MSC_VER
#pragma intrinsic(_mm256_and_si256)
#pragma intrinsic(_mm256_cmpeq_epi32)
#pragma intrinsic(_mm256_load_si256)
#pragma intrinsic(_mm256_loadu_si256)
#pragma intrinsic(_mm256_or_si256)
#pragma intrinsic(_mm256_set1_epi32)
#pragma intrinsic(_mm256_slli_epi32)
#pragma intrinsic(_mm256_srli_epi32)
#pragma intrinsic(_mm256_storeu_si256)
#pragma intrinsic(_mm256_unpackhi_epi32)
#pragma intrinsic(_mm256_unpackhi_epi64)
#pragma intrinsic(_mm256_unpacklo_epi32)
#pragma intrinsic(_mm256_unpacklo_epi64)
#pragma intrinsic(_mm256_xor_si256)
#endif

#if !defined (LTC_S_X86_CPUID)
#define LTC_S_X86_CPUID
#if defined _MSC_VER
#include <intrin.h>
#pragma intrinsic(__cpuid)
#endif
static LTC_INLINE void s_x86_cpuid(int* regs, int leaf)
{
#if defined _MSC_VER
  __cpuid(regs, leaf);
#else
  int a, b, c, d;

  a = leaf;
  b = c = d = 0;
  asm volatile ("cpuid"
    :"=a"(a), "=b"(b), "=c"(c), "=d"(d)
    :"a"(a), "c"(c)
  );
  regs[0] = a;
  regs[1] = b;
  regs[2] = c;
  regs[3] = d;
#endif
}
#endif /* LTC_S_X86_CPUID */

static LTC_INLINE int s_serpent_accel_256_bit_avx2_is_supported(void)
{
  static int initialized = 0;
  static int supported = 0;

  if(!initialized) {
    int regs[4];
    int avx2;

    s_x86_cpuid(regs, 1);
    if (regs[0] >= 7) {
      s_x86_cpuid(regs, 7);
      avx2 = ((((unsigned int)(regs[1])) >> 5) & 1u) != 0; /* AVX2, leaf 7, ebx, bit 5 */
      supported = avx2;
    }
    initialized = 1;
  }
  return supported;
}

static LTC_INLINE int s_serpent_accel_ecb_encrypt_256_bit_avx2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
  #define blocks_at_a_time (256 / 32)
  #define s_do_broadcast(x) _mm256_set1_epi32(*((const int *)(&(x))))
  #define s_do_xor(a, b) a = _mm256_xor_si256(a, b)
  #define s_do_and(a, b) a = _mm256_and_si256(a, b)
  #define s_do_or(a, b) a = _mm256_or_si256(a, b)
  #define s_do_not(a, b) a = _mm256_xor_si256(b, _mm256_cmpeq_epi32(b, b))
  #define s_do_assign(a, b) a = b
  #define s_do_rol(x, i) x = _mm256_xor_si256(_mm256_slli_epi32(x, i), _mm256_srli_epi32(x, 32 - i))
  #define s_do_shl(a, b, c) a = _mm256_slli_epi32(b, c)
  #define s_do_load_one(ptr) _mm256_loadu_si256(((const __m256i*)(ptr)))
  #define s_do_store_one(x, ptr) _mm256_storeu_si256(((__m256i*)(ptr)), x)
  #define s_do_load_four(ra, rb, rc, rd, bytes) {  \
    const unsigned char* ptr;                      \
    __m256i ia, ib, ic, id;                        \
    __m256i ta, tb, tc, td;                        \
    __m256i sa, sb, sc, sd;                        \
    ptr = ((const unsigned char*)(bytes));         \
    ia = s_do_load_one(&ptr[0 * sizeof(__m256i)]); \
    ib = s_do_load_one(&ptr[1 * sizeof(__m256i)]); \
    ic = s_do_load_one(&ptr[2 * sizeof(__m256i)]); \
    id = s_do_load_one(&ptr[3 * sizeof(__m256i)]); \
    ta = _mm256_unpacklo_epi32(ia, ib);            \
    tb = _mm256_unpacklo_epi32(ic, id);            \
    tc = _mm256_unpackhi_epi32(ia, ib);            \
    td = _mm256_unpackhi_epi32(ic, id);            \
    sa = _mm256_unpacklo_epi64(ta, tb);            \
    sb = _mm256_unpackhi_epi64(ta, tb);            \
    sc = _mm256_unpacklo_epi64(tc, td);            \
    sd = _mm256_unpackhi_epi64(tc, td);            \
    ra = sa;                                       \
    rb = sb;                                       \
    rc = sc;                                       \
    rd = sd;                                       \
  }
  #define s_do_store_four(ra, rb, rc, rd, bytes) { \
    __m256i ia, ib, ic, id;                        \
    __m256i ta, tb, tc, td;                        \
    __m256i sa, sb, sc, sd;                        \
    unsigned char* ptr;                            \
    ia = ra;                                       \
    ib = rb;                                       \
    ic = rc;                                       \
    id = rd;                                       \
    ptr = ((unsigned char*)(bytes));               \
    ta = _mm256_unpacklo_epi32(ia, ib);            \
    tb = _mm256_unpacklo_epi32(ic, id);            \
    tc = _mm256_unpackhi_epi32(ia, ib);            \
    td = _mm256_unpackhi_epi32(ic, id);            \
    sa = _mm256_unpacklo_epi64(ta, tb);            \
    sb = _mm256_unpackhi_epi64(ta, tb);            \
    sc = _mm256_unpacklo_epi64(tc, td);            \
    sd = _mm256_unpackhi_epi64(tc, td);            \
    s_do_store_one(sa, &ptr[0 * sizeof(__m256i)]); \
    s_do_store_one(sb, &ptr[1 * sizeof(__m256i)]); \
    s_do_store_one(sc, &ptr[2 * sizeof(__m256i)]); \
    s_do_store_one(sd, &ptr[3 * sizeof(__m256i)]); \
  }

  const unsigned char *in;
  unsigned char *out;
  const ulong32* k;
  unsigned long iblock;
  __m256i a, b, c, d, e;

  LTC_ARGCHK(pt);
  LTC_ARGCHK(ct);
  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  in = pt;
  out = ct;
  k = &skey->serpent.k[0];
  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    s_do_load_four(a, b, c, d, in);
    s_apply_order_00(s_apply_key);
    s_apply_order_00(s_enc_0); s_apply_order_01(s_apply_ln_tr_key);
    s_apply_order_01(s_enc_1); s_apply_order_02(s_apply_ln_tr_key);
    s_apply_order_02(s_enc_2); s_apply_order_03(s_apply_ln_tr_key);
    s_apply_order_03(s_enc_3); s_apply_order_04(s_apply_ln_tr_key);
    s_apply_order_04(s_enc_4); s_apply_order_05(s_apply_ln_tr_key);
    s_apply_order_05(s_enc_5); s_apply_order_06(s_apply_ln_tr_key);
    s_apply_order_06(s_enc_6); s_apply_order_07(s_apply_ln_tr_key);
    s_apply_order_07(s_enc_7); s_apply_order_08(s_apply_ln_tr_key);
    s_apply_order_08(s_enc_0); s_apply_order_09(s_apply_ln_tr_key);
    s_apply_order_09(s_enc_1); s_apply_order_10(s_apply_ln_tr_key);
    s_apply_order_10(s_enc_2); s_apply_order_11(s_apply_ln_tr_key);
    s_apply_order_11(s_enc_3); s_apply_order_12(s_apply_ln_tr_key);
    s_apply_order_12(s_enc_4); s_apply_order_13(s_apply_ln_tr_key);
    s_apply_order_13(s_enc_5); s_apply_order_14(s_apply_ln_tr_key);
    s_apply_order_14(s_enc_6); s_apply_order_15(s_apply_ln_tr_key);
    s_apply_order_15(s_enc_7); s_apply_order_16(s_apply_ln_tr_key);
    s_apply_order_16(s_enc_0); s_apply_order_17(s_apply_ln_tr_key);
    s_apply_order_17(s_enc_1); s_apply_order_18(s_apply_ln_tr_key);
    s_apply_order_18(s_enc_2); s_apply_order_19(s_apply_ln_tr_key);
    s_apply_order_19(s_enc_3); s_apply_order_20(s_apply_ln_tr_key);
    s_apply_order_20(s_enc_4); s_apply_order_21(s_apply_ln_tr_key);
    s_apply_order_21(s_enc_5); s_apply_order_22(s_apply_ln_tr_key);
    s_apply_order_22(s_enc_6); s_apply_order_23(s_apply_ln_tr_key);
    s_apply_order_23(s_enc_7); s_apply_order_24(s_apply_ln_tr_key);
    s_apply_order_24(s_enc_0); s_apply_order_25(s_apply_ln_tr_key);
    s_apply_order_25(s_enc_1); s_apply_order_26(s_apply_ln_tr_key);
    s_apply_order_26(s_enc_2); s_apply_order_27(s_apply_ln_tr_key);
    s_apply_order_27(s_enc_3); s_apply_order_28(s_apply_ln_tr_key);
    s_apply_order_28(s_enc_4); s_apply_order_29(s_apply_ln_tr_key);
    s_apply_order_29(s_enc_5); s_apply_order_30(s_apply_ln_tr_key);
    s_apply_order_30(s_enc_6); s_apply_order_31(s_apply_ln_tr_key);
    s_apply_order_31(s_enc_7); s_apply_order_32(s_apply_key);
    s_do_store_four(a, b, c, d, out);
    in += blocks_at_a_time * serpent_block_len;
    out += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
  #undef s_do_broadcast
  #undef s_do_xor
  #undef s_do_and
  #undef s_do_or
  #undef s_do_not
  #undef s_do_assign
  #undef s_do_rol
  #undef s_do_shl
  #undef s_do_load_one
  #undef s_do_store_one
  #undef s_do_load_four
  #undef s_do_store_four
}

static LTC_INLINE int s_serpent_accel_ecb_decrypt_256_bit_avx2(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
  return CRYPT_OK;
}

static LTC_INLINE int s_serpent_accel_ctr_encrypt_256_bit_avx2(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
  #define blocks_at_a_time (256 / 32)

  typedef union {
    unsigned char chars[blocks_at_a_time * serpent_block_len];
    __m256i align;
  } pad_t;

  unsigned long iblock;
  int i;
  pad_t pad;
  int err;
  __m256i big_int_pad;
  __m256i big_int_pt;
  __m256i big_int_ct;

  LTC_ARGCHK(blocks % blocks_at_a_time == 0);

  for (iblock = 0; iblock != blocks; iblock += blocks_at_a_time) {
    for (i = 0; i != blocks_at_a_time; ++i) {
      s_serpent_accel_ctr_increment_counter_generic(IV, mode);
      XMEMCPY(&pad.chars[i * serpent_block_len], IV, serpent_block_len);
    }
    if ((err = s_serpent_accel_ecb_encrypt_256_bit_avx2(&pad.chars[0], &pad.chars[0], blocks_at_a_time, skey)) != CRYPT_OK) {
      return err;
    }
    for (i = 0; i != LTC_ARRAY_SIZE(pad.chars) / sizeof(pad.align); ++i) {
      big_int_pad = _mm256_load_si256(((const __m256i*)(&pad.chars[0] + i * sizeof(__m256i))));
      big_int_pt = _mm256_loadu_si256(((const __m256i*)(pt + i * sizeof(__m256i))));
      big_int_ct = _mm256_xor_si256(big_int_pad, big_int_pt);
      _mm256_storeu_si256(((__m256i*)(ct + i * sizeof(__m256i))), big_int_ct);
    }
    pt += blocks_at_a_time * serpent_block_len;
    ct += blocks_at_a_time * serpent_block_len;
  }
  return CRYPT_OK;

  #undef blocks_at_a_time
}

#endif /* LTC_SERPENT_ACCEL_256_BIT_X86_AVX2 */

#undef s_apply_order_00
#undef s_apply_order_01
#undef s_apply_order_02
#undef s_apply_order_03
#undef s_apply_order_04
#undef s_apply_order_05
#undef s_apply_order_06
#undef s_apply_order_07
#undef s_apply_order_08
#undef s_apply_order_09
#undef s_apply_order_10
#undef s_apply_order_11
#undef s_apply_order_12
#undef s_apply_order_13
#undef s_apply_order_14
#undef s_apply_order_15
#undef s_apply_order_16
#undef s_apply_order_17
#undef s_apply_order_18
#undef s_apply_order_19
#undef s_apply_order_20
#undef s_apply_order_21
#undef s_apply_order_22
#undef s_apply_order_23
#undef s_apply_order_24
#undef s_apply_order_25
#undef s_apply_order_26
#undef s_apply_order_27
#undef s_apply_order_28
#undef s_apply_order_29
#undef s_apply_order_30
#undef s_apply_order_31
#undef s_apply_order_32
#undef s_apply_key
#undef s_apply_ln_tr_key
#undef s_enc_0
#undef s_enc_1
#undef s_enc_2
#undef s_enc_3
#undef s_enc_4
#undef s_enc_5
#undef s_enc_6
#undef s_enc_7

#if LTC_SERPENT_ACCEL

int serpent_accel_ecb_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long blocks, const symmetric_key *skey)
{
  const unsigned char *in;
  unsigned char *out;
  unsigned long rem;
  unsigned long n;
  int err;

  in = pt;
  out = ct;
  rem = blocks;
  while (rem != 0) {
    #if defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512
    if (rem >= (512 / 32) && s_serpent_accel_512_bit_avx512_is_supported()) {
      n = (rem / (512 / 32)) * (512 / 32);
      err = s_serpent_accel_ecb_encrypt_avx512_512_bit(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
    if (rem >= (256 / 32) && s_serpent_accel_256_bit_avx2_is_supported()) {
      #if defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512
      n = 256 / 32;
      #else
      n = (rem / (256 / 32)) * (256 / 32);
      #endif
      err = s_serpent_accel_ecb_encrypt_256_bit_avx2(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
    if (rem >= (128 / 32) && s_serpent_accel_128_bit_sse2_is_supported()) {
      #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
      n = 128 / 32;
      #else
      n = (rem / (128 / 32)) * (128 / 32);
      #endif
      err = s_serpent_accel_ecb_encrypt_128_bit_sse2(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_64_BIT_PLAIN
    if (rem >= (64 / 32)) {
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      n = 64 / 32;
      #else
      n = (rem / (64 / 32)) * (64 / 32);
      #endif
      err = s_serpent_accel_ecb_encrypt_64_bit_plain(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX
    if (rem >= (64 / 32)) {
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      n = 64 / 32;
      #else
      n = (rem / (64 / 32)) * (64 / 32);
      #endif
      err = s_serpent_accel_ecb_encrypt_64_bit_mmx(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    {
      #if defined LTC_SERPENT_ACCEL_64_BIT || defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX
      n = 32 / 32;
      #else
      n = rem;
      #endif
      err = s_serpent_accel_ecb_encrypt_32_bit(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    }
  }
  return CRYPT_OK;
}

int serpent_accel_ecb_decrypt(const unsigned char *ct, unsigned char *pt, unsigned long blocks, const symmetric_key *skey)
{
  const unsigned char *in;
  unsigned char *out;
  unsigned long rem;
  unsigned long n;
  int err;
  unsigned long i;

  in = ct;
  out = pt;
  rem = blocks;
  while (rem != 0) {
    #if defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512
    if (rem >= (512 / 32) && s_serpent_accel_512_bit_avx512_is_supported()) {
      n = (rem / (512 / 32)) * (512 / 32);
      err = s_serpent_accel_ecb_decrypt_avx512_512_bit(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
    if (rem >= (256 / 32) && s_serpent_accel_256_bit_avx2_is_supported()) {
      #if defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512
      n = 256 / 32;
      #else
      n = (rem / (256 / 32)) * (256 / 32);
      #endif
      err = s_serpent_accel_ecb_decrypt_256_bit_avx2(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
    if (rem >= (128 / 32) && s_serpent_accel_128_bit_sse2_is_supported()) {
      #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
      n = 128 / 32;
      #else
      n = (rem / (128 / 32)) * (128 / 32);
      #endif
      err = s_serpent_accel_ecb_decrypt_128_bit_sse2(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_64_BIT_PLAIN
    if (rem >= (64 / 32)) {
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      n = 64 / 32;
      #else
      n = (rem / (64 / 32)) * (64 / 32);
      #endif
      err = s_serpent_accel_ecb_decrypt_64_bit_plain(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX
    if (rem >= (64 / 32)) {
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      n = 64 / 32;
      #else
      n = (rem / (64 / 32)) * (64 / 32);
      #endif
      err = s_serpent_accel_ecb_decrypt_64_bit_mmx(in, out, n, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    {
      #if defined LTC_SERPENT_ACCEL_64_BIT || defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX
      n = 32 / 32;
      #else
      n = rem;
      #endif
      for (i = 0; i != n; ++i) {
        err = serpent_ecb_decrypt(in, out, skey); if (err != CRYPT_OK) { return err; }
        out += n * serpent_block_len;
        in += n * serpent_block_len;
      }
      rem -= n;
    }
  }
  return CRYPT_OK;
}

static int s_serpent_accel_ctr_encrypt(const unsigned char *pt, unsigned char *ct, unsigned long blocks, unsigned char *IV, int mode, const symmetric_key *skey)
{
  const unsigned char *in;
  unsigned char *out;
  unsigned long rem;
  unsigned long n;
  int err;

  in = pt;
  out = ct;
  rem = blocks;
  while (rem != 0) {
    #if defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512
    if (rem >= (512 / 32) && s_serpent_accel_512_bit_avx512_is_supported()) {
      n = (rem / (512 / 32)) * (512 / 32);
      err = s_serpent_accel_ctr_encrypt_avx512_512_bit(in, out, n, IV, mode, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
    if (rem >= (256 / 32) && s_serpent_accel_256_bit_avx2_is_supported()) {
      #if defined LTC_SERPENT_ACCEL_512_BIT_X86_AVX512
      n = 256 / 32;
      #else
      n = (rem / (256 / 32)) * (256 / 32);
      #endif
      err = s_serpent_accel_ctr_encrypt_256_bit_avx2(in, out, n, IV, mode, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
    if (rem >= (128 / 32) && s_serpent_accel_128_bit_sse2_is_supported()) {
      #if defined LTC_SERPENT_ACCEL_256_BIT_X86_AVX2
      n = 128 / 32;
      #else
      n = (rem / (128 / 32)) * (128 / 32);
      #endif
      err = s_serpent_accel_ctr_encrypt_128_bit_sse2(in, out, n, IV, mode, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_64_BIT_PLAIN
    if (rem >= (64 / 32)) {
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      n = 64 / 32;
      #else
      n = (rem / (64 / 32)) * (64 / 32);
      #endif
      err = s_serpent_accel_ctr_encrypt_64_bit_plain(in, out, n, IV, mode, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    #if defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX
    if (rem >= (64 / 32)) {
      #if defined LTC_SERPENT_ACCEL_128_BIT_X86_SSE2
      n = 64 / 32;
      #else
      n = (rem / (64 / 32)) * (64 / 32);
      #endif
      err = s_serpent_accel_ctr_encrypt_64_bit_mmx(in, out, n, IV, mode, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    } else
    #endif
    {
      #if defined LTC_SERPENT_ACCEL_64_BIT || defined LTC_SERPENT_ACCEL_64_BIT_X86_MMX
      n = 32 / 32;
      #else
      n = rem;
      #endif
      err = s_serpent_accel_ctr_encrypt_32_bit(in, out, n, IV, mode, skey); if (err != CRYPT_OK) { return err; }
      out += n * serpent_block_len;
      in += n * serpent_block_len;
      rem -= n;
    }
  }
  return CRYPT_OK;
}

#endif

int serpent_test(void)
{
#ifndef LTC_TEST
   return CRYPT_NOP;
#else
   static const struct {
      unsigned char key[32];
      int keylen;
      unsigned char pt[16], ct[16];
   } tests[] = {
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xA2,0x23,0xAA,0x12,0x88,0x46,0x3C,0x0E,0x2B,0xE3,0x8E,0xBD,0x82,0x56,0x16,0xC0}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xEA,0xE1,0xD4,0x05,0x57,0x01,0x74,0xDF,0x7D,0xF2,0xF9,0x96,0x6D,0x50,0x91,0x59}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 32,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x65,0xF3,0x76,0x84,0x47,0x1E,0x92,0x1D,0xC8,0xA3,0x0F,0x45,0xB4,0x3C,0x44,0x99}
      },
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x9E,0x27,0x4E,0xAD,0x9B,0x73,0x7B,0xB2,0x1E,0xFC,0xFC,0xA5,0x48,0x60,0x26,0x89}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x92,0xFC,0x8E,0x51,0x03,0x99,0xE4,0x6A,0x04,0x1B,0xF3,0x65,0xE7,0xB3,0xAE,0x82}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 24,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x5E,0x0D,0xA3,0x86,0xC4,0x6A,0xD4,0x93,0xDE,0xA2,0x03,0xFD,0xC6,0xF5,0x7D,0x70}
      },
      {
      /* key */    {0x80,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x26,0x4E,0x54,0x81,0xEF,0xF4,0x2A,0x46,0x06,0xAB,0xDA,0x06,0xC0,0xBF,0xDA,0x3D}
      },
      {
      /* key */    {0x40,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0x4A,0x23,0x1B,0x3B,0xC7,0x27,0x99,0x34,0x07,0xAC,0x6E,0xC8,0x35,0x0E,0x85,0x24}
      },
      {
      /* key */    {0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* keylen */ 16,
      /* pt */     {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00},
      /* ct */     {0xE0,0x32,0x69,0xF9,0xE9,0xFD,0x85,0x3C,0x7D,0x81,0x56,0xDF,0x14,0xB9,0x8D,0x56}
      }
   };

   unsigned char buf[2][16];
   symmetric_key key;
   int err, x;

   for (x = 0; x < (int)LTC_ARRAY_SIZE(tests); x++) {
      if ((err = serpent_setup(tests[x].key, tests[x].keylen, 0, &key)) != CRYPT_OK) {
        return err;
      }
      if ((err = serpent_ecb_encrypt(tests[x].pt, buf[0], &key)) != CRYPT_OK) {
        return err;
      }
      if (ltc_compare_testvector(buf[0], 16, tests[x].ct, 16, "SERPENT Encrypt", x)) {
        return CRYPT_FAIL_TESTVECTOR;
      }
      if ((err = serpent_ecb_decrypt(tests[x].ct, buf[1], &key)) != CRYPT_OK) {
        return err;
      }
      if (ltc_compare_testvector(buf[1], 16, tests[x].pt, 16, "SERPENT Decrypt", x)) {
        return CRYPT_FAIL_TESTVECTOR;
      }
   }

   return CRYPT_OK;
#endif
}

#undef s_lt
#undef s_ilt
#undef s_beforeS0
#undef s_afterS0
#undef s_afterS1
#undef s_afterS2
#undef s_afterS3
#undef s_afterS4
#undef s_afterS5
#undef s_afterS6
#undef s_afterS7
#undef s_beforeI7
#undef s_afterI7
#undef s_afterI6
#undef s_afterI5
#undef s_afterI4
#undef s_afterI3
#undef s_afterI2
#undef s_afterI1
#undef s_afterI0
#undef s_s0
#undef s_i0
#undef s_s1
#undef s_i1
#undef s_s2
#undef s_i2
#undef s_s3
#undef s_i3
#undef s_s4
#undef s_i4
#undef s_s5
#undef s_i5
#undef s_s6
#undef s_i6
#undef s_s7
#undef s_i7
#undef s_kx
#undef s_lk
#undef s_sk
#undef s_setup_key
#undef serpent_block_len

#endif
