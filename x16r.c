#include "x16r.h"
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include "sha3/sph_blake.h"
#include "sha3/sph_bmw.h"
#include "sha3/sph_groestl.h"
#include "sha3/sph_jh.h"
#include "sha3/sph_keccak.h"
#include "sha3/sph_skein.h"
#include "sha3/sph_luffa.h"
#include "sha3/sph_cubehash.h"
#include "sha3/sph_shavite.h"
#include "sha3/sph_simd.h"
#include "sha3/sph_echo.h"
#include "sha3/sph_hamsi.h"
#include "sha3/sph_fugue.h"
#include "sha3/sph_shabal.h"
#include "sha3/sph_whirlpool.h"
#include "sha3/sph_sha2.h"

#define X16R_BLAKE      0
#define X16R_BMW        1
#define X16R_GROESTL    2
#define X16R_JH         3
#define X16R_KECCAK     4
#define X16R_SKEIN      5
#define X16R_LUFFA      6
#define X16R_CUBEHASH   7
#define X16R_SHAVITE    8
#define X16R_SIMD       9
#define X16R_ECHO       10
#define X16R_HAMSI      11
#define X16R_FUGUE      12
#define X16R_SHABAL     13
#define X16R_WHIRLPOOL  14
#define X16R_SHA512     15

#define X16R_HASH_COUNT (X16R_SHA512 + 1)

static char *hash_names[X16R_HASH_COUNT] =
{
    "blake",
    "bmw",
    "groestl",
    "jh",
    "keccak",
    "skein",
    "luffa",
    "cubehash",
    "shavite",
    "simd",
    "echo",
    "hamsi",
    "fugue",
    "shabal",
    "whirlpool",
    "sha512",
};

inline int get_hash_selection(const uint8_t *prev_block_hash, int index)
{
    uint8_t nibble = prev_block_hash[7 - (index / 2)];
    if (index % 2 == 0)
    {
        return nibble >> 4;
    }
    else
    {
        return nibble & 0x0f;
    }
}

void x16r_hash(const char* input, char* output, uint32_t len)
{
	
	sph_blake512_context     ctx_blake;      //0
    sph_bmw512_context       ctx_bmw;        //1
    sph_groestl512_context   ctx_groestl;    //2
    sph_jh512_context        ctx_jh;         //3
    sph_keccak512_context    ctx_keccak;     //4
    sph_skein512_context     ctx_skein;      //5
    sph_luffa512_context     ctx_luffa;      //6
    sph_cubehash512_context  ctx_cubehash;   //7
    sph_shavite512_context   ctx_shavite;    //8
    sph_simd512_context      ctx_simd;       //9
    sph_echo512_context      ctx_echo;       //A
    sph_hamsi512_context     ctx_hamsi;      //B
    sph_fugue512_context     ctx_fugue;      //C
    sph_shabal512_context    ctx_shabal;     //D
    sph_whirlpool_context    ctx_whirlpool;  //E
    sph_sha512_context       ctx_sha512;     //F

    uchar _ALIGN(64) hash[64];
    uint32_t *phash = (uint32_t *) hash;
    uint8_t *prev_block_hash = (uint8_t *) input + 4;
	
	    for (int i = 0; i < X16R_HASH_COUNT; i++)
    {
        int length;
        if (i == 0)
        {
            length = 80;
        }
        else
        {
            input = phash;
            length = 64;
        }

        int hash_selection = get_hash_selection(prev_block_hash, i);
        switch (hash_selection)
        {
            case X16R_BLAKE:
                sph_blake512_init(&ctx_blake);
                sph_blake512(&ctx_blake, input, length);
                sph_blake512_close(&ctx_blake, phash);
                break;
            case X16R_BMW:
                sph_bmw512_init(&ctx_bmw);
                sph_bmw512(&ctx_bmw, input, length);
                sph_bmw512_close(&ctx_bmw, phash);
                break;
            case X16R_GROESTL:
                sph_groestl512_init(&ctx_groestl);
                sph_groestl512(&ctx_groestl, input, length);
                sph_groestl512_close(&ctx_groestl, phash);
                break;
            case X16R_JH:
                sph_jh512_init(&ctx_jh);
                sph_jh512(&ctx_jh, input, length);
                sph_jh512_close(&ctx_jh, phash);
                break;
            case X16R_KECCAK:
                sph_keccak512_init(&ctx_keccak);
                sph_keccak512(&ctx_keccak, input, length);
                sph_keccak512_close(&ctx_keccak, phash);
                break;
            case X16R_SKEIN:
                sph_skein512_init(&ctx_skein);
                sph_skein512(&ctx_skein, input, length);
                sph_skein512_close(&ctx_skein, phash);
                break;
            case X16R_LUFFA:
                sph_luffa512_init(&ctx_luffa);
                sph_luffa512(&ctx_luffa, input, length);
                sph_luffa512_close(&ctx_luffa, phash);
                break;
            case X16R_CUBEHASH:
                sph_cubehash512_init(&ctx_cubehash);
                sph_cubehash512(&ctx_cubehash, input, length);
                sph_cubehash512_close(&ctx_cubehash, phash);
                break;
            case X16R_SHAVITE:
                sph_shavite512_init(&ctx_shavite);
                sph_shavite512(&ctx_shavite, input, length);
                sph_shavite512_close(&ctx_shavite, phash);
                break;
            case X16R_SIMD:
                sph_simd512_init(&ctx_simd);
                sph_simd512(&ctx_simd, input, length);
                sph_simd512_close(&ctx_simd, phash);
                break;
            case X16R_ECHO:
                sph_echo512_init(&ctx_echo);
                sph_echo512(&ctx_echo, input, length);
                sph_echo512_close(&ctx_echo, phash);
                break;
            case X16R_HAMSI:
                sph_hamsi512_init(&ctx_hamsi);
                sph_hamsi512(&ctx_hamsi, input, length);
                sph_hamsi512_close(&ctx_hamsi, phash);
                break;
            case X16R_FUGUE:
                sph_fugue512_init(&ctx_fugue);
                sph_fugue512(&ctx_fugue, input, length);
                sph_fugue512_close(&ctx_fugue, phash);
                break;
            case X16R_SHABAL:
                sph_shabal512_init(&ctx_shabal);
                sph_shabal512(&ctx_shabal, input, length);
                sph_shabal512_close(&ctx_shabal, phash);
                break;
            case X16R_WHIRLPOOL:
                sph_whirlpool_init(&ctx_whirlpool);
                sph_whirlpool(&ctx_whirlpool, input, length);
                sph_whirlpool_close(&ctx_whirlpool, phash);
                break;
            case X16R_SHA512:
                sph_sha512_init(&ctx_sha512);
                sph_sha512(&ctx_sha512, input, length);
                sph_sha512_close(&ctx_sha512, phash);
                break;
            default:
                gpulog(LOG_ERR, -1, "Unknown hash selection: %d (this should never happen!)", hash_selection);
                break;
        }
    }
    memcpy(output, phash, 32);
}