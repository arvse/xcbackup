/* ------------------------------------------------------------------
 * XCBackup - AES-CBC-256-PKCS#7 Encrypted Stream Impl.
 * ------------------------------------------------------------------ */

#ifdef ENABLE_ENCRYPTION

#include "xcbackup.h"
#include <mbedtls/aes.h>
#include <mbedtls/sha256.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>

#define AES256_KEYLEN 32
#define AES256_KEYLEN_BITS (AES256_KEYLEN * 8)
#define AES256_BLOCKLEN 16
#define SHA256_BLOCKLEN 32
#define DERIVE_N_ROUNDS 10000
#define NONCE_LEN (16 * AES256_BLOCKLEN)

/**
 * AES stream context
 */
struct aes_stream_context_t
{
    int eof;
    size_t unconsumed_len;

    struct io_stream_t *internal;
    mbedtls_aes_context aes;
    mbedtls_md_context_t md_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;

    uint8_t esalt[AES256_KEYLEN];
    uint8_t hsalt[AES256_KEYLEN];
    uint8_t iv[AES256_BLOCKLEN];
    uint8_t unconsumed[AES256_BLOCKLEN];
    uint8_t tail[AES256_BLOCKLEN + SHA256_BLOCKLEN];

    uint8_t buffer[AES256_BLOCKLEN + SHA256_BLOCKLEN + CHUNK_SIZE];
};

/**
 * Derive crypto key using PBKDF2 and SHA-256
 */
static int aes_stream_derive_key ( const char *password, const uint8_t * salt,
    size_t salt_len, uint8_t * key, size_t key_size )
{
    mbedtls_md_context_t sha256_ctx;
    const mbedtls_md_info_t *sha256_info;

    mbedtls_md_init ( &sha256_ctx );

    if ( !( sha256_info = mbedtls_md_info_from_type ( MBEDTLS_MD_SHA256 ) ) )
    {
        mbedtls_md_free ( &sha256_ctx );
        return -1;
    }

    if ( mbedtls_md_setup ( &sha256_ctx, sha256_info, 1 ) != 0 )
    {
        mbedtls_md_free ( &sha256_ctx );
        return -1;
    }

    if ( mbedtls_pkcs5_pbkdf2_hmac ( &sha256_ctx, ( const uint8_t * ) password,
            strlen ( password ), salt, salt_len, DERIVE_N_ROUNDS, key_size, key ) != 0 )
    {
        memset ( key, '\0', key_size );
        mbedtls_md_free ( &sha256_ctx );
        return -1;
    }

    mbedtls_md_free ( &sha256_ctx );

    return 0;
}

/**
 * Random generator personalization bytes
 */
static const uint8_t aes_stream_random_pers[] = {
    0x13, 0xc6, 0xae, 0x24, 0xcd, 0x52, 0x15, 0x1b,
    0x68, 0xbf, 0x64, 0x47, 0x07, 0x54, 0xc9, 0x10,
    0xda, 0x21, 0xae, 0x9f, 0x9f, 0xda, 0xc0, 0xf2,
    0x40, 0x9b, 0x8d, 0xea, 0x32, 0x9c, 0x1d, 0x04
};

/**
 * Setup random generator
 */
static int aes_stream_random_init ( struct aes_stream_context_t *context )
{
    mbedtls_entropy_init ( &context->entropy );
    mbedtls_ctr_drbg_init ( &context->ctr_drbg );

    mbedtls_ctr_drbg_set_prediction_resistance ( &context->ctr_drbg, MBEDTLS_CTR_DRBG_PR_ON );

    if ( mbedtls_ctr_drbg_seed ( &context->ctr_drbg, mbedtls_entropy_func, &context->entropy,
            aes_stream_random_pers, sizeof ( aes_stream_random_pers ) ) != 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Generate random bytes
 */
static int aes_stream_random_bytes ( struct aes_stream_context_t *context, uint8_t * data,
    size_t len )
{
    if ( mbedtls_ctr_drbg_random ( &context->ctr_drbg, data, len ) != 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Cleanup random generator
 */
static void aes_stream_random_free ( struct aes_stream_context_t *context )
{
    mbedtls_entropy_free ( &context->entropy );
    mbedtls_ctr_drbg_free ( &context->ctr_drbg );
}

/**
 * Shift unconsumed queue
 */
static size_t aes_stream_shift_unconsumed ( struct aes_stream_context_t *context, void *data,
    size_t len )
{
    size_t shift_len;
    uint8_t temp[AES256_BLOCKLEN];

    shift_len = MIN ( len, context->unconsumed_len );
    context->unconsumed_len -= shift_len;
    memcpy ( data, context->unconsumed, shift_len );
    memcpy ( temp, context->unconsumed + shift_len, context->unconsumed_len );
    memcpy ( context->unconsumed, temp, context->unconsumed_len );

    return shift_len;
}

/**
 * Get AES PKCS#7 padding length
 */
static int pkcs7_get_padding_length ( const uint8_t * input, size_t length, size_t *result )
{
    size_t i;
    size_t padding_len;

    if ( length != AES256_BLOCKLEN )
    {
        return -1;
    }

    padding_len = input[AES256_BLOCKLEN - 1];

    if ( padding_len > AES256_BLOCKLEN )
    {
        return -1;
    }

    for ( i = AES256_BLOCKLEN - padding_len; i < AES256_BLOCKLEN; i++ )
    {
        if ( input[i] != padding_len )
        {
            return -1;
        }
    }

    *result = padding_len;

    return 0;
}

/**
 * Read data from AES stream
 */
static ssize_t aes_stream_read ( struct io_stream_t *io, void *data, size_t len )
{
    ssize_t read_len;
    size_t offset;
    size_t aligned_len;
    size_t padding_len;
    struct aes_stream_context_t *context;

    context = ( struct aes_stream_context_t * ) io->context;

    if ( context->unconsumed_len )
    {
        return aes_stream_shift_unconsumed ( context, data, len );
    }

    if ( context->eof )
    {
        return 0;
    }

    aligned_len = len;

    if ( aligned_len % AES256_BLOCKLEN )
    {
        aligned_len += AES256_BLOCKLEN - aligned_len % AES256_BLOCKLEN;
    }

    if ( AES256_BLOCKLEN + SHA256_BLOCKLEN + aligned_len > CHUNK_SIZE )
    {
        aligned_len = CHUNK_SIZE - AES256_BLOCKLEN - SHA256_BLOCKLEN;
    }

    if ( aligned_len > AES256_BLOCKLEN )
    {
        aligned_len = AES256_BLOCKLEN;
    }

    memcpy ( context->buffer, context->tail, AES256_BLOCKLEN + SHA256_BLOCKLEN );

    if ( ( read_len =
            context->internal->read_max ( context->internal,
                context->buffer + AES256_BLOCKLEN + SHA256_BLOCKLEN, aligned_len ) ) < 0 )
    {
        return -1;
    }

    aligned_len = read_len;

    if ( aligned_len % AES256_BLOCKLEN )
    {
        return -1;
    }

    if ( aligned_len == ARCHIVE_PREFIX_LENGTH )
    {
        for ( offset = 1; offset <= AES256_BLOCKLEN; offset++ )
        {
            if ( !memcmp ( context->buffer + SHA256_BLOCKLEN + offset, xcbackup_archive_postfix,
                    ARCHIVE_PREFIX_LENGTH ) )
            {
                aligned_len = 0;
                break;
            }
        }
    }

    if ( !aligned_len )
    {
        if ( mbedtls_md_hmac_update ( &context->md_ctx, context->tail, AES256_BLOCKLEN ) != 0 )
        {
            return -1;
        }

        if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_DECRYPT, AES256_BLOCKLEN,
                context->iv, context->tail, context->unconsumed ) != 0 )
        {
            return -1;
        }

        if ( pkcs7_get_padding_length ( context->unconsumed, AES256_BLOCKLEN, &padding_len ) < 0 )
        {
            return -1;
        }

        context->unconsumed_len = AES256_BLOCKLEN - padding_len;

        context->eof = 1;

        return aes_stream_shift_unconsumed ( context, data, len );
    }

    if ( mbedtls_md_hmac_update ( &context->md_ctx, context->buffer, aligned_len ) != 0 )
    {
        return -1;
    }

    if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_DECRYPT, aligned_len, context->iv,
            context->buffer, context->buffer ) != 0 )
    {
        return -1;
    }

    memcpy ( context->tail, context->buffer + aligned_len, AES256_BLOCKLEN + SHA256_BLOCKLEN );

    if ( len < aligned_len )
    {
        memcpy ( data, context->buffer, len );
        context->unconsumed_len = aligned_len - len;
        memcpy ( context->unconsumed, context->buffer + len, context->unconsumed_len );
        return len;
    }

    memcpy ( data, context->buffer, aligned_len );
    context->unconsumed_len = 0;

    return aligned_len;
}

/**
 * Write data to AES stream
 */
static ssize_t aes_stream_write ( struct io_stream_t *io, const void *data, size_t len )
{
    size_t shift_len;
    size_t aligned_len;
    size_t offset = 0;
    struct aes_stream_context_t *context;

    context = ( struct aes_stream_context_t * ) io->context;

    if ( context->unconsumed_len )
    {
        if ( context->unconsumed_len + len > AES256_BLOCKLEN )
        {
            shift_len = AES256_BLOCKLEN - context->unconsumed_len;

        } else
        {
            shift_len = len;
        }

        memcpy ( context->unconsumed + context->unconsumed_len, data, shift_len );
        context->unconsumed_len += shift_len;

        if ( context->unconsumed_len < AES256_BLOCKLEN )
        {
            return len;
        }

        if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_ENCRYPT, AES256_BLOCKLEN,
                context->iv, context->unconsumed, context->buffer ) != 0 )
        {
            return -1;
        }

        if ( mbedtls_md_hmac_update ( &context->md_ctx, context->buffer, AES256_BLOCKLEN ) != 0 )
        {
            return -1;
        }

        if ( context->internal->write_complete ( context->internal, context->buffer,
                AES256_BLOCKLEN ) < 0 )
        {
            return -1;
        }

        context->unconsumed_len = 0;

        offset += shift_len;
        len -= shift_len;
    }

    aligned_len = len;

    if ( aligned_len % AES256_BLOCKLEN )
    {
        aligned_len -= aligned_len % AES256_BLOCKLEN;
    }

    if ( aligned_len > sizeof ( context->buffer ) )
    {
        aligned_len = sizeof ( context->buffer );
    }

    if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_ENCRYPT, aligned_len, context->iv,
            data + offset, context->buffer ) != 0 )
    {
        return -1;
    }

    if ( mbedtls_md_hmac_update ( &context->md_ctx, context->buffer, aligned_len ) != 0 )
    {
        return -1;
    }

    if ( context->internal->write_complete ( context->internal, context->buffer, aligned_len ) < 0 )
    {
        return -1;
    }

    offset += aligned_len;
    len -= aligned_len;

    if ( len && len < AES256_BLOCKLEN )
    {
        context->unconsumed_len = len;
        memcpy ( context->unconsumed, data + offset, context->unconsumed_len );
        offset += context->unconsumed_len;
    }

    return offset;
}

/**
 * Verify AES stream integrity
 */
static int aes_stream_verify ( struct io_stream_t *io )
{
    struct aes_stream_context_t *context;
    uint8_t calc_hmac[SHA256_BLOCKLEN];
    uint8_t temp[AES256_BLOCKLEN];

    context = ( struct aes_stream_context_t * ) io->context;

    while ( !context->eof )
    {
        if ( aes_stream_read ( io, temp, sizeof ( temp ) ) < 0 )
        {
            return -1;
        }
    }

    if ( mbedtls_md_hmac_finish ( &context->md_ctx, calc_hmac ) != 0 )
    {
        return -1;
    }

    if ( memcmp ( calc_hmac, context->tail + AES256_BLOCKLEN, SHA256_BLOCKLEN ) != 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Flush AES stream output
 */
static int aes_stream_flush ( struct io_stream_t *io )
{
    struct aes_stream_context_t *context;
    uint8_t padding;
    uint8_t buffer[AES256_BLOCKLEN] = { 0 };
    uint8_t hmac[SHA256_BLOCKLEN];

    context = ( struct aes_stream_context_t * ) io->context;
    padding = AES256_BLOCKLEN - context->unconsumed_len;

    memcpy ( buffer, context->unconsumed, context->unconsumed_len );
    memset ( buffer + context->unconsumed_len, padding, padding );

    if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_ENCRYPT, AES256_BLOCKLEN, context->iv,
            buffer, buffer ) != 0 )
    {
        return -1;
    }

    if ( mbedtls_md_hmac_update ( &context->md_ctx, buffer, sizeof ( buffer ) ) != 0 )
    {
        return -1;
    }

    if ( context->internal->write_complete ( context->internal, buffer, sizeof ( buffer ) ) < 0 )
    {
        return -1;
    }

    if ( mbedtls_md_hmac_finish ( &context->md_ctx, hmac ) != 0 )
    {
        return -1;
    }

    if ( context->internal->write_complete ( context->internal, hmac, sizeof ( hmac ) ) < 0 )
    {
        return -1;
    }

    if ( context->internal->flush ( context->internal ) < 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Close AES stream
 */
static void aes_stream_close ( struct io_stream_t *io )
{
    struct aes_stream_context_t *context;

    context = ( struct aes_stream_context_t * ) io->context;

    mbedtls_aes_free ( &context->aes );
    mbedtls_md_free ( &context->md_ctx );
    context->internal->close ( context->internal );
    free ( io );
}

/**
 * Create new input AES stream
 */
struct io_stream_t *input_aes_stream_new ( struct io_stream_t *internal, const char *password )
{
    struct io_stream_t *io;
    struct aes_stream_context_t *context;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    uint8_t ekey[AES256_KEYLEN];
    uint8_t hkey[AES256_KEYLEN];
    uint8_t nonce[NONCE_LEN];

    if ( !( context =
            ( struct aes_stream_context_t * ) malloc ( sizeof ( struct aes_stream_context_t ) ) ) )
    {
        return NULL;
    }

    context->eof = 0;
    context->unconsumed_len = 0;
    context->internal = internal;

    if ( context->internal->read_complete ( context->internal, context->esalt,
            sizeof ( context->esalt ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( context->internal->read_complete ( context->internal, context->hsalt,
            sizeof ( context->hsalt ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( context->internal->read_complete ( context->internal, context->iv,
            sizeof ( context->iv ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( context->internal->read_complete ( context->internal, nonce, sizeof ( nonce ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( aes_stream_derive_key ( password, context->esalt, sizeof ( context->esalt ), ekey,
            sizeof ( ekey ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    mbedtls_aes_init ( &context->aes );

    if ( mbedtls_aes_setkey_dec ( &context->aes, ekey, AES256_KEYLEN_BITS ) != 0 )
    {
        memset ( ekey, '\0', sizeof ( ekey ) );
        mbedtls_aes_free ( &context->aes );
        free ( context );
        return NULL;
    }

    memset ( ekey, '\0', sizeof ( ekey ) );

    if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_DECRYPT, sizeof ( nonce ), context->iv,
            nonce, nonce ) != 0 )
    {
        mbedtls_aes_free ( &context->aes );
        free ( context );
        return NULL;
    }

    if ( aes_stream_derive_key ( password, context->hsalt, sizeof ( context->hsalt ), hkey,
            sizeof ( hkey ) ) < 0 )
    {
        mbedtls_aes_free ( &context->aes );
        free ( context );
        return NULL;
    }

    mbedtls_md_init ( &context->md_ctx );

    if ( mbedtls_md_setup ( &context->md_ctx, mbedtls_md_info_from_type ( md_type ), 1 ) != 0 )
    {
        memset ( hkey, '\0', sizeof ( hkey ) );
        mbedtls_aes_free ( &context->aes );
        mbedtls_md_free ( &context->md_ctx );
        free ( context );
        return NULL;
    }

    if ( mbedtls_md_hmac_starts ( &context->md_ctx, hkey, sizeof ( hkey ) ) != 0 )
    {
        memset ( hkey, '\0', sizeof ( hkey ) );
        mbedtls_aes_free ( &context->aes );
        mbedtls_md_free ( &context->md_ctx );
        free ( context );
        return NULL;
    }

    memset ( hkey, '\0', sizeof ( hkey ) );

    if ( context->internal->read_complete ( context->internal, context->tail,
            sizeof ( context->tail ) ) < 0 )
    {
        mbedtls_aes_free ( &context->aes );
        mbedtls_md_free ( &context->md_ctx );
        free ( context );
        return NULL;
    }

    if ( !( io = io_stream_new (  ) ) )
    {
        mbedtls_aes_free ( &context->aes );
        mbedtls_md_free ( &context->md_ctx );
        free ( context );
        return NULL;
    }

    io->context = ( struct io_base_context_t * ) context;
    io->read = aes_stream_read;
    io->verify = aes_stream_verify;
    io->close = aes_stream_close;

    return io;
}

/**
 * Create new output AES stream
 */
struct io_stream_t *output_aes_stream_new ( struct io_stream_t *internal, const char *password )
{
    struct io_stream_t *io;
    struct aes_stream_context_t *context;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    uint8_t ekey[AES256_KEYLEN];
    uint8_t hkey[AES256_KEYLEN];
    uint8_t nonce[NONCE_LEN];

    if ( !( context =
            ( struct aes_stream_context_t * ) malloc ( sizeof ( struct aes_stream_context_t ) ) ) )
    {
        return NULL;
    }

    context->unconsumed_len = 0;
    context->internal = internal;

    if ( aes_stream_random_init ( context ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( aes_stream_random_bytes ( context, context->esalt, sizeof ( context->esalt ) ) < 0 )
    {
        aes_stream_random_free ( context );
        free ( context );
        return NULL;
    }

    if ( aes_stream_random_bytes ( context, context->hsalt, sizeof ( context->hsalt ) ) < 0 )
    {
        aes_stream_random_free ( context );
        free ( context );
        return NULL;
    }

    if ( aes_stream_random_bytes ( context, context->iv, sizeof ( context->iv ) ) < 0 )
    {
        aes_stream_random_free ( context );
        free ( context );
        return NULL;
    }

    if ( aes_stream_random_bytes ( context, nonce, sizeof ( nonce ) ) < 0 )
    {
        aes_stream_random_free ( context );
        free ( context );
        return NULL;
    }

    aes_stream_random_free ( context );

    if ( context->internal->write_complete ( context->internal, context->esalt,
            sizeof ( context->esalt ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( context->internal->write_complete ( context->internal, context->hsalt,
            sizeof ( context->hsalt ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( context->internal->write_complete ( context->internal, context->iv,
            sizeof ( context->iv ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    if ( aes_stream_derive_key ( password, context->esalt, sizeof ( context->esalt ), ekey,
            sizeof ( ekey ) ) < 0 )
    {
        free ( context );
        return NULL;
    }

    mbedtls_aes_init ( &context->aes );

    if ( mbedtls_aes_setkey_enc ( &context->aes, ekey, AES256_KEYLEN_BITS ) != 0 )
    {
        memset ( ekey, '\0', sizeof ( ekey ) );
        mbedtls_aes_free ( &context->aes );
        free ( context );
        return NULL;
    }

    memset ( ekey, '\0', sizeof ( ekey ) );

    if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_ENCRYPT, sizeof ( nonce ), context->iv,
            nonce, nonce ) != 0 )
    {
        mbedtls_aes_free ( &context->aes );
        free ( context );
        return NULL;
    }

    if ( context->internal->write_complete ( context->internal, nonce, sizeof ( nonce ) ) < 0 )
    {
        mbedtls_aes_free ( &context->aes );
        free ( context );
        return NULL;
    }

    if ( aes_stream_derive_key ( password, context->hsalt, sizeof ( context->hsalt ), hkey,
            sizeof ( hkey ) ) < 0 )
    {
        mbedtls_aes_free ( &context->aes );
        free ( context );
        return NULL;
    }

    mbedtls_md_init ( &context->md_ctx );

    if ( mbedtls_md_setup ( &context->md_ctx, mbedtls_md_info_from_type ( md_type ), 1 ) != 0 )
    {
        memset ( hkey, '\0', sizeof ( hkey ) );
        mbedtls_aes_free ( &context->aes );
        mbedtls_md_free ( &context->md_ctx );
        free ( context );
        return NULL;
    }

    if ( mbedtls_md_hmac_starts ( &context->md_ctx, hkey, sizeof ( hkey ) ) != 0 )
    {
        memset ( hkey, '\0', sizeof ( hkey ) );
        mbedtls_aes_free ( &context->aes );
        mbedtls_md_free ( &context->md_ctx );
        free ( context );
        return NULL;
    }

    memset ( hkey, '\0', sizeof ( hkey ) );

    if ( !( io = io_stream_new (  ) ) )
    {
        mbedtls_aes_free ( &context->aes );
        mbedtls_md_free ( &context->md_ctx );
        free ( context );
        return NULL;
    }

    io->context = ( struct io_base_context_t * ) context;
    io->write = aes_stream_write;
    io->flush = aes_stream_flush;
    io->close = aes_stream_close;

    return io;
}

/**
 * Split input AES stream
 */
int input_aes_stream_split ( struct io_stream_t *io, const char *password )
{
    int update_keys = 0;
    struct aes_stream_context_t *context;
    mbedtls_md_type_t md_type = MBEDTLS_MD_SHA256;
    uint8_t ekey[AES256_KEYLEN];
    uint8_t hkey[AES256_KEYLEN];
    uint8_t nonce[NONCE_LEN];
    uint8_t tmp_esalt[AES256_KEYLEN];
    uint8_t tmp_hsalt[AES256_KEYLEN];

    context = ( struct aes_stream_context_t * ) io->context;

    context->eof = 0;
    context->unconsumed_len = 0;

    if ( context->internal->read_complete ( context->internal, tmp_esalt,
            sizeof ( tmp_esalt ) ) < 0 )
    {
        return -1;
    }

    if ( context->internal->read_complete ( context->internal, tmp_hsalt,
            sizeof ( tmp_hsalt ) ) < 0 )
    {
        return -1;
    }

    if ( context->internal->read_complete ( context->internal, context->iv,
            sizeof ( context->iv ) ) < 0 )
    {
        return -1;
    }

    if ( context->internal->read_complete ( context->internal, nonce, sizeof ( nonce ) ) < 0 )
    {
        return -1;
    }

    if ( memcmp ( tmp_esalt, context->esalt, AES256_KEYLEN ) != 0 ||
        memcmp ( tmp_hsalt, context->hsalt, AES256_KEYLEN ) != 0 )
    {
        memcpy ( context->esalt, tmp_esalt, AES256_KEYLEN );
        memcpy ( context->hsalt, tmp_hsalt, AES256_KEYLEN );
        update_keys = 1;
    }

    if ( update_keys )
    {
        if ( aes_stream_derive_key ( password, context->esalt, sizeof ( context->esalt ), ekey,
                sizeof ( ekey ) ) < 0 )
        {
            return -1;
        }

        mbedtls_aes_free ( &context->aes );
        mbedtls_aes_init ( &context->aes );

        if ( mbedtls_aes_setkey_dec ( &context->aes, ekey, AES256_KEYLEN_BITS ) != 0 )
        {
            memset ( ekey, '\0', sizeof ( ekey ) );
            return -1;
        }

        memset ( ekey, '\0', sizeof ( ekey ) );
    }

    if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_DECRYPT, sizeof ( nonce ), context->iv,
            nonce, nonce ) != 0 )
    {
        return -1;
    }

    if ( update_keys )
    {
        if ( aes_stream_derive_key ( password, context->hsalt, sizeof ( context->hsalt ), hkey,
                sizeof ( hkey ) ) < 0 )
        {
            return -1;
        }

        mbedtls_md_free ( &context->md_ctx );
        mbedtls_md_init ( &context->md_ctx );

        if ( mbedtls_md_setup ( &context->md_ctx, mbedtls_md_info_from_type ( md_type ), 1 ) != 0 )
        {
            memset ( hkey, '\0', sizeof ( hkey ) );
            return -1;
        }

        if ( mbedtls_md_hmac_starts ( &context->md_ctx, hkey, sizeof ( hkey ) ) != 0 )
        {
            memset ( hkey, '\0', sizeof ( hkey ) );
            return -1;
        }

        memset ( hkey, '\0', sizeof ( hkey ) );

    } else
    {
        mbedtls_md_hmac_reset ( &context->md_ctx );
    }

    if ( context->internal->read_complete ( context->internal, context->tail,
            sizeof ( context->tail ) ) < 0 )
    {
        return -1;
    }

    return 0;
}

/**
 * Split output AES stream
 */
int output_aes_stream_split ( struct io_stream_t *io )
{
    struct aes_stream_context_t *context;
    uint8_t nonce[NONCE_LEN];

    context = ( struct aes_stream_context_t * ) io->context;

    context->unconsumed_len = 0;

    if ( aes_stream_random_init ( context ) < 0 )
    {
        return -1;
    }

    if ( aes_stream_random_bytes ( context, context->iv, sizeof ( context->iv ) ) < 0 )
    {
        aes_stream_random_free ( context );
        return -1;
    }

    if ( aes_stream_random_bytes ( context, nonce, sizeof ( nonce ) ) < 0 )
    {
        aes_stream_random_free ( context );
        return -1;
    }

    aes_stream_random_free ( context );

    if ( context->internal->write_complete ( context->internal, context->esalt,
            sizeof ( context->esalt ) ) < 0 )
    {
        return -1;
    }

    if ( context->internal->write_complete ( context->internal, context->hsalt,
            sizeof ( context->hsalt ) ) < 0 )
    {
        return -1;
    }

    if ( context->internal->write_complete ( context->internal, context->iv,
            sizeof ( context->iv ) ) < 0 )
    {
        return -1;
    }

    if ( mbedtls_aes_crypt_cbc ( &context->aes, MBEDTLS_AES_ENCRYPT, sizeof ( nonce ), context->iv,
            nonce, nonce ) != 0 )
    {
        return -1;
    }

    if ( context->internal->write_complete ( context->internal, nonce, sizeof ( nonce ) ) < 0 )
    {
        return -1;
    }

    mbedtls_md_hmac_reset ( &context->md_ctx );

    return 0;
}
#endif
