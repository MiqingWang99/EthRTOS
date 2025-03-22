#ifndef SHA256_H
#define SHA256_H

#include <stddef.h>
#include <stdint.h>

/**
 * @brief SHA256 context structure.
 */
typedef struct {
    uint32_t state[8];     /**< State (ABCDEFGH) */
    uint64_t bitcount;     /**< Number of bits processed */
    uint8_t buffer[64];    /**< Data block being processed */
} SHA256_CTX;

/**
 * @brief Initialize the SHA256 context.
 *
 * @param ctx [in,out] Pointer to the SHA256 context.
 */
void sha256_init(SHA256_CTX *ctx);

/**
 * @brief Update the SHA256 context with new data.
 *
 * @param ctx [in,out] Pointer to the SHA256 context.
 * @param data [in] Pointer to input data.
 * @param len [in] Length of the input data.
 */
void sha256_update(SHA256_CTX *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalize the SHA256 hash computation.
 *
 * @param ctx [in,out] Pointer to the SHA256 context.
 * @param hash [out] Buffer (32 bytes) to receive the final hash.
 */
void sha256_final(SHA256_CTX *ctx, uint8_t hash[32]);

#endif // SHA256_H
