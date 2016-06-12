/*
 * crypto.h - Hearder file
 * Crypt or decrypt given block. XXTEA cipher is used.
 * Based on: 
 * David J. Wheeler and Roger M. Needham (October 1998). "Correction to XTEA".
 * Computer Laboratory, Cambridge University, England.
 * Author: Vlastimil Kosar <ikosar@fit.vutbr.cz> 
 */

#include <stdint.h>

#define BLOCK_SIZE 512
#define CRYPT_ATONCE_SIZE 128

#define S_KEY_LEN 32
#define S_KEY_CAP (S_KEY_LEN + 1)
#define S_PART_LEN 8
#define S_PART_CAP (S_PART_LEN + 1)
#define KEY_PARTS_COUNT 4

/*
 * Decrypt block by XXTEA.
 * Params:
 *   block - block of encrypted data
 *   len   - length of block
 *   key   - 128b key
 */
void xxdecrypt(uint32_t *block, uint32_t len, uint32_t *key);

/*
 * Crypt block by XXTEA.
 * Params:
 *   block - block of input data
 *   len   - length of block
 *   key   - 128b key
 */
void xxcrypt(uint32_t *block, uint32_t len, uint32_t *key);


void xxdecryptbin(char*data, uint32_t len, uint32_t *key);

void parseKey(char *keyChar, uint32_t *key);


