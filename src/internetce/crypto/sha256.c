/**
 * SHA256 module
 * Inspired from Ti romcalls (but with the correct endianness...)
 */

#include <stdint.h>
#include <stdbool.h>

#include "../include/crypto.h"
#include "../include/debug.h"
#include "../include/core.h"

/* Internal state variables */
static bool enabled = false;
static size_t total_bytes;
static uint8_t next_command;


bool sha256_IsEnabled() {
    return enabled;
}

web_status_t sha256_Init() {
    if(enabled) {
        dbg_warn("SHA256 module already initialized");
        return WEB_SHA256_IN_USE;
    }

    flash_unlock();

    enabled = true;
    *SHA256_ENABLE = 1;
    *SHA256_CTRL = 0x10;
    *SHA256_CTRL = 0;
    total_bytes = 0;
    next_command = SHA256_BEGIN_HASH;

    return WEB_SUCCESS;
}


web_status_t sha256_Part(const void *data, size_t size) {
    if(!enabled) {
        dbg_warn("SHA256 module not initialized");
        return WEB_SHA256_NOT_INITIALIZED;
    }

    uint32_t *data_array = (uint32_t *)data;
    size_t already_filled = total_bytes & 0x3F;

    // Just wanted to say thank you SHA256 chip for being little-endian *sigh*
    const uint8_t modulo = already_filled % 4;
    if(modulo != 0) {
        uint32_t mask_block, mask_data;
        switch(modulo) {
            case 1:
                mask_block = 0xff000000;
                mask_data  = 0x00ffffff;
                break;
            case 2:
                mask_block = 0xffff0000;
                mask_data  = 0x0000ffff;
                break;
            case 3:
                mask_block = 0xffffff00;
                mask_data  = 0x000000ff;
                break;
            default:
                /* Impossible */
                dbg_err("SHA256: impossible branch");
                return WEB_NOT_SUPPORTED;
        }
        SHA256_BLOCK[already_filled / 4] = (SHA256_BLOCK[already_filled / 4] & mask_block) | \
                                           ((htonl(data_array[0]) >> ((modulo) * 8)) & mask_data);
        data_array = (uint32_t *)(data + (4 - modulo));
        size -= 4 - modulo;
        already_filled += 4 - modulo;
        total_bytes += 4 - modulo;

        if(already_filled == 0x40) {
            already_filled = 0;
            *SHA256_CTRL = next_command;
            next_command = SHA256_CONTINUE_HASH;
            while((*SHA256_STATUS & 0b00001000) != 0);
        }
    }

    while(size != 0) {
        const size_t rem_size = min(0x40 - already_filled, size);
        for(size_t i = 0; i < (rem_size + 3) >> 2; i++) {
            SHA256_BLOCK[(already_filled >> 2) + i] = htonl(*data_array);
            data_array++;
        }

        size = size - rem_size;
        total_bytes += rem_size;
        already_filled += rem_size;
        if(already_filled == 0x40) {
            already_filled = 0;
            *SHA256_CTRL = next_command;
            next_command = SHA256_CONTINUE_HASH;
            while((*SHA256_STATUS & 0b00001000) != 0);
        } else if(already_filled > 0x40) {
            dbg_err("already_filled > 0x40");
        }
    }

    return WEB_SUCCESS;
}


web_status_t sha256_Hash(void *dst) {
    if(!enabled) {
        dbg_warn("SHA256 module not initialized");
        return WEB_SHA256_NOT_INITIALIZED;
    }

    const uint32_t total_bits_be = htonl(total_bytes << 3);
    const int modulo = total_bytes & 0x3F;
    if(modulo < 0x38) {
        const uint8_t tail[0x3c] = {0x80, 0};
        sha256_Part(tail, 0x3c - modulo);
    } else {
        const uint8_t tail[0x7c] = {0x80, 0};
        sha256_Part(tail, 0x7c - modulo);
    }    

    sha256_Part(&total_bits_be, sizeof(uint32_t));

    *SHA256_CTRL = 9;

    uint32_t *dst_array = (uint32_t *)dst;
    for(int i = 0; i < 0x20 / 4; i++) {
        dst_array[i] = ntohl(SHA256_HASH_DATA[i]);
    }

    *SHA256_ENABLE = 0;
    enabled = false;

    flash_lock();

    return WEB_SUCCESS;
}
