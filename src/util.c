/* ------------------------------------------------------------------
 * SBox - Misc Utility Stuff
 * ------------------------------------------------------------------ */

#include "xcbackup.h"

/**
 * Show operation progress with current file path
 */
void show_progress ( char action, const char *path )
{
    printf ( " %c %s\n", action, path );
}

/**
 * SBox archive prefix
 */
const uint8_t xcbackup_archive_prefix[ARCHIVE_PREFIX_LENGTH] = {
    0xe2, 0xec, 0x3e, 0x46, 0xc4, 0x20, 0x2e, 0x99,
    0x8a, 0x61, 0x5e, 0x3b, 0x0c, 0xa7, 0x4a, 0x7b
};

/**
 * SBox archive postifx
 */
const uint8_t xcbackup_archive_postfix[ARCHIVE_PREFIX_LENGTH] = {
    0x98, 0x8a, 0x01, 0x84, 0xe7, 0x4e, 0xb5, 0xa9,
    0x2a, 0xd3, 0xb4, 0x7e, 0xa1, 0x0d, 0xa8, 0xd5
};
