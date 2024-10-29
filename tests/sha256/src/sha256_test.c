/**
 *	Autotest for SHA256 collection
 *  Warning: It cannot be used in CLI as CEmu does not emulate the SHA256 chip in this case.
 *  The autotest.json file must be provided directly to the GUI autotest dock of CEmu.
 */

#include <stdint.h>
#include <tice.h>
#include <string.h>

#include "../../../src/internetce/include/crypto.h"

#define TEST_1 "Les sanglots longs des violons de l'automne blessent mon coeur d'une langueur monotone."
#define TEST_2 ""  /* empty */
#define TEST_3 "Les sondages c'est pour que les gens sachent ce qu'ils pensent" /* Edge case because it fits in 64 bytes but the size doesn't */
#define TEST_4 "Aucune loi n'oblige les dieux à être justes, Achille, reprit Chiron. Et après tout, peut-être que l'ultime chagrin consiste à se retrouver seul sur terre une fois que l'autre est parti."
#define TEST_5 {0}  /* Edge case: exactly 56 bytes */
#define TEST_6 /* Edge case: exactly 55 bytes */


int main(void)
{
    uint8_t *out = (uint8_t *)(0xd40000 + 320*240*2 - 32);  // Should be safe enough

    flash_setup();

    sha256_Init();
    sha256_Part((uint8_t *)TEST_1, strlen(TEST_1));
    sha256_Hash(out);
    while(!os_GetCSC());

    sha256_Init();
    sha256_Part((uint8_t *)TEST_2, strlen(TEST_2));
    sha256_Hash(out);
    while(!os_GetCSC());

    sha256_Init();
    sha256_Part((uint8_t *)TEST_3, strlen(TEST_3));
    sha256_Hash(out);
    while(!os_GetCSC());

    sha256_Init();
    sha256_Part((uint8_t *)TEST_4, strlen(TEST_4));
    sha256_Hash(out);
    while(!os_GetCSC());

    uint8_t test5[56] = TEST_5;
    sha256_Init();
    sha256_Part(test5, 56);
    sha256_Hash(out);
    while(!os_GetCSC());

    uint8_t test6[55];
    memset(test6, 'A', 55);
    sha256_Init();
    sha256_Part(test6, 55);
    sha256_Hash(out);
    while(!os_GetCSC());
	
    return 0;
}
