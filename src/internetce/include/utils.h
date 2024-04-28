/**
 * Assembly functions
 */

#ifndef INTERNET_ASSEMBLY
#define INTERNET_ASSEMBLY


#include <stdint.h>
#include <tice.h>


/**
 * Assembly functions
 */

var_t *MoveToArc(const char* name);

var_t *MoveToRam(const char* name);

bool os_EnoughMem(size_t mem);

int ResizeAppVar(const char* name, size_t new_size); /* 1=the resizing happened, 0 if not */


#endif // INTERNET_ASSEMBLY
