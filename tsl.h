#pragma once

/*
3.7.28.14
*/

/*
precomp.h:

#pragma once

#define WIN32_LEAN_AND_MEAN
#include <Windows.h>

#include <malloc.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
*/
#include "precomp.h"

typedef uint64_t(*decrypt_func)(uint64_t);

struct tsl {
	decrypt_func func;
};

int tsl_init(struct tsl *tsl);
void tsl_finit(struct tsl *tsl);
uint64_t tsl_decrypt_world(struct tsl *tsl, uint64_t world);
uint64_t tsl_decrypt_gnames(struct tsl *tsl, uint64_t gnames);
uint64_t tsl_decrypt_actor(struct tsl *tsl, uint64_t actor);
uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop);
