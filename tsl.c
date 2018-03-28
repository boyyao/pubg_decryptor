#include "tsl.h"

int tsl_init(struct tsl *tsl) {
	tsl->func = (decrypt_func)VirtualAlloc(NULL, 0x800, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (tsl->func == NULL) {
		return 0;
	}
	return 1;
}

void tsl_finit(struct tsl *tsl) {
	if (tsl->func != NULL) {
		VirtualFree(tsl->func, 0, MEM_RELEASE);
		tsl->func = NULL;
	}
}

// ida

#define BYTEn(x, n) (*((BYTE *)&(x) + n))
#define WORDn(x, n) (*((WORD *)&(x) + n))

#define IDA_LOBYTE(x) BYTEn(x, 0)
#define IDA_LOWORD(x) WORDn(x, 0)

#define WORD1(x) WORDn(x, 1)
#define BYTE1(x) BYTEn(x, 1)
#define BYTE2(x) BYTEn(x, 2)

// rotate

static uint8_t rol1(uint8_t x, unsigned int count) {
	count %= 8;
	return (x << count) | (x >> (8 - count));
}

static uint16_t rol2(uint16_t x, unsigned int count) {
	count %= 16;
	return (x << count) | (x >> (16 - count));
}

static uint32_t rol4(uint32_t x, unsigned int count) {
	count %= 32;
	return (x << count) | (x >> (32 - count));
}

static uint64_t rol8(uint64_t x, unsigned int count) {
	count %= 64;
	return (x << count) | (x >> (64 - count));
}

static uint8_t ror1(uint8_t x, unsigned int count) {
	count %= 8;
	return (x << (8 - count)) | (x >> count);
}

static uint16_t ror2(uint16_t x, unsigned int count) {
	count %= 16;
	return (x << (16 - count)) | (x >> count);
}

static uint32_t ror4(uint32_t x, unsigned int count) {
	count %= 32;
	return (x << (32 - count)) | (x >> count);
}

static uint64_t ror8(uint64_t x, unsigned int count) {
	count %= 64;
	return (x << (64 - count)) | (x >> count);
}

// macro for uc!

// bool read_size(uint64_t src, void *dest, size_t size) {...}
#define READ(src, dest, size) mem->read_size(src, dest, size)
// template<typename T> read(uint64_t addr)
#define READ32(addr) mem->read<uint32_t>(addr)
#define READ64(addr) mem->read<uint64_t>(addr)

#define GET_ADDR(addr) (g_base_addr + addr)

// credit: https://www.unknowncheats.me/forum/members/2235736.html

static uint32_t get_func_len(struct tsl *tsl, uint64_t func, uint8_t end) {
	uint8_t buf[0x80];
	if (READ(func, buf, sizeof(buf))) {
		uint32_t len = 0;
		for (; len < sizeof(buf); len++) {
			if (buf[len] == end) {
				return len;
			}
		}
	}
	return 0;
}

static int make_decrypt_func(struct tsl *tsl, uint64_t func) {
	if (!READ(func, tsl->func, 9)) {
		return 0;
	}
	uint32_t delta = READ32(func + 10);
	uint32_t len = get_func_len(tsl, func + 14 + delta, 0xc3);
	if (!READ(func + 14 + delta, (char *)tsl->func + 9, len)) {
		return 0;
	}
	if (!READ(func + 14, (char *)tsl->func + 9 + len, 0x46)) {
		return 0;
	}
	return 1;
}

// exports

#define TABLE 0x3c53120

struct uint128_t {
	uint64_t low;
	uint64_t high;
};

uint64_t tsl_decrypt_world(struct tsl *tsl, uint64_t world) {
	struct uint128_t xmm;
	READ(world, &xmm, 16);
	uint32_t index = (uint32_t)xmm.low;
	uint16_t x;
	uint8_t y;
	uint8_t z;
	uint8_t w;
	uint16_t q;
	uint8_t e;
	uint64_t r;
	x = rol2(index - 34, -34) ^ ((WORD1(index) ^ 0x26) + 35518);
	y = x - 50;
	z = x >> 8;
	w = rol1(y, -50);
	if (z & 4) {
		q = ~(~z - 246);
	}
	else {
		IDA_LOBYTE(q) = z - 92;
	}
	e = w ^ ((uint8_t)q + 4);
	if (index & 2) {
		r = xmm.high ^ index;
	}
	else {
		r = xmm.high + index;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (e % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(r);
	memset(tsl->func, 0, 0x800);
	return ror8(ret, -58);
}

uint64_t tsl_decrypt_actor(struct tsl *tsl, uint64_t actor) {
	struct uint128_t xmm;
	READ(actor, &xmm, 16);
	uint32_t index = (uint32_t)xmm.low;
	uint32_t x;
	uint32_t y;
	uint16_t z;
	uint16_t w;
	if (index & 4) {
		x = ~(~(uint16_t)index + 309);
	}
	else {
		IDA_LOWORD(x) = index - 206;
	}
	y = index >> 16;
	if (index & 0x40000) {
		y = ~(~y - 255);
	}
	else {
		IDA_LOWORD(y) = y + 170;
	}
	z = (uint16_t)x ^ ((uint16_t)y + 4905);
	w = (uint8_t)(x ^ (y + 41));
	if (z & 4) {
		w = ~(~w + 93);
	}
	else {
		IDA_LOBYTE(w) = w - 62;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (((uint8_t)w ^ ((BYTE1(z) + 15) + 110)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(rol8(xmm.high, index & 7) - index);
	memset(tsl->func, 0, 0x800);
	return ror8(ret, -123);
}

uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop) {
	struct uint128_t xmm;
	READ(prop, &xmm, 16);
	uint32_t index = (uint32_t)xmm.low;
	uint16_t x = ror2(index + 82, 82) ^ (~(~WORD1(index) - 74) + 34418);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((ror1((ror2(index + 82, 82) ^ (~(~BYTE2(index) - 74) + 114)) - 30, -30) ^ (ror1(BYTE1(x), -2) + 156)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(xmm.high ^ index);
	memset(tsl->func, 0, 0x800);
	return ror8(ret, -86);
}
