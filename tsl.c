#include "tsl.h"

int tsl_init(struct tsl *tsl) {
	tsl->func = (decrypt_func)VirtualAlloc(NULL, 0x400, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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
#define DWORDn(x, n) (*((DWORD *)&(x) + n))

#define IDA_LOBYTE(x) BYTEn(x, 0)
#define IDA_LOWORD(x) WORDn(x, 0)
#define IDA_LODWORD(x) WORDn(x, 0)
#define IDA_HIBYTE(x) BYTEn(x, 1)
#define IDA_HIWORD(x) WORDn(x, 1)
#define IDA_HIDWORD(x) DWORDn(x, 1)

#define BYTE1(x) BYTEn(x, 1)
#define BYTE2(x) BYTEn(x, 2)
#define WORD1(x) WORDn(x, 1)
#define DWORD1(x) DWORDn(x, 1)

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

// macro

// bool read_size(uint64_t src, void *dest, size_t size)
#define READ(src, dest, size) mem->read_size(src, dest, size)
// template<typename T> T read(uint64_t addr)
#define READ32(addr) mem->read<uint32_t>(addr)
#define READ64(addr) mem->read<uint64_t>(addr)

#define GET_ADDR(addr) (g_base_addr + addr)

// credit: DirtyFrank

static uint32_t get_func_len(struct tsl *tsl, uint64_t func, uint8_t start, uint32_t end) {
	uint8_t buf[0x80];
	if (READ(func, buf, sizeof(buf))) {
		if (buf[0] == start) {
			uint32_t len = 0;
			for (; len < (sizeof(buf) - sizeof(end)); len++) {
				if (*(uint32_t *)(buf + len) == end) {
					return len;
				}
			}
		}
	}
	return 0;
}

static int make_decrypt_func(struct tsl *tsl, uint64_t func) {
	uint64_t x = (func + 14) + READ32(func + 10);
	uint32_t len = get_func_len(tsl, x, 0x48, 0xccccccc3);
	if (!len || len > 0xf) {
		return 0;
	}
	if (!READ(func, tsl->func, 9) ||
		!READ(x, (char *)tsl->func + 9, len) ||
		!READ(func + 14, (char *)tsl->func + 9 + len, 0x50)) {
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
	if (!READ(world, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x;
	uint16_t y;
	uint8_t z;
	uint8_t w;
	uint8_t q;
	uint64_t e;
	if (key & 1) {
		x = rol2(key, 95);
	}
	else {
		x = ror2(key, 95);
	}
	y = x ^ (ror2(WORD1(key) + 61, -61) + 38223);
	z = x ^ (ror2(WORD1(key) + 61, -61) + 79);
	if (((uint8_t)x ^ (uint8_t)(ror2(WORD1(key) + 61, -61) + 79)) & 1) {
		w = rol1(z, -41);
	}
	else {
		w = ror1(z, -41);
	}
	q = w ^ ((uint8_t)(BYTE1(y) + 71) + 162);
	if (key & 2) {
		e = xmm.high - key;
	}
	else {
		e = key + xmm.high;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (q % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(~e);
	memset(tsl->func, 0, 0x400);
	return ror8(ret, 19);
}

uint64_t tsl_decrypt_actor(struct tsl *tsl, uint64_t actor) {
	struct uint128_t xmm;
	if (!READ(actor, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x = (uint16_t)~((~(uint16_t)key - 26) ^ 0x1A) ^ ((uint16_t)(IDA_HIWORD(key) + 14) + 7866);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (((uint8_t)~((~(~((~(uint8_t)key - 26) ^ 0x1A) ^ (BYTE2(key) - 56)) + 22) ^ 0xEA) ^ (rol1(BYTE1(x), 118) + 12)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(key + rol8(key + xmm.high, key & 7));
	memset(tsl->func, 0, 0x400);
	return ror8(ret, -46);
}

uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop) {
	struct uint128_t xmm;
	if (!READ(prop, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x;
	uint16_t y;
	uint16_t z;
	uint8_t w;
	uint16_t q;
	uint8_t e;
	uint16_t r;
	x = key >> 16;
	if (key & 0x10000) {
		y = rol2(x, -25);
	}
	else {
		y = ror2(x, -25);
	}
	z = ror2(key + 45, -45) ^ (y + 37123);
	w = z + 21;
	q = z >> 8;
	e = ror1(w, -21);
	if (q & 4) {
		r = ~(~(uint8_t)q - 303);
	}
	else {
		IDA_LOBYTE(r) = q - 54;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((e ^ ((uint8_t)r + 58)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(~(~xmm.high - key));
	memset(tsl->func, 0, 0x400);
	return ror8(ret, -9);
}
