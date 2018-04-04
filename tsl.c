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
	uint32_t z; // uint16_t
	uint16_t w;
	x = ror2(key + 93, -93);
	y = key >> 16;
	if (key & 0x20000) {
		z = ~(y + 119) + ~(y - 119);
	}
	else {
		z = ~(y ^ 0x77) + y + 120;
	}
	w = x ^ ((uint16_t)z + 33235);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((ror1((x ^ (z - 45)) - 59, 59) ^ (rol1(BYTE1(w) + 21, 21) + 154)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(~(~xmm.high - key));
	memset(tsl->func, 0, 0x400);
	return ror8(ret, -121);
}

uint64_t tsl_decrypt_actor(struct tsl *tsl, uint64_t actor) {
	struct uint128_t xmm;
	if (!READ(actor, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x;
	uint64_t y;
	x = rol2(key + 94, 94) ^ (ror2(WORD1(key), -90) + 2622);
	if (key & 2) {
		y = xmm.high ^ key;
	}
	else {
		y = xmm.high + key;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((((uint8_t)~(~BYTE1(x) + 46) + 4) ^ rol1((rol2(key + 94, 94) ^ (ror2(WORD1(key), -90) + 62)) + 78, 78)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(y);
	memset(tsl->func, 0, 0x400);
	return ror8(ret, 70);
}

uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop) {
	struct uint128_t xmm;
	if (!READ(prop, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x = (uint16_t)(key + 23) ^ ((uint16_t)(WORD1(key) ^ 0xFF9B) + 32135);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (((uint8_t)(((key + 23) ^ ((BYTE2(key) ^ 0x9B) - 121)) + 79) ^ ((uint8_t)(BYTE1(x) - 63) + 50)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(ror8(xmm.high, key & 7) - key);
	memset(tsl->func, 0, 0x400);
	return ror8(ret, 107);
}
