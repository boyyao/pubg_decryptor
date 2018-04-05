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

#define TABLE 0x3c72120

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
	uint32_t x; // uint16_t
	uint32_t y;
	uint16_t z;
	x = key >> 16;
	if (key & 0x40000) {
		y = ~(~x - 189);
	}
	else {
		IDA_LOWORD(y) = x + 126;
	}
	z = ror2(key - 11, 11) ^ ((uint16_t)y + 63931);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((ror1(z + 29, -29) ^ (ror1(BYTE1(z) + 19, -19) + 202)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(key ^ rol8(xmm.high - key, key & 7));
	memset(tsl->func, 0, 0x400);
	return ror8(ret, -49);
}

uint64_t tsl_decrypt_actor(struct tsl *tsl, uint64_t actor) {
	struct uint128_t xmm;
	if (!READ(actor, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x = rol2(key - 58, -58) ^ (ror2(WORD1(key), 110) + 33318);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((((uint8_t)~(~BYTE1(x) + 86) + 52) ^ rol1((rol2(key - 58, -58) ^ (ror2(WORD1(key), 110) + 38)) - 10, -10)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(ror8(xmm.high, key & 7) + key);
	memset(tsl->func, 0, 0x400);
	return ror8(ret, -114);
}

uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop) {
	struct uint128_t xmm;
	if (!READ(prop, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x;
	uint16_t y;
	uint8_t z;
	uint8_t w;
	uint64_t q;
	if (key & 1) {
		x = rol2(key, 127);
	}
	else {
		x = ror2(key, 127);
	}
	y = x ^ ((uint16_t)(WORD1(key) ^ 0x63) + 62831);
	z = x ^ ((BYTE2(key) ^ 0x63) + 111);
	if (((uint8_t)x ^ (uint8_t)((BYTE2(key) ^ 0x63) + 111)) & 1) {
		w = rol1(z, -9);
	}
	else {
		w = ror1(z, -9);
	}
	if (key & 2) {
		q = xmm.high - key;
	}
	else {
		q = key + xmm.high;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((w ^ ((uint8_t)(BYTE1(y) - 103) + 98)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(~q);
	memset(tsl->func, 0, 0x400);
	return ror8(ret, -77);
}
