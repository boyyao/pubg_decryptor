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
// extern uint64_t g_base_addr
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

#define TABLE 0x3c54120

struct uint128_t {
	uint64_t low;
	uint64_t high;
};

uint64_t tsl_decrypt_world(struct tsl *tsl, uint64_t world) {
	struct uint128_t xmm;
	READ(world, &xmm, 16);
	uint32_t index = (uint32_t)xmm.low;
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (((uint8_t)(((index - 101) ^ (~(~BYTE2(index) - 113) - 75)) - 13) ^ ((uint8_t)(((uint16_t)((index - 101) ^ (~(~WORD1(index) - 113) - 10315)) >> 8) + 35) + 86)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(~(~xmm.high ^ index));
	memset(tsl->func, 0, 0x800);
	return ror8(ret, -31);
}

uint64_t tsl_decrypt_actor(struct tsl *tsl, uint64_t actor) {
	struct uint128_t xmm;
	READ(actor, &xmm, 16);
	uint32_t index = (uint32_t)xmm.low;
	uint16_t x = rol2(index, 32) ^ (ror2(WORD1(index) - 96, -96) + 24608);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * ((rol1(rol2(index, 32) ^ (ror2(WORD1(index) - 96, -96) + 32), 32) ^ (ror1(BYTE1(x) - 32, -32) + 192)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(xmm.high - index);
	memset(tsl->func, 0, 0x800);
	return ror8(ret, -96);
}

uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop) {
	struct uint128_t xmm;
	READ(prop, &xmm, 16);
	uint32_t index = (uint32_t)xmm.low;
	uint32_t x;
	uint16_t y;
	uint16_t z;
	if (index & 4) {
		x = ~(~(uint16_t)index + 117);
	}
	else {
		IDA_LOWORD(x) = index - 78;
	}
	y = (uint16_t)x ^ (ror2(WORD1(index), -107) + 54121);
	z = (uint8_t)(x ^ (ror2(WORD1(index), -107) + 105));
	if (((uint8_t)x ^ (uint8_t)(ror2(WORD1(index), -107) + 105)) & 4) {
		z = ~(~z - 99);
	}
	else {
		IDA_LOBYTE(z) = z + 66;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (((uint8_t)z ^ (ror1(BYTE1(y) + 49, -49) + 238)) % 128));
	if (!make_decrypt_func(tsl, func)) {
		return 0;
	}
	uint64_t ret = tsl->func(rol8(xmm.high, index & 7) - index);
	memset(tsl->func, 0, 0x800);
	return ror8(ret, -59);
}
