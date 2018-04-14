#include "tsl.h"

int tsl_init(struct tsl *tsl) {
	tsl->func = (decrypt_func)VirtualAlloc(NULL, 0x400, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	return tsl->func == NULL ? 0 : 1;
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

struct rel_addr {
	uint32_t offset;
	uint32_t addr;
};

static int get_func_rel_addr(struct tsl *tsl, uint64_t func, struct rel_addr *ret) {
	uint8_t buf[0xf0];
	if (READ(func, buf, sizeof(buf))) {
		uint32_t offset = 0;
		for (; offset < sizeof(buf) - 5; offset++) {
			if (buf[offset] == 0xe8) {
				uint32_t addr = *(uint32_t *)(buf + (offset + 1));
				if (addr < 0x7fff) {
					ret->offset = offset + 5;
					ret->addr = addr;
					return 1;
				}
			}
		}
	}
	return 0;
}

static uint32_t get_func_len(struct tsl *tsl, uint64_t func, uint8_t start, uint32_t end) {
	uint8_t buf[0x20];
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

static uint64_t call_decrypt_func(struct tsl *tsl, uint64_t func, uint64_t arg) {
	struct rel_addr rel_addr;
	if (!get_func_rel_addr(tsl, func, &rel_addr)) {
		return 0;
	}
	uint64_t abs_addr = func + (rel_addr.offset + rel_addr.addr);
	uint32_t len = get_func_len(tsl, abs_addr, 0x48, 0xccccccc3);
	if (!len || len > 0xf) {
		return 0;
	}
	uint32_t before_call = rel_addr.offset - 5;
	if (!READ(func, tsl->func, before_call) ||
		!READ(abs_addr, (char *)tsl->func + before_call, len) ||
		!READ(func + rel_addr.offset, (char *)tsl->func + (before_call + len), 0xf0 - rel_addr.offset)) {
		return 0;
	}
	uint64_t ret = tsl->func(arg);
	memset(tsl->func, 0, 0x400);
	return ret;
}

// exports

#define TABLE 0x3e74120

struct uint128_t {
	uint64_t low;
	uint64_t high;
};

uint64_t tsl_decrypt_world(struct tsl *tsl, uint64_t world) {
	return 0;
}

uint64_t tsl_decrypt_gnames(struct tsl *tsl, uint64_t gnames) {
	return 0;
}

uint64_t tsl_decrypt_actor(struct tsl *tsl, uint64_t actor) {
	struct uint128_t xmm;
	if (!READ(actor, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x;
	uint16_t y;
	uint32_t z;
	if (key & 4) {
		x = ~(~(uint16_t)key - 267);
	}
	else {
		x = key + 178;
		x = (INT16)x;
	}
	y = (uint16_t)x ^ ((uint16_t)(IDA_HIWORD(key) - 21) + 21481);
	z = (uint8_t)(x ^ (BYTE2(key) - 44));
	if (z & 4) {
		z = ~(~z + 285);
	}
	else {
		z = z + 66;
		z = (uint8_t)z;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 8 * (((uint8_t)z ^ ((uint8_t)(BYTE1(y) - 79) + 238)) % 128));
	return ror8(call_decrypt_func(tsl, func, (rol8(xmm.high, 8 * (key & 7)) - key)), 69);
}

uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop) {
	struct uint128_t xmm;
	if (!READ(prop, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint32_t x;
	if (((uint16_t)((key + 18) ^ (WORD1(key) - 14798)) >> 8) & 4) {
		x = ~(~(uint8_t)((uint16_t)((key + 18) ^ (WORD1(key) - 14798)) >> 8) - 186);
	}
	else {
		x = ((uint16_t)((key + 18) ^ (WORD1(key) - 14798)) >> 8) + 124;
		x = (uint8_t)x;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 8 * (((uint8_t)(((key + 18) ^ (BYTE2(key) + 50)) - 94) ^ ((uint8_t)x + 28)) % 128));
	return ror8(call_decrypt_func(tsl, func, xmm.high ^ key), 106);
}
