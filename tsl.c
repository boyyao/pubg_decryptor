#include "tsl.h"

int tsl_init(struct tsl *tsl) {
	tsl->func = (decrypt_func)VirtualAlloc(NULL, 0x200, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
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

static int find_call(const uint8_t *buf, uint32_t size, struct rel_addr *ret) {
	uint32_t offset = 0;
	while (offset < (size - 5)) {
		if (buf[offset] == 0xe8) {
			uint32_t addr = *(uint32_t *)(buf + (offset + 1));
			if (addr < 0x8000) {
				ret->offset = offset + 5;
				ret->addr = addr;
				return 1;
			}
		}
		offset++;
	}
	return 0;
}

static uint32_t get_func_len(const uint8_t *buf, uint32_t size, uint8_t start, uint32_t end) {
	if (*buf == start) {
		uint32_t offset = 0;
		while (offset < (size - sizeof(end))) {
			if (*(uint32_t *)(buf + offset) == end) {
				return offset;
			}
			offset++;
		}
	}
	return 0;
}

static uint64_t decrypt(struct tsl *tsl, uint64_t func, uint64_t arg) {
	uint8_t buf_0x100[0x100];
	if (!READ(func, buf_0x100, 0x100)) {
		return 0;
	}
	struct rel_addr rel_addr;
	if (!find_call(buf_0x100, 0x100, &rel_addr)) {
		return 0;
	}
	uint64_t abs_addr = func + (rel_addr.offset + rel_addr.addr);
	uint8_t buf_0x20[0x20];
	if (!READ(abs_addr, buf_0x20, 0x20)) {
		return 0;
	}
	uint32_t len = get_func_len(buf_0x20, 0x20, 0x48, 0xccccccc3);
	if (!len || len > 0xf) {
		return 0;
	}
	uint32_t temp = rel_addr.offset - 5;
	memcpy(tsl->func, buf_0x100, temp);
	memcpy((char *)tsl->func + temp, buf_0x20, len);
	memcpy((char *)tsl->func + (temp + len), buf_0x100 + rel_addr.offset, 0x100 - rel_addr.offset);
	uint64_t ret = tsl->func(arg);
	memset(tsl->func, 0, 0x200);
	return ret;
}

// exports

#define TABLE 0x3ef3120

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
	uint32_t x;
	uint16_t y;
	uint32_t z;
	uint32_t w;
	uint32_t q;
	uint32_t e;
	uint8_t r;
	if (IDA_LOWORD(key) & 2) {
		x = ~(IDA_LOWORD(key) - 60);
		y = IDA_LOWORD(key) + 60;
	}
	else {
		IDA_LOWORD(x) = IDA_LOWORD(key) + 61;
		y = IDA_LOWORD(key) ^ 0x3C;
	}
	z = (uint16_t)(~y + x);
	w = z ^ ((uint16_t)~((~IDA_HIWORD(key) + 52) ^ 0xFFCC) + 38140);
	q = (uint8_t)(z ^ (~((~(uint8_t)IDA_HIWORD(key) + 52) ^ 0xCC) - 4));
	if (q & 2) {
		e = ~(q - 28);
		r = q + 28;
	}
	else {
		IDA_LOBYTE(e) = q + 29;
		r = q ^ 0x1C;
	}
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (((uint8_t)(~r + e) ^ ((uint8_t)~((~BYTE1(w) - 36) ^ 0x24) + 8)) % 128));
	return ror8(decrypt(tsl, func, rol8(xmm.high ^ key, 8 * (IDA_LOWORD(key) & 7u)) - key), 12);
}

uint64_t tsl_decrypt_prop(struct tsl *tsl, uint64_t prop) {
	struct uint128_t xmm;
	if (!READ(prop, &xmm, 16)) {
		return 0;
	}
	uint32_t key = (uint32_t)xmm.low;
	uint16_t x = (uint16_t)(IDA_LOWORD(key) - 53) ^ (rol2(IDA_HIWORD(key) + 1, 8) + 51077);
	uint64_t func = READ64(GET_ADDR(TABLE) + 0x8 * (((uint8_t)(((IDA_LOWORD(key) - 53) ^ (rol2(IDA_HIWORD(key) + 1, 8) - 123)) - 93) ^ ((uint8_t)(BYTE1(x) + 45) + 182)) % 128));
	return ror8(decrypt(tsl, func, ~(~xmm.high ^ key)), 113);
}
