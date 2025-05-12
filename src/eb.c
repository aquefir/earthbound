/* for memset */
#include <string.h>

/* BEGIN SHA-3 IMPLEMENTATION */

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ( (x) >> (64 - (y))))
#endif

struct sha3
{
	/* State: */
	union
	{
		/* byte-wise */
		__UINT8_TYPE__ b[200];
		/* word-wise */
		__UINT64_TYPE__ q[25];
	} st;
	/* these don't overflow */
	int pt, rsiz, mdlen;
};

/* Compression function */
void sha3_keccakf( __UINT64_TYPE__ st[25] );

/* OpenSSL-like interface */

/* mdlen = hash output in bytes */
int sha3_init( struct sha3 * c, int mdlen );

int sha3_update(
	struct sha3 * c,
	const void * data,
	__SIZE_TYPE__ len
);
/* digest goes to md */
int sha3_final( void * md, struct sha3 * c );

/* compute a sha3 hash (md) of given byte length from "in" */
void * sha3(
	const void * in,
	__SIZE_TYPE__ inlen,
	void * md,
	int mdlen
);

/* SHAKE128 and SHAKE256 extensible-output functions */
#define shake128_init(c) sha3_init(c, 16)
#define shake256_init(c) sha3_init(c, 32)
#define shake_update sha3_update

void shake_xof( struct sha3 * c );
void shake_out( struct sha3 * c, void * out, __SIZE_TYPE__ len );

/* constants */
static const __UINT64_TYPE__ keccakf_rndc[24] = {
	0x0000000000000001, 0x0000000000008082,
	0x800000000000808a, 0x8000000080008000,
	0x000000000000808b, 0x0000000080000001,
	0x8000000080008081, 0x8000000000008009,
	0x000000000000008a, 0x0000000000000088,
	0x0000000080008009, 0x000000008000000a,
	0x000000008000808b, 0x800000000000008b,
	0x8000000000008089, 0x8000000000008003,
	0x8000000000008002, 0x8000000000000080,
	0x000000000000800a, 0x800000008000000a,
	0x8000000080008081, 0x8000000000008080,
	0x0000000080000001, 0x8000000080008008
};

static const int keccakf_rotc[24] = {
	1, 3, 6, 10, 15, 21, 28, 36,
	45, 55, 2, 14, 27, 41, 56, 8,
	25, 43, 62, 18, 39, 61, 20, 44
};

static const int keccakf_piln[24] = {
	10, 7, 11, 17, 18, 3, 5, 16,
	8, 21, 24, 4, 15, 23, 19, 13,
	12, 2, 20, 14, 22, 9, 6, 1
};

/* update the state with given number of rounds */
void sha3_keccakf( __UINT64_TYPE__ st[25] )
{
	/* variables */
	int i, j, r;
	__UINT64_TYPE__ t, bc[5];

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	__UINT8_TYPE__ * v;

	/* endianess conversion. this is redundant on little-endian
	 * targets */
	for(i = 0; i < 25; ++i)
	{
		v = (__UINT8_TYPE__ *)&st[i];

		st[i] = ( (__UINT64_TYPE__)v[0] ) |
			( ( (__UINT64_TYPE__)v[1] ) << 8 ) |
			( ( (__UINT64_TYPE__)v[2] ) << 16 ) |
			( ( (__UINT64_TYPE__)v[3] ) << 24 ) |
			( ( (__UINT64_TYPE__)v[4] ) << 32 ) |
			( ( (__UINT64_TYPE__)v[5] ) << 40 ) |
			( ( (__UINT64_TYPE__)v[6] ) << 48 ) |
			( ( (__UINT64_TYPE__)v[7] ) << 56 );
	}
#endif

	/* actual iteration */
	for(r = 0; r < KECCAKF_ROUNDS; ++r)
	{
		/* Theta */
		for(i = 0; i < 5; ++i)
		{
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^
				st[i + 15] ^ st[i + 20];
		}

		for(i = 0; i < 5; ++i)
		{
			t = bc[( i + 4 ) % 5] ^
				ROTL64( bc[( i + 1 ) % 5], 1 );
			for(j = 0; j < 25; j += 5)
			{
				st[j + i] ^= t;
			}
		}

		/* Rho Pi */
		t = st[1];
		for(i = 0; i < 24; ++i)
		{
			j = keccakf_piln[i];

			bc[0] = st[j];
			st[j] = ROTL64( t, keccakf_rotc[i] );

			t = bc[0];
		}

		/* Chi */
		for(j = 0; j < 25; j += 5)
		{
			for(i = 0; i < 5; ++i)
			{
				bc[i] = st[j + i];
			}

			for(i = 0; i < 5; ++i)
			{
				st[j + i] ^= ( ~bc[( i + 1 ) % 5] ) &
					bc[( i + 2 ) % 5];
			}
		}

		/* Iota */
		st[0] ^= keccakf_rndc[r];
	}

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	/* endianess conversion. this is redundant on little-endian
	 * targets */
	for(i = 0; i < 25; ++i)
	{
		v = (__UINT8_TYPE__ *)&st[i];
		t = st[i];

		v[0] = t & 0xFF;
		v[1] = ( t >> 8 ) & 0xFF;
		v[2] = ( t >> 16 ) & 0xFF;
		v[3] = ( t >> 24 ) & 0xFF;
		v[4] = ( t >> 32 ) & 0xFF;
		v[5] = ( t >> 40 ) & 0xFF;
		v[6] = ( t >> 48 ) & 0xFF;
		v[7] = ( t >> 56 ) & 0xFF;
	}
#endif
}

/* Initialize the context for SHA3 */

int sha3_init( struct sha3 * c, int mdlen )
{
	int i;

	for(i = 0; i < 25; ++i)
	{
		c->st.q[i] = 0;
	}

	c->mdlen = mdlen;
	c->rsiz  = 200 - 2 * mdlen;
	c->pt    = 0;

	return 1;
}

/* update state with more data */

int sha3_update( struct sha3 * c, const void * data, __SIZE_TYPE__ len )
{
	__SIZE_TYPE__ i;
	int j = c->pt;

	for(i = 0; i < len; ++i)
	{
		c->st.b[j++] ^= ( (const __UINT8_TYPE__ *)data )[i];

		if(j >= c->rsiz)
		{
			sha3_keccakf( c->st.q );
			j = 0;
		}
	}

	c->pt = j;

	return 1;
}

/* finalize and output a hash */

int sha3_final( void * md, struct sha3 * c )
{
	int i;

	c->st.b[c->pt] ^= 0x06;
	c->st.b[c->rsiz - 1] ^= 0x80;

	sha3_keccakf( c->st.q );

	for(i = 0; i < c->mdlen; ++i)
	{
		( (__UINT8_TYPE__ *)md )[i] = c->st.b[i];
	}

	return 1;
}

/* compute a SHA-3 hash (md) of given byte length from "in" */

void * sha3(
const void * in,
__SIZE_TYPE__ inlen,
void * md,
int mdlen )
{
	struct sha3 sha3;

	sha3_init( &sha3, mdlen );
	sha3_update( &sha3, in, inlen );
	sha3_final( md, &sha3 );

	return md;
}

/* SHAKE128 and SHAKE256 extensible-output functionality */

void shake_xof( struct sha3 * c )
{
	c->st.b[c->pt] ^= 0x1F;
	c->st.b[c->rsiz - 1] ^= 0x80;

	sha3_keccakf( c->st.q );

	c->pt = 0;
}

void shake_out( struct sha3 * c, void * out, __SIZE_TYPE__ len )
{
	__SIZE_TYPE__ i;
	int j = c->pt;

	for(i = 0; i < len; ++i)
	{
		if(j >= c->rsiz)
		{
			sha3_keccakf( c->st.q );
			j = 0;
		}

		( (__UINT8_TYPE__ *)out )[i] = c->st.b[j++];
	}

	c->pt = j;
}

/* END SHA-3 IMPLEMENTATION */

/* BEGIN SHA-2 IMPLEMENTATION */

struct sha2 {
	__UINT8_TYPE__ *hash;
	__UINT8_TYPE__ chunk[64];
	__UINT8_TYPE__ *chunk_pos;
	__SIZE_TYPE__ space_left;
	__UINT64_TYPE__ total_len;
	__UINT32_TYPE__ h[8];
};

void calc_sha_256(
	__UINT8_TYPE__ hash[32],
	const void * input,
	__SIZE_TYPE__ len
);

void sha2_init(
	struct sha2 * sha256,
	__UINT8_TYPE__ hash[32]
);

void sha_256_write(
	struct sha2 * sha256,
	const void * data,
	__SIZE_TYPE__ len
);

 __UINT8_TYPE__ * sha_256_close(
	struct sha2 * sha256
);

/*
 * Initialize array of round constants:
 * (first 32 bits of the fractional parts of the cube roots of the first
 * 64 primes 2..311):
 */
 static const __UINT32_TYPE__ k[] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
	0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
	0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
	0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
	0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
	0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
	0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
	0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
	0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static inline __UINT32_TYPE__ right_rot(
__UINT32_TYPE__ value,
unsigned int count )
{
	/*
	 * Defined behaviour in standard C for all count where
	 * 0 < count < 32, which is what we need here.
	 */
	return value >> count | value << (32 - count);
}

static inline void sha2_internal(
__UINT32_TYPE__ *h,
const __UINT8_TYPE__ *p )
{
	unsigned i, j;
	__UINT32_TYPE__ ah[8];

	for(i = 0; i < 8; ++i)
	{
		ah[i] = h[i];
	}

	__UINT32_TYPE__ w[16];

	/* Compression function main loop: */
	for(i = 0; i < 4; i++)
	{
		for(j = 0; j < 16; ++j)
		{
			__UINT32_TYPE__ t1;
			w[j] = i == 0
				? (__UINT32_TYPE__)p[0] << 24
				| (__UINT32_TYPE__)p[1] << 16
				| (__UINT32_TYPE__)p[2] << 8
				| (__UINT32_TYPE__)p[3]
				: w[j]
				+ (right_rot(w[(j + 1) & 0xf], 7)
				^ right_rot(w[(j + 1) & 0xf], 18)
				^ (w[(j + 1) & 0xf] >> 3))
				+ w[(j + 9) & 0xf]
				+ (right_rot(w[(j + 14) & 0xf], 17)
				^ right_rot(w[(j + 14) & 0xf], 19)
				^ (w[(j + 14) & 0xf] >> 10));

			t1 = ah[7] + (right_rot(ah[4], 6)
				^ right_rot(ah[4], 11)
				^ right_rot(ah[4], 25))
				+ ((ah[4] & ah[5])
				^ (~ah[4] & ah[6])) + k[i << 4 | j]
				+ w[j];

			ah[7] = ah[6];
			ah[6] = ah[5];
			ah[5] = ah[4];
			ah[4] = ah[3] + t1;
			ah[3] = ah[2];
			ah[2] = ah[1];
			ah[1] = ah[0];
			ah[0] = t1 + (right_rot(ah[0], 2)
				^ right_rot(ah[0], 13)
				^ right_rot(ah[0], 22))
				+ (ah[0] & ah[1]) ^ (ah[0] & ah[2])
				^ (ah[1] & ah[2]);
		}
	}

	/* Add the compressed chunk to the current hash value: */
	for(i = 0; i < 8; ++i)
	{
		h[i] += ah[i];
	}
}

void sha2_init( struct sha2 *sha256, __UINT8_TYPE__ hash[32] )
{
	sha256->hash = hash;
	sha256->chunk_pos = sha256->chunk;
	sha256->space_left = 64;
	sha256->total_len = 0;
	/*
	 * Initialize hash values (first 32 bits of the fractional parts
	 * of the square roots of the first 8 primes  2..19):
	 */
	sha256->h[0] = 0x6a09e667;
	sha256->h[1] = 0xbb67ae85;
	sha256->h[2] = 0x3c6ef372;
	sha256->h[3] = 0xa54ff53a;
	sha256->h[4] = 0x510e527f;
	sha256->h[5] = 0x9b05688c;
	sha256->h[6] = 0x1f83d9ab;
	sha256->h[7] = 0x5be0cd19;
}

void sha2_update(
struct sha2 *sha256,
const void *data,
__SIZE_TYPE__ len )
{
	sha256->total_len += len;

	const __UINT8_TYPE__ *p = (const __UINT8_TYPE__ *)data;

	while(len > 0)
	{
		/*
		 * If the input chunks have sizes that are multiples of
		 * the calculation chunk size, no copies are  necessary.
		 * We operate directly on the input data instead.
		 */
		if(sha256->space_left == 64 && len >= 64)
		{
			sha2_internal(sha256->h, p);
			len -= 64;
			p += 64;

			continue;
		}

		/* General case; no particular optimization. */
		const __SIZE_TYPE__ consumed_len =
			len < sha256->space_left
			? len : sha256->space_left;

		memcpy(sha256->chunk_pos, p, consumed_len);

		sha256->space_left -= consumed_len;
		len -= consumed_len;
		p += consumed_len;

		if(sha256->space_left == 0)
		{
			sha2_internal(sha256->h, sha256->chunk);
			sha256->chunk_pos = sha256->chunk;
			sha256->space_left = 64;
		}
		else
		{
			sha256->chunk_pos += consumed_len;
		}
	}
}

__UINT8_TYPE__ *sha2_final( struct sha2 *sha256 )
{
	__UINT8_TYPE__ * pos = sha256->chunk_pos;
	__UINT8_TYPE__ * hash;
	__SIZE_TYPE__ space_left = sha256->space_left;
	__UINT32_TYPE__ * const h = sha256->h;
	__SIZE_TYPE__ left;
	__UINT64_TYPE__ len;
	int i, j;

	/*
	 * The current chunk cannot be full. Otherwise, it would already
	 * have been consumed. I.e. there is space left for at least one
	 * byte. The next step in the calculation is to add a single
	 * one-bit to the data.
	 */
	*pos++ = 0x80;
	--space_left;

	/*
	 * Now, the last step is to add the total data length at the end
	 * of the last chunk, and zero padding before that. But we do
	 * not necessarily have enough space left. If not, we pad the
	 * current chunk with zeroes, and add an extra chunk at the end.
	 */

	if(space_left < 8)
	{
		memset(pos, 0x00, space_left);
		sha2_internal(h, sha256->chunk);

		pos = sha256->chunk;
		space_left = 64;
	}

	left = space_left - 8;

	memset(pos, 0x00, left);

	pos     += left;
	len      = sha256->total_len;
	pos[7]   = (__UINT8_TYPE__)(len << 3);
	len    >>= 5;

	for(i = 6; i >= 0; --i)
	{
		pos[i] = (__UINT8_TYPE__)len;
		len >>= 8;
	}

	sha2_internal(h, sha256->chunk);

	/* Produce the final hash value (big-endian): */
	hash = sha256->hash;

	for(i = 0, j = 0; i < 8; ++i)
	{
		hash[j++] = (__UINT8_TYPE__)(h[i] >> 24);
		hash[j++] = (__UINT8_TYPE__)(h[i] >> 16);
		hash[j++] = (__UINT8_TYPE__)(h[i] >> 8);
		hash[j++] = (__UINT8_TYPE__)h[i];
	}

	return sha256->hash;
}

void sha2(
__UINT8_TYPE__ hash[32],
const void * input,
__SIZE_TYPE__ len )
{
	struct sha2 sha256;

	sha2_init(&sha256, hash);
	sha2_update(&sha256, input, len);
	(void)sha2_final(&sha256);
}

/* END SHA-2 IMPLEMENTATION */
