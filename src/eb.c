
/* BEGIN SHA-3 IMPLEMENTATION */

#ifndef KECCAKF_ROUNDS
#define KECCAKF_ROUNDS 24
#endif

#ifndef ROTL64
#define ROTL64(x, y) (((x) << (y)) | ( (x) >> (64 - (y))))
#endif

typedef struct
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
} sha3_ctx_t;

/* Compression function */
void sha3_keccakf( __UINT64_TYPE__ st[25] );

/* OpenSSL-like interface */

/* mdlen = hash output in bytes */
int sha3_init( sha3_ctx_t * c, int mdlen );
int sha3_update( sha3_ctx_t * c, const void * data, __SIZE_TYPE__ len );
/* digest goes to md */
int sha3_final( void * md, sha3_ctx_t * c );

/* compute a sha3 hash (md) of given byte length from "in" */
void * sha3(
	const void * in, __SIZE_TYPE__ inlen, void * md, int mdlen );

/* SHAKE128 and SHAKE256 extensible-output functions */
#define shake128_init( c ) sha3_init( c, 16 )
#define shake256_init( c ) sha3_init( c, 32 )
#define shake_update sha3_update

void shake_xof( sha3_ctx_t * c );
void shake_out( sha3_ctx_t * c, void * out, __SIZE_TYPE__ len );

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
	for( i = 0; i < 25; i++ )
	{
		v     = (__UINT8_TYPE__ *)&st[i];
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
	for( r = 0; r < KECCAKF_ROUNDS; r++ )
	{

		/* Theta */
		for( i = 0; i < 5; i++ )
			bc[i] = st[i] ^ st[i + 5] ^ st[i + 10] ^
				st[i + 15] ^ st[i + 20];

		for( i = 0; i < 5; i++ )
		{
			t = bc[( i + 4 ) % 5] ^
				ROTL64( bc[( i + 1 ) % 5], 1 );
			for( j = 0; j < 25; j += 5 )
				st[j + i] ^= t;
		}

		/* Rho Pi */
		t = st[1];
		for( i = 0; i < 24; i++ )
		{
			j     = keccakf_piln[i];
			bc[0] = st[j];
			st[j] = ROTL64( t, keccakf_rotc[i] );
			t     = bc[0];
		}

		/*  Chi */
		for( j = 0; j < 25; j += 5 )
		{
			for( i = 0; i < 5; i++ )
				bc[i] = st[j + i];
			for( i = 0; i < 5; i++ )
				st[j + i] ^= ( ~bc[( i + 1 ) % 5] ) &
					bc[( i + 2 ) % 5];
		}

		/*  Iota */
		st[0] ^= keccakf_rndc[r];
	}

#if __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
	/* endianess conversion. this is redundant on little-endian
	 * targets */
	for( i = 0; i < 25; i++ )
	{
		v    = (__UINT8_TYPE__ *)&st[i];
		t    = st[i];
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

int sha3_init( sha3_ctx_t * c, int mdlen )
{
	int i;

	for( i = 0; i < 25; i++ )
		c->st.q[i] = 0;
	c->mdlen = mdlen;
	c->rsiz  = 200 - 2 * mdlen;
	c->pt    = 0;

	return 1;
}

/* update state with more data */

int sha3_update( sha3_ctx_t * c, const void * data, __SIZE_TYPE__ len )
{
	__SIZE_TYPE__ i;
	int j;

	j = c->pt;
	for( i = 0; i < len; i++ )
	{
		c->st.b[j++] ^= ( (const __UINT8_TYPE__ *)data )[i];
		if( j >= c->rsiz )
		{
			sha3_keccakf( c->st.q );
			j = 0;
		}
	}
	c->pt = j;

	return 1;
}

/* finalize and output a hash */

int sha3_final( void * md, sha3_ctx_t * c )
{
	int i;

	c->st.b[c->pt] ^= 0x06;
	c->st.b[c->rsiz - 1] ^= 0x80;
	sha3_keccakf( c->st.q );

	for( i = 0; i < c->mdlen; i++ )
	{
		( (__UINT8_TYPE__ *)md )[i] = c->st.b[i];
	}

	return 1;
}

/* compute a SHA-3 hash (md) of given byte length from "in" */

void * sha3(
	const void * in, __SIZE_TYPE__ inlen, void * md, int mdlen )
{
	sha3_ctx_t sha3;

	sha3_init( &sha3, mdlen );
	sha3_update( &sha3, in, inlen );
	sha3_final( md, &sha3 );

	return md;
}

/* SHAKE128 and SHAKE256 extensible-output functionality */

void shake_xof( sha3_ctx_t * c )
{
	c->st.b[c->pt] ^= 0x1F;
	c->st.b[c->rsiz - 1] ^= 0x80;
	sha3_keccakf( c->st.q );
	c->pt = 0;
}

void shake_out( sha3_ctx_t * c, void * out, __SIZE_TYPE__ len )
{
	__SIZE_TYPE__ i;
	int j;

	j = c->pt;
	for( i = 0; i < len; i++ )
	{
		if( j >= c->rsiz )
		{
			sha3_keccakf( c->st.q );
			j = 0;
		}
		( (__UINT8_TYPE__ *)out )[i] = c->st.b[j++];
	}
	c->pt = j;
}

/* END SHA-3 IMPLEMENTATION */
