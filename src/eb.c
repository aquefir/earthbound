/* for memset */
#include <string.h>
#include <ctype.h>
#include <stddef.h>

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

/* BEGIN SLRE IMPLEMENTATION */

/* slre_match() failure codes */
#define SLRE_NO_MATCH ( -1 )
#define SLRE_UNEXPECTED_QUANTIFIER ( -2 )
#define SLRE_UNBALANCED_BRACKETS ( -3 )
#define SLRE_INTERNAL_ERROR ( -4 )
#define SLRE_INVALID_CHARACTER_SET ( -5 )
#define SLRE_INVALID_METACHARACTER ( -6 )
#define SLRE_CAPS_ARRAY_TOO_SMALL ( -7 )
#define SLRE_TOO_MANY_BRANCHES ( -8 )
#define SLRE_TOO_MANY_BRACKETS ( -9 )

struct slre_cap
{
	const char * ptr;
	int len;
};

int slre_match( const char * regexp,
	const char * buf,
	int buf_len,
	struct slre_cap * caps,
	int num_caps,
	int flags );

/* Possible flags for slre_match() */
enum
{
	SLRE_IGNORE_CASE = 1
};

#define MAX_BRANCHES 100
#define MAX_BRACKETS 100
#define FAIL_IF(c, e) if(c) return (e)

#ifndef ARRAY_SIZE
#define ARRAY_SIZE( ar ) ( sizeof( ar ) / sizeof( ( ar )[0] ) )
#endif

struct bracket_pair
{
	/* Points to the first char after '(' in regex */
	const char * ptr;
	/* Length of the text between '(' and ')' */
	int len;
	/* Index in the branches array for this pair */
	int branches;
  /* Number of '|' in this bracket pair */
	int num_branches;
};

struct branch
{
	/* index for 'struct bracket_pair brackets'
	 * array defined below */
	int bracket_index;
	/* points to the '|' character in the regex */
	const char * schlong;
};

struct regex_info
{
	/* Describes all bracket pairs in the regular expression.
	 * First entry is always present, and grabs the whole regex.
	 */
	struct bracket_pair brackets[MAX_BRACKETS];
	int num_brackets;

	/* Describes alternations ('|' operators) in the regular
	 * expression. Each branch falls into a specific branch pair.
	 */
	struct branch branches[MAX_BRANCHES];
	int num_branches;

	/* Array of captures provided by the user */
	struct slre_cap * caps;
	int num_caps;

	/* E.g. SLRE_IGNORE_CASE. See enum below */
	int flags;
};

static int is_metacharacter( const unsigned char * s )
{
	static const char * metacharacters = "^$().[]*+?|\\Ssdbfnrtv";
	return strchr( metacharacters, *s ) != NULL;
}

static int op_len( const char * re )
{
	return re[0] == '\\' && re[1] == 'x' ? 4
		: re[0] == '\\'              ? 2
					     : 1;
}

static int set_len( const char * re, int re_len )
{
	int len = 0;

	while( len < re_len && re[len] != ']' )
	{
		len += op_len( re + len );
	}

	return len <= re_len ? len + 1 : -1;
}

static int get_op_len( const char * re, int re_len )
{
	return re[0] == '[' ? set_len( re + 1, re_len - 1 ) + 1
			    : op_len( re );
}

static int is_quantifier( const char * re )
{
	return re[0] == '*' || re[0] == '+' || re[0] == '?';
}

static int toi( int x ) { return isdigit( x ) ? x - '0' : x - 'W'; }

static int hextoi( const unsigned char * s )
{
	return ( toi( tolower( s[0] ) ) << 4 ) | toi( tolower( s[1] ) );
}

static int match_op( const unsigned char * re,
	const unsigned char * s,
	struct regex_info * info )
{
	int result = 0;
	switch( *re )
	{
	case '\\':
		/* Metacharacters */
		switch( re[1] )
		{
		case 'S':
			FAIL_IF( isspace( *s ), SLRE_NO_MATCH );
			result++;
			break;
		case 's':
			FAIL_IF( !isspace( *s ), SLRE_NO_MATCH );
			result++;
			break;
		case 'd':
			FAIL_IF( !isdigit( *s ), SLRE_NO_MATCH );
			result++;
			break;
		case 'b':
			FAIL_IF( *s != '\b', SLRE_NO_MATCH );
			result++;
			break;
		case 'f':
			FAIL_IF( *s != '\f', SLRE_NO_MATCH );
			result++;
			break;
		case 'n':
			FAIL_IF( *s != '\n', SLRE_NO_MATCH );
			result++;
			break;
		case 'r':
			FAIL_IF( *s != '\r', SLRE_NO_MATCH );
			result++;
			break;
		case 't':
			FAIL_IF( *s != '\t', SLRE_NO_MATCH );
			result++;
			break;
		case 'v':
			FAIL_IF( *s != '\v', SLRE_NO_MATCH );
			result++;
			break;

		case 'x':
			/* Match byte, \xHH where HH is hexadecimal byte
			 * representaion */
			FAIL_IF(
				hextoi( re + 2 ) != *s, SLRE_NO_MATCH );
			result++;
			break;

		default:
			/* Valid metacharacter check is done in bar() */
			FAIL_IF( re[1] != s[0], SLRE_NO_MATCH );
			result++;
			break;
		}
		break;

	case '|':
		FAIL_IF( 1, SLRE_INTERNAL_ERROR );
		break;
	case '$':
		FAIL_IF( 1, SLRE_NO_MATCH );
		break;
	case '.':
		result++;
		break;

	default:
		if( info->flags & SLRE_IGNORE_CASE )
		{
			FAIL_IF( tolower( *re ) != tolower( *s ),
				SLRE_NO_MATCH );
		}
		else
		{
			FAIL_IF( *re != *s, SLRE_NO_MATCH );
		}
		result++;
		break;
	}

	return result;
}

static int match_set( const char * re,
	int re_len,
	const char * s,
	struct regex_info * info )
{
	int len = 0, result = -1, invert = re[0] == '^';

	if( invert )
		re++, re_len--;

	while( len <= re_len && re[len] != ']' && result <= 0 )
	{
		/* Support character range */
		if( re[len] != '-' && re[len + 1] == '-' &&
			re[len + 2] != ']' && re[len + 2] != '\0' )
		{
			result = info->flags & SLRE_IGNORE_CASE
				? tolower( *s ) >= tolower( re[len] ) &&
					tolower( *s ) <=
						tolower( re[len + 2] )
				: *s >= re[len] && *s <= re[len + 2];
			len += 3;
		}
		else
		{
			result = match_op(
				(const unsigned char *)re + len,
				(const unsigned char *)s,
				info );
			len += op_len( re + len );
		}
	}
	return ( !invert && result > 0 ) || ( invert && result <= 0 )
		? 1
		: -1;
}

static int doh(
	const char * s, int s_len, struct regex_info * info, int bi );

static int bar( const char * re,
	int re_len,
	const char * s,
	int s_len,
	struct regex_info * info,
	int bi )
{
	/* i is offset in re, j is offset in s, bi is brackets index */
	int i, j, n, step;

	for( i = j = 0; i < re_len && j <= s_len; i += step )
	{

		/* Handle quantifiers. Get the length of the chunk. */
		step = re[i] == '(' ? info->brackets[bi + 1].len + 2
				    : get_op_len( re + i, re_len - i );

		FAIL_IF( is_quantifier( &re[i] ),
			SLRE_UNEXPECTED_QUANTIFIER );
		FAIL_IF( step <= 0, SLRE_INVALID_CHARACTER_SET );

		if( i + step < re_len &&
			is_quantifier( re + i + step ) )
		{
			if( re[i + step] == '?' )
			{
				int result = bar( re + i,
					step,
					s + j,
					s_len - j,
					info,
					bi );
				j += result > 0 ? result : 0;
				i++;
			}
			else if( re[i + step] == '+' ||
				re[i + step] == '*' )
			{
				int j2 = j, nj = j, n1, n2 = -1, ni,
				    non_greedy = 0;

				/* Points to the regexp code after the
				 * quantifier */
				ni = i + step + 1;
				if( ni < re_len && re[ni] == '?' )
				{
					non_greedy = 1;
					ni++;
				}

				do
				{
					if( ( n1 = bar( re + i,
						      step,
						      s + j2,
						      s_len - j2,
						      info,
						      bi ) ) > 0 )
					{
						j2 += n1;
					}
					if( re[i + step] == '+' &&
						n1 < 0 )
						break;

					if( ni >= re_len )
					{
						/* After quantifier,
						 * there is nothing */
						nj = j2;
					}
					else if( ( n2 = bar( re + ni,
							   re_len - ni,
							   s + j2,
							   s_len - j2,
							   info,
							   bi ) ) >= 0 )
					{
						/* Regex after
						 * quantifier matched */
						nj = j2 + n2;
					}
					if( nj > j && non_greedy )
						break;
				} while( n1 > 0 );

				/*
				 * Even if we found one or more pattern,
				 * this branch will be executed,
				 * changing the next captures.
				 */
				if( n1 < 0 && n2 < 0 &&
					re[i + step] == '*' &&
					( n2 = bar( re + ni,
						  re_len - ni,
						  s + j,
						  s_len - j,
						  info,
						  bi ) ) > 0 )
				{
					nj = j + n2;
				}

				FAIL_IF( re[i + step] == '+' && nj == j,
					SLRE_NO_MATCH );

				/* If while loop body above was not
				 * executed for the * quantifier,  */
				/* make sure the rest of the regex
				 * matches                          */
				FAIL_IF( nj == j && ni < re_len &&
						n2 < 0,
					SLRE_NO_MATCH );

				/* Returning here cause we've matched
				 * the rest of RE already */
				return nj;
			}
			continue;
		}

		if( re[i] == '[' )
		{
			n = match_set( re + i + 1,
				re_len - ( i + 2 ),
				s + j,
				info );
			FAIL_IF( n <= 0, SLRE_NO_MATCH );
			j += n;
		}
		else if( re[i] == '(' )
		{
			n = SLRE_NO_MATCH;
			bi++;
			FAIL_IF( bi >= info->num_brackets,
				SLRE_INTERNAL_ERROR );

			if( re_len - ( i + step ) <= 0 )
			{
				/* Nothing follows brackets */
				n = doh( s + j, s_len - j, info, bi );
			}
			else
			{
				int j2;
				for( j2 = 0; j2 <= s_len - j; j2++ )
				{
					if( ( n = doh( s + j,
						      s_len - ( j + j2 ),
						      info,
						      bi ) ) >= 0 &&
						bar( re + i + step,
							re_len -
								( i + step ),
							s + j + n,
							s_len - ( j + n ),
							info,
							bi ) >= 0 )
						break;
				}
			}

			FAIL_IF( n < 0, n );
			if( info->caps != NULL && n > 0 )
			{
				info->caps[bi - 1].ptr = s + j;
				info->caps[bi - 1].len = n;
			}
			j += n;
		}
		else if( re[i] == '^' )
		{
			FAIL_IF( j != 0, SLRE_NO_MATCH );
		}
		else if( re[i] == '$' )
		{
			FAIL_IF( j != s_len, SLRE_NO_MATCH );
		}
		else
		{
			FAIL_IF( j >= s_len, SLRE_NO_MATCH );
			n = match_op( (const unsigned char *)( re + i ),
				(const unsigned char *)( s + j ),
				info );
			FAIL_IF( n <= 0, n );
			j += n;
		}
	}

	return j;
}

/* Process branch points */
static int doh(
	const char * s, int s_len, struct regex_info * info, int bi )
{
	const struct bracket_pair * b = &info->brackets[bi];
	int i                         = 0, len, result;
	const char * p;

	do
	{
		p   = i == 0
			  ? b->ptr
			  : info->branches[b->branches + i - 1].schlong +
                                1;
		len = b->num_branches == 0 ? b->len
			: i == b->num_branches
			? (int)( b->ptr + b->len - p )
			: (int)( info->branches[b->branches + i]
					  .schlong -
				  p );
		result = bar( p, len, s, s_len, info, bi );
	} while( result <= 0 &&
		i++ < b->num_branches ); /* At least 1 iteration */

	return result;
}

static int baz( const char * s, int s_len, struct regex_info * info )
{
	int i, result = -1,
	       is_anchored = info->brackets[0].ptr[0] == '^';

	for( i = 0; i <= s_len; i++ )
	{
		result = doh( s + i, s_len - i, info, 0 );
		if( result >= 0 )
		{
			result += i;
			break;
		}
		if( is_anchored )
			break;
	}

	return result;
}

static void setup_branch_points( struct regex_info * info )
{
	int i, j;
	struct branch tmp;

	/* First, sort branches. Must be stable, no qsort. Use bubble
	 * algo. */
	for( i = 0; i < info->num_branches; i++ )
	{
		for( j = i + 1; j < info->num_branches; j++ )
		{
			if( info->branches[i].bracket_index >
				info->branches[j].bracket_index )
			{
				tmp               = info->branches[i];
				info->branches[i] = info->branches[j];
				info->branches[j] = tmp;
			}
		}
	}

	/*
	 * For each bracket, set their branch points. This way, for
	 * every bracket (i.e. every chunk of regex) we know all branch
	 * points before matching.
	 */
	for( i = j = 0; i < info->num_brackets; i++ )
	{
		info->brackets[i].num_branches = 0;
		info->brackets[i].branches     = j;
		while( j < info->num_branches &&
			info->branches[j].bracket_index == i )
		{
			info->brackets[i].num_branches++;
			j++;
		}
	}
}

static int foo( const char * re,
	int re_len,
	const char * s,
	int s_len,
	struct regex_info * info )
{
	int i, step, depth = 0;

	/* First bracket captures everything */
	info->brackets[0].ptr = re;
	info->brackets[0].len = re_len;
	info->num_brackets    = 1;

	/* Make a single pass over regex string, memorize brackets and
	 * branches */
	for( i = 0; i < re_len; i += step )
	{
		step = get_op_len( re + i, re_len - i );

		if( re[i] == '|' )
		{
			FAIL_IF( info->num_branches >=
					(int)ARRAY_SIZE(
						info->branches ),
				SLRE_TOO_MANY_BRANCHES );
			info->branches[info->num_branches]
				.bracket_index =
				info->brackets[info->num_brackets - 1]
						.len == -1
				? info->num_brackets - 1
				: depth;
			info->branches[info->num_branches].schlong =
				&re[i];
			info->num_branches++;
		}
		else if( re[i] == '\\' )
		{
			FAIL_IF( i >= re_len - 1,
				SLRE_INVALID_METACHARACTER );
			if( re[i + 1] == 'x' )
			{
				/* Hex digit specification must follow
				 */
				FAIL_IF( re[i + 1] == 'x' &&
						i >= re_len - 3,
					SLRE_INVALID_METACHARACTER );
				FAIL_IF( re[i + 1] == 'x' &&
						!( isxdigit( re[i +
							   2] ) &&
							isxdigit( re[i +
								3] ) ),
					SLRE_INVALID_METACHARACTER );
			}
			else
			{
				FAIL_IF( !is_metacharacter(
						 (const unsigned char *)
							 re +
						 i + 1 ),
					SLRE_INVALID_METACHARACTER );
			}
		}
		else if( re[i] == '(' )
		{
			FAIL_IF( info->num_brackets >=
					(int)ARRAY_SIZE(
						info->brackets ),
				SLRE_TOO_MANY_BRACKETS );
			depth++; /* Order is important here. Depth
				    increments first. */
			info->brackets[info->num_brackets].ptr =
				re + i + 1;
			info->brackets[info->num_brackets].len = -1;
			info->num_brackets++;
			FAIL_IF( info->num_caps > 0 &&
					info->num_brackets - 1 >
						info->num_caps,
				SLRE_CAPS_ARRAY_TOO_SMALL );
		}
		else if( re[i] == ')' )
		{
			int ind = info->brackets[info->num_brackets - 1]
						.len == -1
				? info->num_brackets - 1
				: depth;
			info->brackets[ind].len = (int)( &re[i] -
				info->brackets[ind].ptr );
			depth--;
			FAIL_IF( depth < 0, SLRE_UNBALANCED_BRACKETS );
			FAIL_IF( i > 0 && re[i - 1] == '(',
				SLRE_NO_MATCH );
		}
	}

	FAIL_IF( depth != 0, SLRE_UNBALANCED_BRACKETS );
	setup_branch_points( info );

	return baz( s, s_len, info );
}

int slre_match( const char * regexp,
const char * s,
int s_len,
struct slre_cap * caps,
int num_caps,
int flags )
{
	struct regex_info info;

	/* Initialize info structure */
	info.flags        = flags;
	info.num_brackets = 0;
	info.num_branches = 0;
	info.num_caps     = num_caps;
	info.caps         = caps;

	return foo( regexp, (int)strlen( regexp ), s, s_len, &info );
}

/* END SLRE IMPLEMENTATION */
