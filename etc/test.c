/**********************************************************************\
 *                             Earthbound                             *
 *                                                                    *
 *             Copyright (C) 2025 Aquefir Consulting LLC.             *
 *         Released under General Public License, version 2.0         *
\**********************************************************************/

#include <string.h>

typedef __UINT8_TYPE__ u8;
typedef __UINTPTR_TYPE__ ptri;

enum bl
{
	HN_FALSE = 0,
	HN_TRUE
};

typedef enum bl bl;

const char * const k_rando = "Test\\  \\   \"\"\\\" \\\\";

void hn_memset( u8 oct, ptri buf_sz, void * buf )
{
	memset( buf, oct, buf_sz );
}

void hn_memcpy( void * dst, ptri sz, void * src )
{
	memcpy( dst, src, sz );
}

bl hn_memequ( void * buf_a, ptri bufs_sz, void * buf_b )
{
	return memcmp( buf_a, buf_b, bufs_sz ) == 0 ? HN_TRUE :
	               HN_FALSE;
}
