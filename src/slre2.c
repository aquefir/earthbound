/**********************************************************************\
 *                             Earthbound                             *
 *                                                                    *
 *             Written by  Alexander Nicholi <//nich.fi/>             *
 *   Copyright (C) 2025-2026 Aquefir Consulting LLC <//aquefir.co/>   *
 *         Released under General Public License, version 2.0         *
\**********************************************************************/

#include <ctype.h>
#include <string.h>

#define CHK(_x,_r) do{if((_x)){}else{return (_r);}}while(0)
#define CHKC(_x) do{if((_x)){}else{continue;}}while(0)

typedef unsigned slre_bool;
typedef __UINT16_TYPE__ slre_uint;
typedef unsigned slre_ubf;
typedef __INTPTR_TYPE__ slre_offs;
typedef __UINTPTR_TYPE__ slre_ptri;

enum slre_err
{
	SLRE_ERR_SUCCESS,
	SLRE_ERR_NOMATCH,
	SLRE_ERR_BADENUM,
	SLRE_ERR_BADQUANTI,
	SLRE_ERR_BADPARENS,
	SLRE_ERR_BADCHARSET,
	SLRE_ERR_BADMETACHAR,
	SLRE_ERR_TOOMANYGROUPS,
	SLRE_ERR_TOOMANYBRANCHES,
	SLRE_ERR_BADCALL,
	SLRE_ERR_UNKNOWN,
	SLRE_MAX_ERR
};

enum
{
	SLRE_GROUPS_MAX = 8191
};

enum
{
	SLRE_BRANCHES_MAX = 8191
};

/* Possible flags for slre_match() */
enum slre_flags
{
	SLRE_IGNORE_CASE = 1
};

struct slre_set
{
	slre_ubf ascii_0 : 16;
	slre_ubf ascii_1 : 16;
	slre_ubf ascii_2 : 16;
	slre_ubf ascii_3 : 16;
	slre_ubf ascii_4 : 16;
	slre_ubf ascii_5 : 16;
	slre_ubf ascii_6 : 16;
	slre_ubf ascii_7 : 16;
	slre_ubf ascii_8 : 16;
	slre_ubf ascii_9 : 16;
	slre_ubf ascii_a : 16;
	slre_ubf ascii_b : 16;
	slre_ubf ascii_c : 16;
	slre_ubf ascii_d : 16;
	slre_ubf ascii_e : 16;
	slre_ubf ascii_f : 16;
	slre_ubf inverted : 1;
};

struct slre_group;

struct slre_group
{
	/* relative offsets from beginning of string */
	slre_offs open;
	/* relative offset from `.open` */
	slre_offs len;
	/* element count of `.branches` */
	slre_uint branch_ct;
	/* array of offsets from `.open` pointing to `'|'` metachars */
	slre_uint * branches;
	/* number of child groups */
	slre_ptri children_sz;
	/* ordered list of child groups */
	struct slre_group * children;
};

static slre_bool _chk_regex_octal( const char c[3], slre_ptri idx,
slre_ptri sz)
{
	slre_ptri i;

	if(idx + 2 >= sz
	|| c[0] != '0' && c[0] != '1' && c[0] != '2' && c[0] != '3')
	{
		/* might still fail but it's not our business */
		return 0;
	}

	for(i = 1; i <= 2; ++i)
	{
		if(c[i] < '0' || c[i] > '7')
		{
			return 1;
		}
	}

	return 0;
}

static slre_bool _chk_regex_meta( char c )
{
	switch(c)
	{
	case '^':
	case '$':
	case '(':
	case ')':
	case '.':
	case '[':
	case ']':
	case '*':
	case '+':
	case '?':
	case '|':
	case '\\':
	/* shorthands for character sets */
	case 'S':
	case 's':
	case 'D':
	case 'd':
	case 'W':
	case 'w':
	/* ASCII literals */
	case 'a':
	case 'b':
	case 'f':
	case 'n':
	case 'r':
	case 't':
	case 'v':
		return 0;
	default:
		return 1;
	}
}

static slre_bool _formgroups(
	const char * regex,
	slre_ptri regex_sz,
	struct slre_group (* groups)[SLRE_GROUPS_MAX],
	slre_ptri groups_sz
)
{
	slre_ptri i;
	slre_uint wip_sizes[SLRE_GROUPS_MAX];

	memset( &wip_sizes, 0, SLRE_GROUPS_MAX );

	for(i = 0; i < regex_sz; ++i)
	{
	}

	return 0;
}

static enum slre_err _slre_match(
	const char * regex,
	const char * string,
	slre_ptri string_sz,
	enum slre_flags flags
)
{
	slre_uint branch_idxs[SLRE_BRANCHES_MAX];
	struct slre_group groups[SLRE_GROUPS_MAX];
	slre_ptri groups_sz = 0;
	slre_uint branch_sz = 0;
	slre_uint opgroup_sz = 0;
	slre_uint clgroup_sz = 0;
	slre_ptri i;
	slre_uint r;
	const slre_ptri regex_sz = strlen( regex );

	/* this is a preliminary sweep to nope out of more obviously
	 * broken expressions before expensive parsing commences */
	for(i = 0; i < regex_sz; ++i)
	{
		switch(regex[i])
		{
		case '|':
			CHK( branch_sz + 1 < SLRE_BRANCHES_MAX,
				SLRE_ERR_TOOMANYBRANCHES );
			branch_idxs[branch_sz] = i;
			branch_sz += 1;
			break;
		case '\\':
			CHK( i + 1 < regex_sz, SLRE_ERR_BADMETACHAR );
			r = _chk_regex_octal( &regex[i + 1], i + 1,
				regex_sz );
			CHK( r == 0, SLRE_ERR_BADMETACHAR );
			r = _chk_regex_meta( regex[i + 1] );
			CHK( r == 0, SLRE_ERR_BADMETACHAR );
			/* extra chars to advance */
			i += regex[i + 1] == 'x' ? 3 : 1;
			break;
		case '(':
			CHK( opgroup_sz + 1 < SLRE_GROUPS_MAX,
				SLRE_ERR_TOOMANYGROUPS );
			CHK( i + 1 < regex_sz, SLRE_ERR_BADPARENS );
			opgroup_sz += 1;
			break;
		case ')':
			CHK( clgroup_sz + 1 < SLRE_GROUPS_MAX,
				SLRE_ERR_TOOMANYGROUPS );
			clgroup_sz += 1;
		default:
			break;
		}
	}

	CHK( opgroup_sz == clgroup_sz, SLRE_ERR_BADPARENS );

	r = _formgroups( regex, regex_sz, &groups, opgroup_sz );

	return SLRE_ERR_SUCCESS;
}

enum slre_err slre_match(
	const char * regex,
	const char * string,
	unsigned long string_sz,
	struct slre_group * groups,
	unsigned long groups_sz,
	enum slre_flags flags
)
{
	if(regex == 0 || string == 0 || string_sz == 0
	|| (groups != 0 && groups_sz == 0)
	|| (groups == 0 && groups_sz != 0))
	{
		return SLRE_ERR_BADCALL;
	}

	return _slre_match( regex, string, (slre_ptri)string_sz,
		flags );
}
