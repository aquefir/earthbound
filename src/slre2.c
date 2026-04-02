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

typedef __UINT16_TYPE__ slre_uint;
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

struct slre_group
{
	/* relative offsets from beginning of string */
	slre_uint open;
	/* relative offset from `.open` */
	slre_uint close;
	/* element count of `.branches` */
	slre_uint branch_ct;
	/* array of offsets from `.open` pointing to `'|'` metachars */
	slre_uint * branches;
};

static slre_uint _op_len( const char * regex,
	slre_ptri i, slre_ptri regex_sz )
{
	if(regex[i] == '\\')
	{
		return regex[(i + 1 < regex_sz) ? i + 1 : i] == 'x'
			? 4 : 2;
	}
	else
	{
		return 1;
	}
}

static slre_uint _set_len( const char * regex,
	slre_ptri i, slre_ptri regex_sz )
{
	slre_ptri len = 0;

	while( len + i < regex_sz && regex[len + i] != ']' )
	{
		len += _op_len( regex, i, regex_sz );
	}

	return len + i <= regex_sz ? len + i + 1 : -1;
}

static slre_ptri _get_op_len( const char * regex,
	slre_ptri i, slre_ptri regex_sz )
{
	return regex[i] == '['
		? _set_len( regex, i + 1, regex_sz - 1 ) + 1
		: _op_len( regex, i, regex_sz );
}

static slre_uint _chk_regex_hex( const char * regex,
	slre_ptri i, slre_ptri regex_sz )
{
	if( regex[i + 1] != 'x')
	{
		return 0;
	}
	else if(i + 3 >= regex_sz
	|| !isxdigit( regex[i + 2] )
	|| !isxdigit( regex[i + 3] ))
	{
		return 1;
	}

	return 0;
}

static slre_uint _chk_regex_meta( char c )
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
	case 'S':
	case 's':
	case 'd':
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

static slre_uint _formgroup(
	const char * regex,
	slre_uint opgroup_idxs[SLRE_GROUPS_MAX],
	slre_uint opgroup_sz,
	slre_ptri idx,
	struct slre_group (* groups)[SLRE_GROUPS_MAX],
	slre_ptri * groups_sz
)
{
	slre_ptri i;
	slre_uint depth = 0;
	slre_uint branch_ct = 0;

	if(idx >= opgroup_sz)
	{
		return 0;
	}

	for(i = 0; regex[i + opgroup_idxs[idx] + 1] != '\0'; ++i)
	{
		slre_uint quit = 0;

		switch(regex[i + opgroup_idxs[idx] + 1])
		{
		case '(':
			depth += 1;
			break;
		case ')':
			depth -= depth > 0 ? 1 : 0;
			quit = depth == 0 ? 1 : 0;
			break;
		case '|':
			/* this does nothing if depth > 0 since it
			 * would be an inner group's branch */
			(*groups)[idx].branches[branch_ct] = depth == 0
				? i
				: (*groups)[idx].branches[branch_ct];
			branch_ct += depth == 0 ? 1 : 0;
		default:
			break;
		}

		if(quit)
		{
			break;
		}
	}

	(*groups)[idx].open = opgroup_idxs[idx] + 1;
	(*groups)[idx].close = (*groups)[idx].open - i;

	return 1;
}

static enum slre_err _slre_match(
	const char * regex,
	const char * string,
	slre_ptri string_sz,
	enum slre_flags flags
)
{
	slre_uint branch_idxs[SLRE_BRANCHES_MAX];
	slre_uint opgroup_idxs[SLRE_GROUPS_MAX];
	struct slre_group groups[SLRE_GROUPS_MAX];
	slre_ptri groups_sz = 0;
	slre_uint branch_sz = 0;
	slre_uint opgroup_sz = 0;
	slre_uint clgroup_sz = 0;
	slre_uint step = 1;
	slre_ptri i;
	slre_uint r;
	const slre_ptri regex_sz = strlen( regex );

	if(groups && groups_sz >= 1)
	{
		groups[0].open = 0;
		groups[0].close = string_sz;
		groups[0].branch_ct = 0;
		groups[0].branches = (void *)0;
	}

	for(i = 0; i < regex_sz; i += step)
	{
		step = _get_op_len( regex, i, regex_sz );

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
			r = _chk_regex_hex( regex, i, regex_sz );
			CHK( r == 0, SLRE_ERR_BADMETACHAR );
			r = _chk_regex_meta( regex[i + 1] );
			CHK( r == 0, SLRE_ERR_BADMETACHAR );
			break;
		case '(':
			CHK( opgroup_sz + 1 < SLRE_GROUPS_MAX,
				SLRE_ERR_TOOMANYGROUPS );
			CHK( i + 1 < regex_sz, SLRE_ERR_BADPARENS );
			opgroup_idxs[opgroup_sz] = i;
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

	{
		struct slre_group groups[SLRE_GROUPS_MAX];
		slre_ptri groups_ct = 0;

		i = 0;

		do
		{
			r = _formgroup( regex, opgroup_idxs, opgroup_sz,
				i, &groups, &groups_sz );
		}
		while(r != 0);
	}

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
