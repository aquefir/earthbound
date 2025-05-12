#!/usr/bin/env python3
########################################################################
##                             Earthbound                             ##
##                                                                    ##
##             Copyright (C) 2025 Aquefir Consulting LLC.             ##
##         Released under General Public License, version 2.0         ##
########################################################################

import re

def f_operators(ops: list[str]):
	ret = dict.fromkeys(ops)
	ops_sz = len(ops)
	i = 0
	while i < ops_sz:
		ret[ops[i]] = re.compile(r'[ \t\v\f]*'
			+ re.escape(ops[i]) + r'[ \t\v\f]*')
		i += 1
	return ret

k_help_text = '''
cminify
A Python 3 utility for minifying C code

Usage:
\tutil/cminify.py <-h|--help>   Print this help and exit
\tutil/cminify.py <-s|--stats>  Show a before-and-after comparison
\tutil/cminify.py               Silently run the program

cminify always reads from stdin and writes to stdout. If stats are
requested they are sent to stderr. Return code is 0 on success and
nonzero on failure.

'''

k_block_comment = re.compile(r'/\*.*?\*/', re.DOTALL)
k_line_comment = re.compile(r'//.*$', re.MULTILINE)
k_whitespace = re.compile(r'[ \t\v\f]+', re.DOTALL)
k_leading = re.compile(r'^[ \t\v\f]+')
k_trailing = re.compile(r'[ \t\v\f]+$')
k_newlines = re.compile(r'\n+')
k_operators = f_operators([
	'&&', '||', '++', '--', '+=', '-=', '*=', '/=', '%=', '&=',
	'|=', '^=', '<<=', '>>=', '==', '!=', '<=', '>=', '+', '-', '*',
	'/', '%', '&', '|', '^', '<<', '>>', '=', '!', '~', '<', '>',
	'(', ')', '[', ']', '{', '}', '?', ':', ';', ','
])
k_operators_sz = len(k_operators)

k_preproc = re.compile(r'^#((include)[ \t\v\f]+(["<][A-Za-z_0-9/\\\.]' +
	r'+[">])|(define)[ \t\v\f]+([A-Za-z_][A-Za-z0-9_]*)(\([A-Za-z0-9_,' +
	r' \t\v\f]+\))?([ \t\v\f]+(.+$))?|([a-z]+)([ \t\v\f]+(.+$))?)',
	re.MULTILINE)

def print2(s: str):
	from sys import stderr
	stderr.buffer.write(s.encode('utf-8'))
	stderr.buffer.flush()

def read2(n: int | None = None):
	from sys import stdin
	b = stdin.buffer.read() if n is None else stdin.buffer.read(n)
	return b.decode('utf-8')

def write2(s: str):
	from sys import stdout
	stdout.buffer.write(s.encode('utf-8'))

def replace_operator(s: str, key: str):
	return k_operators[key].sub(key, s)

def convert_line(lines, lines_sz, ret, i):
	line = k_leading.sub('', k_trailing.sub('', lines[i]))
	line = k_line_comment.sub('', line)
	m = k_preproc.match(line)
	pre_n = False
	post_n = False
	is_incl = False
	if m:
		post_n = True
		gs = m.groups()
		#print2(':<: ' + str(gs) + ' :>:\n')
		if i > 0 and lines[i - 1] and not lines[i - 1].startswith('#'):
			pre_n = True
		if gs[3] == 'define':
			if gs[5] is not None:
				line = '#define ' + gs[4] + k_whitespace.sub('', gs[5]) + \
					k_whitespace.sub('', gs[7])
			else:
				line = '#define ' + gs[4] + ' ' + \
					k_whitespace.sub('', gs[7])
		elif gs[8] == 'if':
			line = '#if ' + k_whitespace.sub('', gs[10])
		elif gs[1] == 'include':
			line = '#include ' + gs[2]
			is_incl = True
		else: line = '#' + gs[0]
	j = 0
	keys = list(k_operators.keys())
	while j < k_operators_sz:
		if keys[j] == '<' and is_incl:
			j += 1
			continue
		line = replace_operator(line, keys[j])
		j += 1
	ret += '\n' if pre_n else ''
	ret += line
	ret += '\n' if post_n else ''
	return ret

def strip_whitespace(t: str):
	pieces: list[str] = ['']
	# this is a hack to make sure a shallow backtrack
	# never gives a false positive
	t = t.replace('\\\\', '\a')
	t_sz = len(t)
	i = 0
	j = 0
	while i < t_sz:
		if t[i] == '"' and (i == 0 or t[i - 1] != '\\'):
			pieces.append('')
			j += 1
		else:
			pieces[j] += t[i]
		i += 1
	in_str = False
	pieces_sz = len(pieces)
	i = 0
	ret = ''
	while i < pieces_sz:
		if i > 0:
			ret += '"'
		s = pieces[i].replace('\a', '\\\\')
		if i % 2 == 0:
			s = k_whitespace.sub(' ', s)
		ret += s
		i += 1
	return ret

def convert(t: str):
	# Replace Windows \r\n before replacing Classic Mac OS \r
	t = t.replace('\r\n', '\n').replace('\r', '\n')
	# Remove block comments
	t = k_block_comment.sub('', t)
	# Remove excess whitespace
	# In order to do this we have to split the input into string
	# and non-string portions first, perform whitespace minimising
	# on the non-string portions, and stitch it back together
	t = strip_whitespace(t)
	# Remove all empty lines
	t = k_newlines.sub('\n', t)
	lines = t.split('\n')
	lines_sz = len(lines)
	ret = ''
	i = 0
	while i < lines_sz:
		ret = convert_line(lines, lines_sz, ret, i)
		i += 1
	return ret + '\n'

def main(args: list[str]):
	if '-h' in args or '--help' in args:
		print2(k_help_text)
		return 0
	compare = False
	if '-s' in args or '--stats' in args:
		compare = True
	t = read2()
	t_sz = len(t)
	t2 = convert(t)
	t2_sz = len(t2)
	pct = t2_sz / t_sz * 100.0
	pct_i = 100.0 - pct
	write2(t2)
	if compare:
		print2('Original: %i\nMinified: %i\n' % (t_sz, t2_sz))
		print2('Saved: %.2f%% (%.2f%% of original)\n' % (pct_i, pct))
	return 0

if __name__ == '__main__':
	from sys import argv, exit
	exit(main(argv))
