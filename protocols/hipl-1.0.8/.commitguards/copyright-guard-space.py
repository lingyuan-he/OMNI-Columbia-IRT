#!/usr/bin/env python

# Copyright (c) 2012 Aalto University and RWTH Aachen University.
#
# Permission is hereby granted, free of charge, to any person
# obtaining a copy of this software and associated documentation
# files (the "Software"), to deal in the Software without
# restriction, including without limitation the rights to use,
# copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the
# Software is furnished to do so, subject to the following
# conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
# OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
# HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.

#
# Test whether a copyright comment block is followed by a blank line
#

import os, re, sys

class CommentStyle:
    def __init__(self, header = None, body = None, footer = None, pattern = None):
        if pattern:
            self.pattern = re.compile(pattern, re.MULTILINE)
        else:
            self.pattern = re.compile('^' + header + '[^\n]*\n(^' + body + '[^\n]*\n)+^' + footer + '\n\n', re.MULTILINE)

c_style = CommentStyle(' \* Copyright ', ' \*', ' \*/')
hash_style = CommentStyle('# Copyright ', '#', '#.*')
# the following pattern reads as follows:
# At the beginning of the copyright block, the string """\nCopyright is
# expected. After the next newline, there maybe any number of lines that do not
# contain the string """ (cf. negative lookahead assertions). Finally, there
# must be a line that does contain the string """ which may be preceded by
# other characters.
python_string_style = CommentStyle(pattern = '"""\nCopyright .*\n(((?!""").)*\n)*.*"""\n\n')

styles = {
    '.c': [c_style],
    '.h': [c_style],
    '.am': [hash_style],
    '.ac': [hash_style],
    '.in': [hash_style],
    '.py': [hash_style, python_string_style],
    '.sh': [hash_style],
}

filename = sys.argv[1]
# If the filename ends in '.in', remove it to discover it's true ending.
# Autoconf strips the '.in' postfix and generates, e.g., .c or .py files
# based on this.
if filename.endswith('.in'):
    filename = filename[ : len(filename) - len('.in')]
# Parse the type of the file (.c, .h, etc)
extension = os.path.splitext(filename)[1]

if extension in styles:
    for style in styles[extension]:
        fh = open(sys.argv[1], 'r')
        match = style.pattern.search(fh.read())
        fh.close()

        if match:
            break

    if not match:
        print 'The copyright header in file %s should be followed by an empty line' % (sys.argv[1])
        sys.exit(1)
