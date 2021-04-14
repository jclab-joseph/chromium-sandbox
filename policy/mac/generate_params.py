#!/usr/bin/env python
# Copyright 2021 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""generate_params.py processes input .sb seatbelt files and extracts
parameter definitions of the form

    (define "sandbox-param-name")

And generates C++ constants of the form

    kParamSandboxParamName

Usage:

    generate_sandbox_params.py path/to/params policy1.sb policy2.sb...

Where |path/to/params| specifies the file prefix for the generated .h
and .cc files.
"""

from __future__ import print_function

import re
import sys


def generate_sandbox_params(argv):
    if len(argv) < 3:
        print('Usage: {} output_file_prefix file1.sb...'.format(argv[0]),
              file=sys.stderr)
        return 1

    h_contents = ''
    cc_contents = ''
    for (name, value) in _process_policy_files(argv[2:]):
        variable_name = 'kParam' + name.title().replace('-', '')
        h_contents += 'SANDBOX_POLICY_EXPORT extern const char {}[];\n'.format(
            variable_name)
        cc_contents += 'const char {}[] = "{}";\n'.format(variable_name, value)

    with open(argv[1] + '.h', 'w') as f:
        f.write(
            FILE_TEMPLATE.format(includes='#include "sandbox/policy/export.h"',
                                 contents=h_contents))

    with open(argv[1] + '.cc', 'w') as f:
        f.write(
            FILE_TEMPLATE.format(
                includes='#include "sandbox/policy/mac/params.h"',
                contents=cc_contents))

    return 0


def _process_policy_files(files):
    """Iterates the files in |files|, parsing out parameter definitions, and
    yields the name-value pair.
    """
    for sb_file in files:
        with open(sb_file, 'r') as f:
            for line in f:
                comment_start = line.find(';')
                if comment_start != -1:
                    line = line[:comment_start]
                match = DEFINE_RE.match(line)
                if match:
                    groups = match.groups()
                    yield (groups[0], groups[1])


DEFINE_RE = re.compile(r'^\(define\s+([a-zA-Z0-9\-]+).*"(\w+)"\)')

FILE_TEMPLATE = """// Generated by generate_params.py. Do not edit!!!

{includes}

namespace sandbox {{
namespace policy {{

{contents}

}}  // namespace policy
}}  // namespace sandbox
"""

if __name__ == '__main__':
    sys.exit(generate_sandbox_params(sys.argv))
