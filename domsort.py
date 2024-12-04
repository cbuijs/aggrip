#!/usr/bin/env python3
'''
==========================================================================
 domsort.py v0.01-20200409 Copyright 2019-2024 by cbuijs@chrisbuijs.com
==========================================================================

 Domain-List Sorter

==========================================================================
'''

from fileinput import input
import sys

for y in sorted([x.strip().split('.')[::-1] for x in input()]):
    print('.'.join(y[::-1]))

sys.exit(0)

