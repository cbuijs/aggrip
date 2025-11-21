#!/usr/bin/env python3
'''
==========================================================================
 domsort.py v0.02-20251121 Copyright 2019-2025 by cbuijs@chrisbuijs.com
==========================================================================

 Domain-List Sorter

==========================================================================
'''

import sys

unique_data = {line.strip().lower() for line in sys.stdin if line.strip()}
sorted_data = sorted(unique_data, key=lambda s: s.split('.')[::-1])
sys.stdout.write('\n'.join(sorted_data) + '\n')

sys.exit(0)

