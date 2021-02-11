#!/usr/bin/python3
# Copyright 2017-2021 Joel Allen Luellwitz and Emily Frost
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""The project test runner. To run the test suite, execute the following from the project
root:

CLEAR_GPG_AGENT_CACHE=true python3 -m unittest
"""

__author__ = 'Joel Luellwitz and Emily Frost'
__version__ = '0.8'

import unittest
from test.gpgmailbuildertest import GpgMailBuilderTest

if __name__ == '__main__':
    unittest.main()
