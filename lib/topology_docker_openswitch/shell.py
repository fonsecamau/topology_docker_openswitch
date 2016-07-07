# -*- coding: utf-8 -*-
#
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
Custom Topology Docker Node for OpenSwitch.

    http://openswitch.net/
"""

from __future__ import unicode_literals, absolute_import
from __future__ import print_function, division

# from re import sub as regex_sub

from topology_docker.shell import DockerShell
from pexpect import EOF, TIMEOUT
from pytest import set_trace
from time import sleep


# TERM_CODES_REGEX = r'\x1b[E|\[](\?)?([0-9]{1,2}(;[0-9]{1,2})?)?[m|K|h|H|r]?'
class DockerOpsShell(DockerShell):
    def send_command(self, command, matches=None, newline=True, timeout=None,
                     connection=None):
        if matches is None:
            matches = [self._prompt, 'Segmentation fault', EOF, TIMEOUT]
        else:
            matches.append(EOF)
            matches.append(TIMEOUT)

        # try:
        match_index = super(DockerOpsShell, self).send_command(
            command, matches, newline, timeout, connection)
        # except:
        # set_trace()
        if match_index == (len(matches) - 3):
            set_trace()
            print(self._connections['0'].before)
        elif match_index == (len(matches) - 2):
            sleep(1)
            set_trace()
            self.get_response()
        elif match_index == (len(matches) - 1):
            set_trace()
        return match_index


__all__ = ['DockerOpsShell']
