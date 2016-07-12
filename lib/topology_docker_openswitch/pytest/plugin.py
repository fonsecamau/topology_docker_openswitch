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

from os.path import exists, basename, splitext
from os import makedirs
from shutil import copytree, Error
from logging import warning


def pytest_runtest_teardown(item):
    """
    pytest hook to get the name of the test executed, it creates a folder with
    the name, then copies the folders defined in the shared_dir_mount attribute
    of each openswitch container, additionally the /var/log/messages of the
    container is copied to the same folder.
    """
    if 'topology' in item.funcargs:
        topology = item.funcargs['topology']
        if topology.engine == 'docker':
            logs_path = '/var/log/messages'
            for node in topology.nodes:
                node_obj = topology.get(node)
                if node_obj.metadata.get('type', None) == 'openswitch':
                    shared_dir = node_obj.shared_dir
                    try:
                        node_obj.send_command(
                            'cat {} > {}/var_messages.log'.format(
                                logs_path, node_obj.shared_dir_mount
                            ),
                            shell='bash',
                            silent=True
                        )
                    except:
                        warning(
                            'Unable to get {} from container.'.format(
                                logs_path
                            )
                        )
                    test_suite = splitext(basename(item.parent.name))[0]
                    path_name = '/tmp/{}_{}_{}'.format(
                        test_suite, item.name, str(id(item))
                    )
                    if not exists(path_name):
                        makedirs(path_name)
                    try:
                        copytree(
                            shared_dir, '{}/{}'.format(
                                path_name,
                                basename(shared_dir)
                            )
                        )
                    except Error as err:
                        errors = err.args[0]
                        for error in errors:
                            src, dest, msg = error
                            warning(
                                'Unable to copy file {}, Error {}'.format(
                                    src, msg
                                )
                            )
