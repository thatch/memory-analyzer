#!/usr/bin/env python3
# Copyright (c) Facebook, Inc. and its affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

import os
import subprocess
import sys
import tempfile
import time
import unittest


class IntegrationTest(unittest.TestCase):
    def test_works_at_all(self):
        # This test is very Linux-centric, while the gdb bits will probably work
        # no other unices
        output_name = tempfile.mktemp()
        print(output_name)

        with open("/proc/sys/kernel/yama/ptrace_scope") as f:
            value = f.read().strip()
        self.assertIn(
            value, ("0", "1"), "/proc/sys/kernel/yama/ptrace_scope should be 0 or 1"
        )
        print("yama/ptrace_scope is", value)

        # This tells us that everything important was packaged if we tox
        # installed an sdist, but doesn't tell us anything if this was setup.py
        # develop'd in a git repo.
        os.chdir("/")

        # See https://www.kernel.org/doc/Documentation/security/Yama.txt for
        # PR_SET_PTRACER info (PR_SET_PTRACER_ANY is documented in prctl(2))
        # This precise invocation is adapted from pwnlib/tubes/ssh.py

        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                """
import ctypes
PR_SET_PTRACER = 0x59616d61
PR_SET_PTRACER_ANY = -1
ctypes.CDLL('libc.so.6').prctl(PR_SET_PTRACER, PR_SET_PTRACER_ANY, 0, 0, 0)
import sys; sys.stdin.readline()""",
            ],
            stdin=subprocess.PIPE,
        )

        self.assertFalse(os.path.exists(output_name))

        # Presumably this is a virtualenv python executable that has objgraph
        # and pympler.  TODO test with one that removes everything from
        # sys.path, and ensure that we can inject the dir properly.
        try:
            # TODO figure out how we can ensure setup is done; right now we're
            # just relying on it taking a while to launch/attach
            analyzer = subprocess.Popen(
                ["memory_analyzer", "run", "-q", "-f", output_name, str(child.pid)]
            )
            rc = analyzer.wait(5)
        finally:
            child.communicate(b"\n")

        self.assertEqual(0, rc)
        self.assertTrue(os.path.exists(output_name))
        # TODO verify pickle has some strs


if __name__ == "__main__":
    unittest.main()
