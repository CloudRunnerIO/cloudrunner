#!/usr/bin/python
# -*- coding: utf-8 -*-
# vim: tabstop=4 shiftwidth=4 softtabstop=4

# Copyright 2013 CloudRunner.IO
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import mock

from cloudrunner.core import parser
from cloudrunner.tests import base


class TestParser(base.BaseTestCase):
    selector_template = "#! switch [{0}]{1}"

    def test_parse_selectors(self):

        test_sel1 = "host22"
        test_args1 = "arg1 arg2 arg3"

        res = parser.parse_selectors(
            self.selector_template.format(test_sel1, test_args1)
        )

        self.assertEqual(res[0], test_sel1)
        self.assertEqual(res[1], test_args1)

        res = parser.parse_selectors("some broken selector")
        self.assertIsNone(res[0])
        self.assertIsNone(res[1])

    def test_split_sections(self):

        script = """#! switch [*]

section1

#! switch [os=linux]

section 2

#! switch [os=windows]
#! /usr/bin/python

echo "#! switch [some_blabla] \
hostname > test.sh"
"""

        res = parser.split_sections(script)

        self.assertCount(res, 7)
        self.assertEqual(res[0], "", res)
        self.assertEqual(res[1], "#! switch [*]", res)
        self.assertEqual(res[2], "\n\nsection1\n\n")
        self.assertEqual(res[3], "#! switch [os=linux]")
        self.assertEqual(res[4], "\n\nsection 2\n\n")
        self.assertEqual(res[5], "#! switch [os=windows]")
        self.assertEqual(res[6], """
#! /usr/bin/python

echo "#! switch [some_blabla] \
hostname > test.sh"
""")

        self.assertEqual(parser.parse_selectors(res[1]), ("*", ""))
        self.assertEqual(parser.parse_selectors(res[2]), (None, None))

    def test_has_params(self):
        matched_params = ["$P1=12", "$P2=12", "$P3=12"]

        generated_params = map("{0}".format, matched_params)
        unmatched_params = ["NOT", "MATCHED", "ELEMENTS"]

        test_params = " ".join(generated_params + unmatched_params)
        params = parser.has_params(test_params)
        self.assertEqual(params, zip(('', '', ''), matched_params))

    def test_parse_lang(self):
        language = "notpythonatall"
        env_str = "#!/usr/bin/env"
        bin_str = "#!/usr/bin/"
        unmatched_str = "unmatched string"

        parsed_language = parser.parse_lang(
            "{0} {1}\n".format(env_str, language))
        self.assertEqual(parsed_language, language)
        test_str = bin_str + language + "\n"
        parsed_language = parser.parse_lang(test_str)
        self.assertEqual(parsed_language, language)

        with mock.patch("os.name", "nt"):
            reload(parser)
            parsed_language = parser.parse_lang(unmatched_str)
            self.assertEqual(parsed_language, parser.LANG_PS)

        with mock.patch("os.name", "not-nt"):
            reload(parser)
            parsed_language = parser.parse_lang(unmatched_str)
            self.assertEqual(parsed_language, parser.LANG_BASH)

    def test_remove_shebang(self):
        shebang = ["#!/usr/bin/alabala"]
        lines = ['line1', 'line2', 'line3']
        shebang_script = "\n".join(shebang + lines)
        res = parser.remove_shebangs(shebang_script)
        self.assertEqual(res.split("\n"), lines)

    def test_remove_shebang_first_only(self):
        script = """#!/usr/bin/alabala
echo '#! switch [*]' > file
#! /usr/bin/bash
"""
        res = parser.remove_shebangs(script)
        self.assertEqual(
            res, "echo '#! switch [*]' > file\n#! /usr/bin/bash\n")
