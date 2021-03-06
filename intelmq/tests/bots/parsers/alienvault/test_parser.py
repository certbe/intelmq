# -*- coding: utf-8 -*-

import unittest

import intelmq.lib.test as test
from intelmq.bots.parsers.alienvault.parser import AlienVaultParserBot


class TestAlienVaultParserBot(test.BotTestCase, unittest.TestCase):
    """
    A TestCase for AlienVaultParserBot.
    """

    @classmethod
    def set_bot(cls):
        cls.bot_reference = AlienVaultParserBot
        cls.default_input_message = {'__type': 'Report'}

if __name__ == '__main__':
    unittest.main()
