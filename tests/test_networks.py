import unittest
from app.lib.networks import *


class TestNetworks(unittest.TestCase):

    def test_networks_prefix_wif_network_by_value(self):
        self.assertEqual(network_by_value('prefix_wif', '80')[:1], ['bitcoin'])
        self.assertEqual(network_by_value('prefix_wif', '10'), [])

    def test_networks_prefix_bech32_network_by_value(self):
        self.assertEqual(network_by_value('prefix_bech32', 'tb'), ['testnet'])

    def test_network_defined(self):
        self.assertTrue(network_defined('bitcoin'))
        self.assertFalse(network_defined('bitcoiiin'))
        self.assertRaisesRegex(NetworkError, "Network bitcoiin not found in network definitions", Network, 'bitcoiin')

    def test_wif_prefix_search(self):
        exp_dict = {
            'is_private': True,
            'network': 'bitcoin',
            'prefix': '0488ADE4',
            'prefix_str': 'xprv',
            'script_type': 'p2pkh',
            'witness_type': 'legacy'}
        self.assertEqual(wif_prefix_search('0488ADE4', network='bitcoin')[0], exp_dict)
        self.assertEqual(wif_prefix_search('lettrythisstrangestring', network='bitcoin'), [])

    def test_network_dunders(self):
        n1 = Network('bitcoin')
        self.assertTrue(n1 == 'bitcoin')
        self.assertTrue(n1 != 'dogecoin')
        self.assertEqual(str(n1), "<Network: bitcoin>")
        self.assertTrue(hash(n1))


if __name__ == '__main__':
    unittest.main()
