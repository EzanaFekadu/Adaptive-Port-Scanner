import unittest
from src import port_scanner

class TestPortScannerUtils(unittest.TestCase):

    def test_identify_service_known(self):
        self.assertEqual(port_scanner.identify_service(80, 'HTTP/1.1 200 OK'), 'HTTP')
        self.assertEqual(port_scanner.identify_service(53, ''), 'DNS')
        self.assertEqual(port_scanner.identify_service(22, ''), 'SSH')

    def test_identify_service_unknown(self):
        self.assertEqual(port_scanner.identify_service(9999, ''), 'Unknown or Banner Not Detected')

    def test_parse_ports(self):
        res = port_scanner.parse_ports("22,80,100-102")
        self.assertListEqual(res, [22, 80, 100, 101, 102])

if __name__ == '__main__':
    unittest.main()
