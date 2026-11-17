"""ЛР5. Модульные тесты. Запуск из папки lab5: python -m unittest -v"""

import ipaddress
import unittest

import audit
import netcalc
import netdiag


class TestSubnetInfo(unittest.TestCase):
    def test_slash24(self):
        info = netcalc.subnet_info("192.168.10.35/24")
        self.assertEqual(info["Адрес сети"], "192.168.10.0")
        self.assertEqual(info["Broadcast"], "192.168.10.255")
        self.assertEqual(info["Количество узлов"], 254)
        self.assertEqual(info["Wildcard"], "0.0.0.255")
        self.assertEqual(info["Маска (двоичная)"],
                         "11111111.11111111.11111111.00000000")

    def test_slash30(self):
        info = netcalc.subnet_info("10.0.0.5/30")
        self.assertEqual(info["Адрес сети"], "10.0.0.4")
        self.assertEqual(info["Broadcast"], "10.0.0.7")
        self.assertEqual(info["Количество узлов"], 2)

    def test_slash32(self):
        info = netcalc.subnet_info("8.8.8.8/32")
        self.assertEqual(info["Количество узлов"], 0)
        self.assertEqual(info["Первый узел"], "-")

    def test_address_types(self):
        self.assertEqual(netcalc.subnet_info("169.254.1.5/16")["Тип адреса"], "link-local")
        self.assertEqual(netcalc.subnet_info("8.8.8.8/32")["Тип адреса"], "публичный")
        self.assertEqual(netcalc.subnet_info("127.0.0.1/8")["Тип адреса"], "loopback")
        self.assertEqual(netcalc.subnet_info("10.5.5.5/24")["Тип адреса"], "частный")


class TestParseCidr(unittest.TestCase):
    def test_two_formats_equal(self):
        self.assertEqual(netcalc.parse_cidr("10.0.0.5/26"),
                         netcalc.parse_cidr("  10.0.0.5   255.255.255.192 "))

    def test_invalid_address(self):
        for bad in ("192.168.1.300/24", "abc", "", "10.0.0.5 255.0.255.0"):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    netcalc.parse_cidr(bad)

    def test_no_mask(self):
        with self.assertRaisesRegex(ValueError, "не указана маска"):
            netcalc.parse_cidr("10.0.0.5")

    def test_same_subnet(self):
        self.assertTrue(netcalc.same_subnet("10.5.5.70/26", "10.5.5.100"))
        self.assertFalse(netcalc.same_subnet("10.5.5.70/26", "10.5.5.128"))


class TestVlsm(unittest.TestCase):
    def test_not_enough_addresses(self):
        with self.assertRaises(ValueError):
            netcalc.vlsm("10.0.0.0/26", {"A": 50, "B": 30})

    def test_with_growth(self):
        self.assertEqual(netcalc.with_growth(60, 10), 66)
        self.assertEqual(netcalc.with_growth(30, 30), 39)

    def test_variant_plan(self):
        plan = netcalc.vlsm(netcalc.VARIANT_BASE, netcalc.VARIANT_DEPS,
                            netcalc.VARIANT_GROWTH)
        sizes = [p["subnet"].num_addresses for p in plan]
        self.assertEqual(sizes, sorted(sizes, reverse=True))      # по убыванию
        self.assertEqual(plan[0]["subnet"].network_address,
                         ipaddress.ip_network(netcalc.VARIANT_BASE).network_address)
        self.assertEqual(netcalc.check_plan(netcalc.VARIANT_BASE, plan), [])
        self.assertEqual([str(p["subnet"]) for p in plan],
                         ["10.5.5.0/26", "10.5.5.64/26",
                          "10.5.5.128/28", "10.5.5.144/28"])

    def test_check_plan_finds_overlap(self):
        bad = netcalc.vlsm("10.0.0.0/24", {"A": 100, "B": 50})
        bad[1]["subnet"] = ipaddress.ip_network("10.0.0.64/26")
        self.assertEqual(len(netcalc.check_plan("10.0.0.0/24", bad)), 1)

    def test_min_base_prefix(self):
        self.assertEqual(netcalc.min_base_prefix("10.0.0.0/26", {"A": 50, "B": 30}),
                         ipaddress.ip_network("10.0.0.0/25"))

    def test_summarize(self):
        plan = netcalc.vlsm(netcalc.VARIANT_BASE, netcalc.VARIANT_DEPS,
                            netcalc.VARIANT_GROWTH)
        collapsed, sup = netcalc.summarize(plan)
        self.assertEqual(collapsed, [ipaddress.ip_network("10.5.5.0/25"),
                                     ipaddress.ip_network("10.5.5.128/27")])
        self.assertEqual(sup, ipaddress.ip_network("10.5.5.0/24"))

    def test_plan_summary(self):
        plan = netcalc.vlsm(netcalc.VARIANT_BASE, netcalc.VARIANT_DEPS, 0)
        s = netcalc.plan_summary(netcalc.VARIANT_BASE, plan)
        self.assertEqual((s["Всего адресов"], s["Выделено"], s["Свободно"]),
                         (256, 88, 168))


class TestAudit(unittest.TestCase):
    PLAN = {"Кредитный отдел": ipaddress.ip_network("10.5.5.64/26")}

    def codes(self, devices):
        return [code for _, code, _ in audit.audit(self.PLAN, devices)]

    def test_duplicate_and_broadcast(self):
        devices = [
            {"hostname": "pc1", "department": "Кредитный отдел", "ip": "10.5.5.70",
             "gateway": "10.5.5.65"},
            {"hostname": "pc2", "department": "Кредитный отдел", "ip": "10.5.5.70",
             "gateway": "10.5.5.65"},
            {"hostname": "pc3", "department": "Кредитный отдел", "ip": "10.5.5.127",
             "gateway": "10.5.5.65"},
        ]
        codes = self.codes(devices)
        self.assertIn("E5", codes)
        self.assertIn("E4", codes)

    def test_gateway_errors(self):
        devices = [
            {"hostname": "a", "department": "Кредитный отдел", "ip": "10.5.5.80", "gateway": "10.5.5.80"},
            {"hostname": "b", "department": "Кредитный отдел", "ip": "10.5.5.81", "gateway": "10.5.5.1"},
            {"hostname": "c", "department": "Кредитный отдел", "ip": "10.5.5.82", "gateway": "10.5.5.126"},
            {"hostname": "d", "department": "Кредитный отдел", "ip": "10.5.5.83", "gateway": "x"},
        ]
        self.assertEqual(self.codes(devices), ["E7", "E6", "W1", "E1"])


class TestPingParsing(unittest.TestCase):
    def test_parse_times(self):
        out = ("Ответ от 8.8.8.8: число байт=32 время=12мс TTL=117\n"
               "Reply from 10.0.0.1: bytes=32 time<1ms TTL=64\n"
               "64 bytes from 8.8.8.8: icmp_seq=1 ttl=117 time=14.5 ms\n")
        self.assertEqual(netdiag.parse_ping_times(out), [12.0, 1.0, 14.5])

    def test_parse_gateway(self):
        win = "          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.105     35\n"
        self.assertEqual(netdiag.parse_gateway("Windows", win), "192.168.1.1")
        self.assertEqual(netdiag.parse_gateway("Darwin", "   gateway: 10.0.0.1\n"), "10.0.0.1")
        self.assertEqual(netdiag.parse_gateway("Linux", "default via 172.16.0.1 dev wlan0"),
                         "172.16.0.1")


if __name__ == "__main__":
    unittest.main()
