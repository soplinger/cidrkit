"""Tests for cidrkit. Run with `python3 -m pytest` or `python3 -m unittest discover -s tests`."""

import contextlib
import ipaddress
import io
import os
import sys
import tempfile
import unittest
from argparse import Namespace

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import cidrkit  # noqa: E402
from cidrkit import CidrKitError  # noqa: E402

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")

BROKEN_PLAN = """@parent 10.20.0.0/16
web      10.20.1.0/24
db       10.20.1.5/24       # host bits set
web      10.20.2.0/24       # duplicate name
backup   10.30.0.0/24       # outside the parent
cache    10.20.1.128/25     # overlaps web
bogus    10.20.9.0/33       # invalid prefix
too many fields here please
"""


def net(text):
    return ipaddress.ip_network(text)


class DetailsTests(unittest.TestCase):
    def test_slash24_usable_range(self):
        details = cidrkit.network_details(net("10.1.2.0/24"))
        self.assertEqual(details["first_usable"], "10.1.2.1")
        self.assertEqual(details["last_usable"], "10.1.2.254")
        self.assertEqual(details["usable_hosts"], 254)
        self.assertEqual(details["broadcast"], "10.1.2.255")
        self.assertEqual(details["wildcard"], "0.0.0.255")

    def test_slash31_is_point_to_point(self):
        details = cidrkit.network_details(net("10.0.0.0/31"))
        self.assertEqual(details["usable_hosts"], 2)
        self.assertIsNone(details["broadcast"])
        self.assertEqual(details["last_usable"], "10.0.0.1")

    def test_slash32_is_single_host(self):
        details = cidrkit.network_details(net("10.0.0.7/32"))
        self.assertEqual(details["usable_hosts"], 1)
        self.assertEqual(details["first_usable"], "10.0.0.7")
        self.assertEqual(details["last_usable"], "10.0.0.7")

    def test_slash30_has_two_hosts(self):
        details = cidrkit.network_details(net("192.168.0.0/30"))
        self.assertEqual(details["usable_hosts"], 2)
        self.assertEqual(details["first_usable"], "192.168.0.1")
        self.assertEqual(details["last_usable"], "192.168.0.2")

    def test_slash0_counts_all_hosts(self):
        details = cidrkit.network_details(net("0.0.0.0/0"))
        self.assertEqual(details["usable_hosts"], 2**32 - 2)

    def test_ipv6_slash64_has_no_broadcast(self):
        details = cidrkit.network_details(net("2001:db8::/64"))
        self.assertNotIn("broadcast", details)
        self.assertEqual(details["usable_hosts"], 2**64 - 1)
        self.assertEqual(details["first_usable"], "2001:db8::1")

    def test_ipv6_slash127_uses_both_addresses(self):
        details = cidrkit.network_details(net("2001:db8::/127"))
        self.assertEqual(details["usable_hosts"], 2)


class ParseTests(unittest.TestCase):
    def test_parse_network_rejects_host_bits(self):
        with self.assertRaises(CidrKitError):
            cidrkit.parse_network("10.0.0.5/24")

    def test_parse_network_accepts_plain_address_as_host_route(self):
        self.assertEqual(cidrkit.parse_network("10.0.0.5"), net("10.0.0.5/32"))

    def test_plan_host_bits_suggests_fix_with_line_number(self):
        plan = cidrkit.parse_plan("web 10.20.1.5/24\n")
        self.assertEqual(plan.errors[0][0], 1)
        self.assertIn("did you mean 10.20.1.0/24", plan.errors[0][1])

    def test_plan_comments_blanks_and_parent(self):
        plan = cidrkit.parse_plan("# header\n\n@parent 10.0.0.0/8  # top\nlan 10.1.0.0/16\n")
        self.assertEqual(plan.parent, net("10.0.0.0/8"))
        self.assertEqual([e.name for e in plan.entries], ["lan"])
        self.assertEqual(plan.entries[0].line, 4)

    def test_plan_unnamed_entry_is_named_by_cidr(self):
        plan = cidrkit.parse_plan("10.0.0.0/24\n")
        self.assertEqual(plan.entries[0].name, "10.0.0.0/24")

    def test_plan_duplicate_name_reports_first_line(self):
        plan = cidrkit.parse_plan("a 10.0.0.0/24\na 10.0.1.0/24\n")
        self.assertEqual(plan.errors, [(2, "duplicate name 'a' (first at line 1)")])

    def test_plan_field_count_error(self):
        plan = cidrkit.parse_plan("a b c\n")
        self.assertEqual(plan.errors, [(1, "expected 'name cidr' but found 3 fields")])

    def test_plan_invalid_name_error(self):
        plan = cidrkit.parse_plan("bad/name 10.0.0.0/24\n")
        self.assertEqual(len(plan.errors), 1)
        self.assertEqual(plan.errors[0][0], 1)

    def test_plan_invalid_prefix_error(self):
        plan = cidrkit.parse_plan("x 10.0.0.0/33\n")
        self.assertIn("invalid CIDR", plan.errors[0][1])

    def test_requirements_zero_hosts_fails_with_line(self):
        with self.assertRaises(CidrKitError) as ctx:
            cidrkit.parse_requirements("ok 5\nbad 0\n", "reqs.txt")
        self.assertIn("reqs.txt:2", str(ctx.exception))

    def test_requirements_parses_names_and_counts(self):
        self.assertEqual(cidrkit.parse_requirements("sales 50\nguest 20\n"),
                         [("sales", 50), ("guest", 20)])


class LintTests(unittest.TestCase):
    def test_broken_plan_reports_each_problem_on_its_line(self):
        errors = cidrkit.lint_plan(cidrkit.parse_plan(BROKEN_PLAN))
        lines = [line for line, _ in errors]
        self.assertEqual(lines, [3, 4, 5, 6, 7, 8])

    def test_overlap_message_names_both_entries(self):
        errors = cidrkit.lint_plan(cidrkit.parse_plan(BROKEN_PLAN))
        overlap = [message for line, message in errors if line == 6][0]
        self.assertIn("cache 10.20.1.128/25 overlaps web 10.20.1.0/24 (line 2)", overlap)

    def test_outside_parent_is_flagged(self):
        plan = cidrkit.parse_plan("@parent 10.0.0.0/16\nx 10.1.0.0/24\n")
        errors = cidrkit.lint_plan(plan)
        self.assertEqual(len(errors), 1)
        self.assertIn("outside @parent 10.0.0.0/16", errors[0][1])

    def test_clean_plan_has_no_errors(self):
        with open(os.path.join(ROOT, "examples", "office.plan"), encoding="utf-8") as handle:
            plan = cidrkit.parse_plan(handle.read())
        self.assertEqual(cidrkit.lint_plan(plan), [])
        self.assertEqual(len(plan.entries), 5)


class SplitSummarizeTests(unittest.TestCase):
    def test_split_by_count_rounds_up_to_power_of_two(self):
        subnets = cidrkit.split_network(net("10.0.0.0/24"), count=3)
        self.assertEqual([str(s) for s in subnets],
                         ["10.0.0.0/26", "10.0.0.64/26", "10.0.0.128/26", "10.0.0.192/26"])

    def test_split_count_one_returns_the_block(self):
        self.assertEqual(cidrkit.split_network(net("10.0.0.0/30"), count=1), [net("10.0.0.0/30")])

    def test_split_by_prefix(self):
        subnets = cidrkit.split_network(net("10.0.0.0/24"), new_prefix=26)
        self.assertEqual(len(subnets), 4)

    def test_split_rejects_shorter_prefix(self):
        with self.assertRaises(CidrKitError):
            cidrkit.split_network(net("10.0.0.0/24"), new_prefix=16)

    def test_split_rejects_huge_output(self):
        with self.assertRaises(CidrKitError):
            cidrkit.split_network(net("10.0.0.0/8"), new_prefix=32)

    def test_split_needs_exactly_one_mode(self):
        with self.assertRaises(CidrKitError):
            cidrkit.split_network(net("10.0.0.0/24"))

    def test_summarize_merges_adjacent_halves(self):
        blocks = cidrkit.summarize([net("10.0.0.0/25"), net("10.0.0.128/25")])
        self.assertEqual([str(b) for b in blocks], ["10.0.0.0/24"])

    def test_summarize_rejects_mixed_versions(self):
        with self.assertRaises(CidrKitError):
            cidrkit.summarize([net("10.0.0.0/24"), net("2001:db8::/32")])

    def test_range_to_minimal_cidrs(self):
        blocks = list(ipaddress.summarize_address_range(
            ipaddress.ip_address("10.0.0.5"), ipaddress.ip_address("10.0.0.20")))
        self.assertEqual([str(b) for b in blocks],
                         ["10.0.0.5/32", "10.0.0.6/31", "10.0.0.8/29", "10.0.0.16/30", "10.0.0.20/32"])


class VlsmTests(unittest.TestCase):
    def requirements(self):
        with open(os.path.join(ROOT, "examples", "requirements.txt"), encoding="utf-8") as handle:
            return cidrkit.parse_requirements(handle.read())

    def test_vlsm_allocates_largest_first_with_alignment(self):
        allocations, _ = cidrkit.plan_vlsm(net("10.20.0.0/16"), self.requirements())
        by_name = {a.name: str(a.network) for a in allocations}
        self.assertEqual(by_name["engineering"], "10.20.0.0/25")
        self.assertEqual(by_name["sales"], "10.20.0.128/26")
        self.assertEqual(by_name["guest"], "10.20.0.192/27")
        self.assertEqual(by_name["servers"], "10.20.0.224/27")
        self.assertEqual(by_name["voip"], "10.20.1.0/28")
        self.assertEqual(by_name["uplink"], "10.20.1.16/30")

    def test_vlsm_free_space_accounts_for_every_address(self):
        allocations, free = cidrkit.plan_vlsm(net("10.20.0.0/16"), self.requirements())
        used = sum(a.network.num_addresses for a in allocations)
        self.assertEqual(sum(b.num_addresses for b in free), 65536 - used)

    def test_vlsm_exhaustion_is_a_clear_error(self):
        with self.assertRaises(CidrKitError) as ctx:
            cidrkit.plan_vlsm(net("10.0.0.0/30"), [("first", 2), ("second", 2)])
        self.assertIn("no room for second", str(ctx.exception))

    def test_vlsm_requirement_larger_than_parent(self):
        with self.assertRaises(CidrKitError):
            cidrkit.plan_vlsm(net("10.0.0.0/24"), [("huge", 300)])

    def test_vlsm_rejects_ipv6_parent(self):
        with self.assertRaises(CidrKitError):
            cidrkit.plan_vlsm(net("2001:db8::/32"), [("x", 2)])


class FreeAndLookupTests(unittest.TestCase):
    def test_free_blocks_after_one_allocation(self):
        blocks = cidrkit.free_blocks(net("10.0.0.0/24"), [net("10.0.0.0/26")])
        self.assertEqual([str(b) for b in blocks], ["10.0.0.64/26", "10.0.0.128/25"])

    def test_free_blocks_fully_covered_is_empty(self):
        self.assertEqual(cidrkit.free_blocks(net("10.0.0.0/24"), [net("10.0.0.0/23")]), [])

    def test_which_text_separates_long_names_from_networks(self):
        with tempfile.NamedTemporaryFile("w", suffix=".plan", delete=False, encoding="utf-8") as handle:
            handle.write("engineering-floor2 10.0.0.0/24\n")
            path = handle.name
        try:
            _, text = cidrkit.cmd_which(Namespace(address="10.0.0.9", source=path))
        finally:
            os.unlink(path)
        self.assertIn("engineering-floor2  10.0.0.0/24", text)

    def test_which_returns_most_specific_first(self):
        with tempfile.NamedTemporaryFile("w", suffix=".plan", delete=False, encoding="utf-8") as handle:
            handle.write("wide 10.0.0.0/16\nnarrow 10.0.5.0/24\n")
            path = handle.name
        try:
            payload, _ = cidrkit.cmd_which(Namespace(address="10.0.5.9", source=path))
        finally:
            os.unlink(path)
        self.assertEqual([m["name"] for m in payload["matches"]], ["narrow", "wide"])

    def test_classify_private_and_global(self):
        self.assertIn("private", cidrkit.classify(ipaddress.ip_address("10.1.2.3")))
        self.assertIn("global", cidrkit.classify(ipaddress.ip_address("8.8.8.8")))
        self.assertNotIn("global", cidrkit.classify(ipaddress.ip_address("10.1.2.3")))

    def test_classify_cli_keeps_typed_host_address(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            cidrkit.main(["classify", "192.168.1.10/24"])
        self.assertTrue(out.getvalue().startswith("192.168.1.10: "))


class ReverseZoneTests(unittest.TestCase):
    def test_ipv4_octet_aligned_zone(self):
        self.assertEqual(cidrkit.reverse_zone(net("10.0.0.0/8")), ("10.in-addr.arpa", None))

    def test_ipv4_slash25_gets_rfc2317_label(self):
        zone, label = cidrkit.reverse_zone(net("10.20.2.128/25"))
        self.assertEqual(zone, "2.20.10.in-addr.arpa")
        self.assertEqual(label, "128-255.2.20.10.in-addr.arpa")

    def test_ipv6_nibble_zone(self):
        zone, label = cidrkit.reverse_zone(net("2001:db8::/32"))
        self.assertEqual(zone, "8.b.d.0.1.0.0.2.ip6.arpa")
        self.assertIsNone(label)


class CliTests(unittest.TestCase):
    def run_cli(self, argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            status = cidrkit.main(argv)
        return status, out.getvalue(), err.getvalue()

    def test_info_text_shows_usable_range(self):
        status, out, _ = self.run_cli(["info", "10.1.2.0/24"])
        self.assertEqual(status, 0)
        self.assertIn("10.1.2.1 - 10.1.2.254 (254)", out)

    def test_bad_input_exits_two_with_message(self):
        status, out, err = self.run_cli(["split", "10.0.0.1/24", "--count", "2"])
        self.assertEqual(status, 2)
        self.assertIn("cidrkit: error:", err)
        self.assertEqual(out, "")

    def test_lint_with_errors_exits_one_and_lists_lines(self):
        with tempfile.NamedTemporaryFile("w", suffix=".plan", delete=False, encoding="utf-8") as handle:
            handle.write(BROKEN_PLAN)
            path = handle.name
        try:
            status, out, _ = self.run_cli(["lint", path])
        finally:
            os.unlink(path)
        self.assertEqual(status, 1)
        self.assertIn("line 3: 10.20.1.5/24 has host bits set", out)

    def test_json_output_is_parseable(self):
        import json
        status, out, _ = self.run_cli(["ptr", "10.20.2.128/25", "--json"])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(out)["zone"], "2.20.10.in-addr.arpa")


if __name__ == "__main__":
    unittest.main()
