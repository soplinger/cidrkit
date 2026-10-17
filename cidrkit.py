"""cidrkit: offline IPv4/IPv6 subnet planner built on the standard library.

Plan files are plain text. Each line holds either ``name cidr`` or just ``cidr``,
and ``#`` starts a comment. An optional ``@parent cidr`` line names the block
that every entry must sit inside.
"""

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass, field

MAX_SPLIT = 65536
NAME_RE = re.compile(r"[A-Za-z0-9_.\-]+")
CLASS_LABELS = ("is_loopback", "is_link_local", "is_private", "is_multicast",
                "is_reserved", "is_unspecified")


class CidrKitError(Exception):
    """A user-facing failure. The CLI prints it to stderr and exits with 2."""


@dataclass(frozen=True)
class Entry:
    line: int
    name: str
    network: object


@dataclass
class Plan:
    parent: object = None
    entries: list = field(default_factory=list)
    errors: list = field(default_factory=list)  # (line, message)


@dataclass(frozen=True)
class Allocation:
    name: str
    hosts: int
    network: object


def parse_network(text):
    """Parse a strict CIDR block, rejecting host bits that are set."""
    try:
        return ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise CidrKitError(f"invalid network {text!r}: {exc}") from None


def parse_address(text):
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        raise CidrKitError(f"invalid IP address {text!r}") from None


def _check_cidr(text):
    """Return (network, None) on success or (None, message) on failure."""
    try:
        return ipaddress.ip_network(text, strict=True), None
    except ValueError as exc:
        if "host bits" in str(exc):
            fixed = ipaddress.ip_network(text, strict=False)
            return None, f"{text} has host bits set; did you mean {fixed}?"
        return None, f"invalid CIDR {text!r}"


def _tokens(text):
    """Yield (line_number, tokens) for each non-blank, non-comment line."""
    for number, raw in enumerate(text.splitlines(), start=1):
        tokens = raw.split("#", 1)[0].split()
        if tokens:
            yield number, tokens


def parse_plan(text):
    """Parse a plan file, collecting every error with its line number."""
    plan = Plan()
    first_seen = {}
    parent_line = None
    for number, tokens in _tokens(text):
        if tokens[0] == "@parent":
            if len(tokens) != 2:
                plan.errors.append((number, "@parent takes exactly one CIDR"))
            elif parent_line is not None:
                plan.errors.append((number, f"duplicate @parent (first at line {parent_line})"))
            else:
                parent_line = number
                plan.parent, problem = _check_cidr(tokens[1])
                if problem:
                    plan.errors.append((number, problem))
            continue
        if len(tokens) > 2:
            plan.errors.append((number, f"expected 'name cidr' but found {len(tokens)} fields"))
            continue
        if len(tokens) == 2:
            name, cidr = tokens
            if not NAME_RE.fullmatch(name):
                plan.errors.append((number, f"invalid name {name!r} (use letters, digits, '.', '_' or '-')"))
                continue
        else:
            name = cidr = tokens[0]
        network, problem = _check_cidr(cidr)
        if problem:
            plan.errors.append((number, problem))
            continue
        if name in first_seen:
            plan.errors.append((number, f"duplicate name {name!r} (first at line {first_seen[name]})"))
            continue
        first_seen[name] = number
        plan.entries.append(Entry(number, name, network))
    return plan


def lint_plan(plan):
    """Return sorted (line, message) errors: parse errors, outside-parent and overlaps."""
    errors = list(plan.errors)
    for position, entry in enumerate(plan.entries):
        if plan.parent is not None:
            inside = (entry.network.version == plan.parent.version
                      and entry.network.subnet_of(plan.parent))
            if not inside:
                errors.append((entry.line, f"{entry.name} {entry.network} is outside @parent {plan.parent}"))
        for earlier in plan.entries[:position]:
            if (earlier.network.version == entry.network.version
                    and earlier.network.overlaps(entry.network)):
                errors.append((entry.line, f"{entry.name} {entry.network} overlaps "
                                           f"{earlier.name} {earlier.network} (line {earlier.line})"))
    return sorted(errors)


def parse_requirements(text, source="requirements"):
    """Parse 'name hosts' lines for VLSM. Fails on the first bad line."""
    requirements = []
    names = set()
    for number, tokens in _tokens(text):
        if len(tokens) != 2:
            raise CidrKitError(f"{source}:{number}: expected 'name hosts', found {len(tokens)} field(s)")
        name, hosts_text = tokens
        if not NAME_RE.fullmatch(name):
            raise CidrKitError(f"{source}:{number}: invalid name {name!r}")
        try:
            hosts = int(hosts_text)
        except ValueError:
            raise CidrKitError(f"{source}:{number}: hosts must be a whole number, got {hosts_text!r}") from None
        if hosts < 1:
            raise CidrKitError(f"{source}:{number}: hosts must be at least 1, got {hosts}")
        if name in names:
            raise CidrKitError(f"{source}:{number}: duplicate name {name!r}")
        names.add(name)
        requirements.append((name, hosts))
    return requirements


def usable_range(net):
    """Return (first, last, count) of usable host addresses, per RFC 3021 for IPv4 /31."""
    if net.version == 4:
        if net.prefixlen >= 31:
            return net.network_address, net.broadcast_address, net.num_addresses
        return net[1], net.broadcast_address - 1, net.num_addresses - 2
    if net.prefixlen >= 127:
        return net.network_address, net.broadcast_address, net.num_addresses
    return net[1], net.broadcast_address, net.num_addresses - 1


def network_details(net):
    first, last, count = usable_range(net)
    details = {
        "version": net.version,
        "network": str(net.network_address),
        "prefix": net.prefixlen,
        "netmask": str(net.netmask),
        "wildcard": str(net.hostmask),
        "addresses": net.num_addresses,
        "first_usable": str(first),
        "last_usable": str(last),
        "usable_hosts": count,
    }
    if net.version == 4:
        details["broadcast"] = None if net.prefixlen == 31 else str(net.broadcast_address)
    return details


def split_network(net, new_prefix=None, count=None):
    """Split a block by target prefix length, or into at least `count` equal pieces."""
    if (new_prefix is None) == (count is None):
        raise CidrKitError("give exactly one of --prefix or --count")
    if count is not None:
        if count < 1:
            raise CidrKitError("--count must be at least 1")
        new_prefix = net.prefixlen + (count - 1).bit_length()
    if not net.prefixlen <= new_prefix <= net.max_prefixlen:
        raise CidrKitError(f"cannot split {net} into /{new_prefix} subnets")
    if 1 << (new_prefix - net.prefixlen) > MAX_SPLIT:
        raise CidrKitError(f"splitting {net} into /{new_prefix} gives more than {MAX_SPLIT} subnets")
    return list(net.subnets(new_prefix=new_prefix))


def plan_vlsm(parent, requirements):
    """Allocate largest-first with alignment. Return (allocations in address order, free blocks)."""
    if parent.version != 4:
        raise CidrKitError("vlsm supports IPv4 parents only")
    sized = []
    for index, (name, hosts) in enumerate(requirements):
        bits = (hosts + 1).bit_length()  # network + broadcast, rounded up to a power of two
        prefix = 32 - bits
        if prefix < parent.prefixlen:
            raise CidrKitError(f"{name} needs /{prefix} for {hosts} hosts, which is larger than {parent}")
        sized.append((bits, index, name, hosts, prefix))
    sized.sort(key=lambda row: (-row[0], row[1]))

    last = int(parent.broadcast_address)
    cursor = int(parent.network_address)
    allocations = []
    for bits, _, name, hosts, prefix in sized:
        size = 1 << bits
        start = -(-cursor // size) * size
        if start + size - 1 > last:
            free = free_blocks(parent, [a.network for a in allocations])
            largest = max(free, key=lambda b: b.num_addresses, default=None)
            where = f"largest free block is {largest}" if largest else "no free space left"
            raise CidrKitError(f"no room for {name} (/{prefix}, {hosts} hosts) in {parent}; {where}")
        network = ipaddress.ip_network(f"{ipaddress.IPv4Address(start)}/{prefix}")
        allocations.append(Allocation(name, hosts, network))
        cursor = start + size
    allocations.sort(key=lambda a: int(a.network.network_address))
    return allocations, free_blocks(parent, [a.network for a in allocations])


def free_blocks(parent, networks):
    """Return the minimal CIDR blocks of `parent` not covered by any of `networks`."""
    free = [parent]
    for taken in networks:
        if taken.version != parent.version:
            continue
        remaining = []
        for block in free:
            if not block.overlaps(taken):
                remaining.append(block)
            elif block.subnet_of(taken):
                continue
            else:
                remaining.extend(block.address_exclude(taken))
        free = remaining
    return list(ipaddress.collapse_addresses(free))


def summarize(networks):
    if len({n.version for n in networks}) > 1:
        raise CidrKitError("cannot summarize IPv4 and IPv6 together")
    return list(ipaddress.collapse_addresses(networks))


def reverse_zone(net):
    """Return (zone, rfc2317_label) for a block. The label is set only for /25-/31 blocks."""
    if net.version == 4:
        octets = str(net.network_address).split(".")[:net.prefixlen // 8]
        zone = ".".join(list(reversed(octets)) + ["in-addr", "arpa"])
        if 25 <= net.prefixlen <= 31:
            first = int(net.network_address.packed[3])
            last = int(net.broadcast_address.packed[3])
            base = ".".join(reversed(str(net.network_address).split(".")[:3]))
            return zone, f"{first}-{last}.{base}.in-addr.arpa"
        return zone, None
    nibbles = net.network_address.packed.hex()[:net.prefixlen // 4]
    return ".".join(list(reversed(nibbles)) + ["ip6", "arpa"]), None


def classify(addr):
    labels = [attr[3:] for attr in CLASS_LABELS if getattr(addr, attr)]
    if addr.is_global:
        labels.insert(0, "global")
    return labels


def _read(source):
    if source == "-":
        return sys.stdin.read()
    try:
        with open(source, encoding="utf-8") as handle:
            return handle.read()
    except (OSError, UnicodeDecodeError) as exc:
        raise CidrKitError(f"cannot read {source}: {getattr(exc, 'strerror', None) or exc}") from None


def _load_plan(source):
    plan = parse_plan(_read(source))
    if plan.errors:
        line, message = min(plan.errors)
        raise CidrKitError(f"{source}:{line}: {message} (run 'cidrkit lint {source}' to see all errors)")
    return plan


def _table(headers, rows):
    cols = list(zip(headers, *rows))
    widths = [max(len(str(cell)) for cell in col) for col in cols]
    fmt = "  ".join("{:<%d}" % w for w in widths)
    lines = [fmt.format(*headers), fmt.format(*("-" * w for w in widths))]
    lines += [fmt.format(*(str(cell) for cell in row)) for row in rows]
    return lines


def cmd_info(args):
    try:
        iface = ipaddress.ip_interface(args.address)
    except ValueError as exc:
        raise CidrKitError(f"invalid address {args.address!r}: {exc}") from None
    details = network_details(iface.network)
    rows = []
    if iface.ip != iface.network.network_address:
        details["address"] = str(iface.ip)
        rows.append(("Address", details["address"]))
    rows += [
        ("Network", f"{details['network']}/{details['prefix']}"),
        ("Netmask", details["netmask"]),
        ("Wildcard", details["wildcard"]),
    ]
    if details["version"] == 4:
        broadcast = details["broadcast"] or "none (point-to-point, RFC 3021)"
        rows.append(("Broadcast", broadcast))
    rows += [
        ("Usable hosts", f"{details['first_usable']} - {details['last_usable']} ({details['usable_hosts']})"),
        ("Addresses", details["addresses"]),
    ]
    text = "\n".join(f"{label + ':':<15}{value}" for label, value in rows)
    return details, text


def cmd_split(args):
    net = parse_network(args.cidr)
    subnets = split_network(net, new_prefix=args.prefix, count=args.count)
    payload = {"parent": str(net), "prefix": subnets[0].prefixlen, "subnets": [str(s) for s in subnets]}
    lines = [str(s) for s in subnets]
    if args.count and len(subnets) != args.count:
        lines.insert(0, f"note: {args.count} requested, rounded up to {len(subnets)} (a power of two)")
    return payload, "\n".join(lines)


def cmd_vlsm(args):
    parent = parse_network(args.parent)
    requirements = parse_requirements(_read(args.requirements), args.requirements)
    allocations, free = plan_vlsm(parent, requirements)
    payload = {
        "parent": str(parent),
        "allocations": [{"name": a.name, "hosts": a.hosts, "network": str(a.network),
                         "usable": a.network.num_addresses - 2} for a in allocations],
        "free": [str(b) for b in free],
    }
    rows = [(a.name, a.hosts, a.network, a.network.num_addresses - 2) for a in allocations]
    lines = _table(("NAME", "HOSTS", "NETWORK", "USABLE"), rows)
    lines.append("")
    lines.append("free: " + (", ".join(str(b) for b in free) or "none"))
    return payload, "\n".join(lines)


def cmd_summarize(args):
    nets = [e.network for e in _load_plan(args.source).entries]
    blocks = summarize(nets)
    payload = {"entries": len(nets), "blocks": [str(b) for b in blocks]}
    lines = [str(b) for b in blocks] or ["no entries"]
    lines.append(f"{len(nets)} entries -> {len(blocks)} blocks")
    return payload, "\n".join(lines)


def cmd_range(args):
    start, end = parse_address(args.start), parse_address(args.end)
    if start.version != end.version:
        raise CidrKitError("start and end must be the same IP version")
    if start > end:
        raise CidrKitError(f"start {start} is after end {end}")
    blocks = list(ipaddress.summarize_address_range(start, end))
    payload = {"start": str(start), "end": str(end), "blocks": [str(b) for b in blocks]}
    return payload, "\n".join(str(b) for b in blocks)


def cmd_which(args):
    address = parse_address(args.address)
    entries = _load_plan(args.source).entries
    matches = sorted((e for e in entries if e.network.version == address.version and address in e.network),
                     key=lambda e: -e.network.prefixlen)
    payload = {"address": str(address),
               "matches": [{"name": e.name, "network": str(e.network), "line": e.line} for e in matches]}
    if not matches:
        return payload, f"no entry contains {address}"
    rows = [(e.name, e.network) for e in matches]
    return payload, "\n".join(_table(("NAME", "NETWORK"), rows))


def cmd_overlaps(args):
    entries = _load_plan(args.source).entries
    pairs = []
    for i, first in enumerate(entries):
        for second in entries[i + 1:]:
            if first.network.version == second.network.version and first.network.overlaps(second.network):
                pairs.append((first, second))
    payload = {"overlaps": [{"a": a.name, "a_line": a.line, "b": b.name, "b_line": b.line} for a, b in pairs]}
    if not pairs:
        return payload, "no overlaps"
    lines = [f"{a.name} (line {a.line}) overlaps {b.name} (line {b.line})" for a, b in pairs]
    return payload, "\n".join(lines)


def cmd_free(args):
    parent = parse_network(args.parent)
    entries = _load_plan(args.source).entries
    blocks = free_blocks(parent, [e.network for e in entries])
    free_total = sum(b.num_addresses for b in blocks)
    payload = {"parent": str(parent), "free": [str(b) for b in blocks], "free_addresses": free_total}
    rows = [(b, b.num_addresses, b.network_address, b.broadcast_address) for b in blocks]
    lines = _table(("FREE BLOCK", "ADDRESSES", "FIRST", "LAST"), rows) if rows else ["no free space"]
    lines.append(f"total free addresses: {free_total}")
    return payload, "\n".join(lines)


def cmd_ptr(args):
    net = parse_network(args.cidr)
    zone, rfc2317 = reverse_zone(net)
    payload = {"network": str(net), "zone": zone, "rfc2317": rfc2317}
    lines = [f"zone:   {zone}"]
    if rfc2317:
        lines.append(f"RFC 2317: {rfc2317}")
    return payload, "\n".join(lines)


def cmd_classify(args):
    try:
        address = ipaddress.ip_interface(args.address).ip
    except ValueError:
        raise CidrKitError(f"invalid address {args.address!r}") from None
    labels = classify(address)
    payload = {"address": str(address), "labels": labels}
    text = f"{address}: " + (", ".join(labels) if labels else "not global (no special label)")
    return payload, text


def cmd_lint(args):
    plan = parse_plan(_read(args.source))
    errors = lint_plan(plan)
    payload = {"source": args.source, "entries": len(plan.entries),
               "parent": str(plan.parent) if plan.parent else None,
               "errors": [{"line": line, "message": message} for line, message in errors]}
    if not errors:
        return payload, f"OK: {len(plan.entries)} entries checked"
    lines = [f"line {line}: {message}" for line, message in errors]
    lines.append(f"{len(errors)} error(s) in {args.source}")
    return payload, "\n".join(lines)


HANDLERS = {
    "info": cmd_info,
    "split": cmd_split,
    "vlsm": cmd_vlsm,
    "summarize": cmd_summarize,
    "range": cmd_range,
    "which": cmd_which,
    "overlaps": cmd_overlaps,
    "free": cmd_free,
    "ptr": cmd_ptr,
    "classify": cmd_classify,
    "lint": cmd_lint,
}


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--json", action="store_true", help="print machine-readable JSON")

    parser = argparse.ArgumentParser(
        prog="cidrkit",
        description="Offline IPv4/IPv6 subnet planner: inspect, split, allocate and lint CIDR plans.")
    sub = parser.add_subparsers(dest="command", required=True, metavar="COMMAND")

    p = sub.add_parser("info", parents=[common], help="describe a network or host address")
    p.add_argument("address", help="address or CIDR, e.g. 10.1.2.3/24")

    p = sub.add_parser("split", parents=[common], help="split a block by prefix or piece count")
    p.add_argument("cidr")
    group = p.add_mutually_exclusive_group(required=True)
    group.add_argument("--prefix", type=int, help="new prefix length")
    group.add_argument("--count", type=int, help="minimum number of equal subnets")

    p = sub.add_parser("vlsm", parents=[common], help="allocate subnets for named host counts")
    p.add_argument("parent", help="IPv4 block to allocate from")
    p.add_argument("requirements", help="file of 'name hosts' lines, or - for stdin")

    p = sub.add_parser("summarize", parents=[common], help="collapse a plan into the fewest CIDRs")
    p.add_argument("source", help="plan file, or - for stdin")

    p = sub.add_parser("range", parents=[common], help="convert an address range to CIDR blocks")
    p.add_argument("start")
    p.add_argument("end")

    p = sub.add_parser("which", parents=[common], help="find plan entries containing an address")
    p.add_argument("address")
    p.add_argument("source", help="plan file, or - for stdin")

    p = sub.add_parser("overlaps", parents=[common], help="list overlapping plan entries")
    p.add_argument("source", help="plan file, or - for stdin")

    p = sub.add_parser("free", parents=[common], help="show unallocated space inside a parent block")
    p.add_argument("parent")
    p.add_argument("source", help="plan file, or - for stdin")

    p = sub.add_parser("ptr", parents=[common], help="show the reverse-DNS zone for a block")
    p.add_argument("cidr")

    p = sub.add_parser("classify", parents=[common], help="label an address (private, multicast, ...)")
    p.add_argument("address")

    p = sub.add_parser("lint", parents=[common], help="check a plan file and report line-numbered errors")
    p.add_argument("source", help="plan file, or - for stdin")
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        payload, text = HANDLERS[args.command](args)
    except CidrKitError as exc:
        print(f"cidrkit: error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(payload, indent=2) if args.json else text)
    return 1 if payload.get("errors") else 0


if __name__ == "__main__":
    sys.exit(main())
