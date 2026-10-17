# cidrkit

**Offline IPv4/IPv6 subnet planner. Inspect, split, allocate and lint address plans from plain text, with no network access.**

cidrkit answers the questions you ask when you plan a network: what does this block contain, how do I carve it into pieces, which team gets which subnet, where is the free space, and does the plan have overlaps or typos. It is a single Python file built only on the standard library. Nothing is sent anywhere, and nothing needs an account or an API key.

## Features

- **`info`**: network, netmask, wildcard, broadcast, usable host range and host count for any IPv4 or IPv6 address or CIDR.
- **RFC 3021 handling**: `/31` point-to-point links have two usable hosts and no broadcast. `/32` and IPv6 `/127` and `/128` are handled explicitly.
- **`split`**: divide a block by target prefix (`--prefix 26`) or into at least N equal pieces (`--count 3`, rounded up to a power of two with a note).
- **`vlsm`**: allocate subnets for named host counts, largest first and aligned, from a requirements file. It fails with the largest remaining free block when space runs out.
- **`free`**: list the unallocated blocks inside a parent, as minimal CIDRs, with a total.
- **`summarize`**: collapse a plan into the fewest covering CIDRs.
- **`range`**: convert an address range such as `10.0.0.5`-`10.0.0.20` into the minimal set of CIDR blocks.
- **`which`**: find which plan entries contain an address, most specific first.
- **`overlaps`**: list every pair of overlapping entries with their line numbers.
- **`ptr`**: reverse-DNS zone for a block, plus the RFC 2317 delegation label for `/25`-`/31` blocks.
- **`classify`**: label an address as global, private, loopback, link-local, multicast, reserved or unspecified.
- **`lint`**: check a plan file and report every error with its line number: malformed lines, bad names, invalid CIDRs, host bits set (with the corrected network suggested), duplicate names, entries outside `@parent`, and overlaps. Exits 1 if anything is wrong, so it works in CI.
- **`--json`** on every command for scripting.
- **Clear failures**: user errors print `cidrkit: error: ...` to stderr and exit 2, never a traceback.

## Plan file format

```
# Office address plan
@parent 10.20.0.0/16

mgmt     10.20.0.0/26     # switches and routers
dmz      10.20.0.64/27
web      10.20.1.0/24
10.20.3.128/25            # unnamed entries are labelled by their CIDR
```

- `name cidr` or just `cidr` per line. `#` starts a comment.
- `@parent cidr` (optional, once) names the block every entry must sit inside.
- Names may use letters, digits, `.`, `_` and `-`.

Requirements for `vlsm` use the same comment rules, one `name hosts` pair per line (see `examples/requirements.txt`).

## Quick start

```sh
python3 cidrkit.py info 10.20.1.77/24
python3 cidrkit.py vlsm 10.20.0.0/16 examples/requirements.txt
python3 cidrkit.py lint examples/office.plan
python3 cidrkit.py free 10.20.0.0/16 examples/office.plan
```

The `examples/` directory has a clean plan (`office.plan`), a requirements file (`requirements.txt`) and a deliberately broken plan (`broken.plan`) so you can see what `lint` reports. Try:

```sh
python3 cidrkit.py lint examples/broken.plan
```

## How to run

Requires Python 3.8 or newer. No install step, no dependencies.

```sh
python3 cidrkit.py --help
python3 cidrkit.py COMMAND --help
python3 cidrkit.py COMMAND ... --json     # machine-readable output
python3 cidrkit.py lint - < plan.txt     # read a plan from stdin
```

Exit status: `0` success, `1` lint found errors, `2` bad input or usage.

## How to test

```sh
python3 -m unittest discover -s tests
```

With pytest installed, `python3 -m pytest tests` runs the same suite. The tests cover the RFC 3021 edge cases, IPv6 counts, host-bit rejection, line-numbered lint errors, VLSM alignment and exhaustion, free-space arithmetic, reverse-zone names and CLI exit codes.

## Notes and limits

- `vlsm` allocates IPv4 only. Each requirement gets `hosts + 2` addresses (network and broadcast) rounded up to a power of two, so the usable count is at least the requested hosts.
- IPv6 usable ranges skip the subnet-router anycast address (the first address) for prefixes shorter than `/127`.
- `split` refuses to produce more than 65,536 subnets at once.
- `ptr` prints delegation labels only for `/25`-`/31`. Other non-aligned blocks are covered by their enclosing zone.
