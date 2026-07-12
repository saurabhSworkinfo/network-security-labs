# Raw TCP/UDP Packet Crafting

Manual construction of TCP and UDP packets from scratch using raw sockets — no Scapy or other packet-crafting libraries. Headers are built byte-by-byte with Python's `struct` module, and checksums are computed manually per RFC 793 (TCP) and RFC 768 (UDP).

## Objective

Application-level socket programming (`SOCK_STREAM` / `SOCK_DGRAM`) hides the transport layer entirely — the kernel handles header construction, sequencing, and checksums. This lab removes that abstraction: packets are crafted field-by-field using `SOCK_RAW`, to build an accurate mental model of how TCP and UDP actually represent data on the wire, and how the pseudo-header ties the transport layer to IP-layer addressing during checksum validation.

## Directory Structure

```
raw-tcp-udp-packets/
├── src/
│   ├── tcp_raw.py
│   └── udp_raw.py
├── screenshots/
│   ├── tcp_syn_packet_capture.png
│   └── udp_packet_capture.png
└── README.md
```

## Socket Model Used

Both scripts use:

```python
socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)  # or IPPROTO_UDP
```

This is **`SOCK_RAW` without `IP_HDRINCL`** — the IP header is still constructed by the kernel (source/destination IP, TTL, IP checksum, fragmentation flags). Only the transport-layer header (TCP or UDP) and payload are built manually and passed to `sendto()`. Full manual IP header construction (`IP_HDRINCL`) is covered separately in `raw-ip-icmp`.

---

## TCP Packet — `src/tcp_raw.py`

### Header Layout (20 bytes, no options)

| Field | Offset (bytes) | Size | Description |
|---|---|---|---|
| Source Port | 0–1 | 2 | Sending application's port |
| Destination Port | 2–3 | 2 | Receiving application's port |
| Sequence Number | 4–7 | 4 | Byte-stream position |
| Acknowledgment Number | 8–11 | 4 | Valid only when ACK flag is set |
| Data Offset / Reserved / Flags | 12–13 | 2 | 4-bit header length (in 32-bit words) + 3 reserved bits + 9 control flag bits |
| Window Size | 14–15 | 2 | Flow-control advertisement |
| Checksum | 16–17 | 2 | Computed over pseudo-header + header + data |
| Urgent Pointer | 18–19 | 2 | Valid only when URG flag is set |

The script sets `data_offset = 5` (5 × 4 = 20 bytes, no options) and `flags = 0x002` (SYN).

### Checksum Procedure

1. Build the TCP header with the checksum field set to `0`.
2. Build a 12-byte pseudo-header: source IP, destination IP, a zero byte, protocol number (`6` for TCP), and TCP segment length (header + payload).
3. Compute a one's-complement sum over `pseudo_header + header(checksum=0) + payload`, folding carries beyond 16 bits back into the lower 16 bits.
4. Rebuild the header with the computed checksum inserted.
5. Concatenate the final header with the payload and send via `sendto()`.

The pseudo-header exists because TCP is a reliable, connection-oriented protocol — it needs a way to detect if a segment has been misrouted or if its IP addressing was corrupted in transit, even though the IP header itself isn't part of the TCP checksum's "real" scope on the wire.

### Run

```bash
sudo python3 src/tcp_raw.py
```

Root privileges are required — raw sockets need `CAP_NET_RAW`.

---

## UDP Packet — `src/udp_raw.py`

### Header Layout (8 bytes, fixed)

| Field | Offset (bytes) | Size | Description |
|---|---|---|---|
| Source Port | 0–1 | 2 | Sending application's port |
| Destination Port | 2–3 | 2 | Receiving application's port |
| Length | 4–5 | 2 | UDP header + payload length (minimum 8) |
| Checksum | 6–7 | 2 | Computed over pseudo-header + header + data |

Unlike TCP, UDP has no options and no flags — the header length is always fixed, so there is no data-offset field.

### Checksum Procedure

Identical structure to TCP, with two differences:

- The pseudo-header uses protocol number `17` (UDP) instead of `6`.
- Per RFC 768, if the computed checksum evaluates to `0x0000`, it is transmitted as `0xFFFF` instead. A checksum field of all-zero has a reserved meaning in IPv4 UDP ("checksum not used"), so a genuine zero result must be avoided.

### Run

```bash
sudo python3 src/udp_raw.py
```

---

## Verification (Wireshark)

Both packets were captured on a live interface and inspected in Wireshark to confirm the manually computed fields matched correct protocol semantics.

**TCP** (`screenshots/tcp_syn_packet_capture.png`) — SYN flag correctly decoded, header fields (ports, sequence number, window size) parsed cleanly by Wireshark's dissector.

**UDP** (`screenshots/udp_packet_capture.png`) — captured with `udp.port==9091` (a non-well-known port, chosen deliberately). An earlier capture using destination port 53 triggered Wireshark's DNS dissector, which flagged the packet as "Malformed" — this was expected: port 53 has no special meaning to the kernel or the wire format, but Wireshark auto-selects a protocol dissector based on port number, and the payload here was plain text, not a valid DNS message. Re-running against port 9091 avoided dissector misidentification and confirmed the correct field values: `Length: 27` (8-byte header + 19-byte payload), correct source/destination ports, and correctly parsed payload bytes.

Wireshark's checksum validation is disabled by default (`Checksum Status: Unverified`) since checksum offloading is normally handled by NIC hardware. This does not indicate an incorrect checksum — it means Wireshark did not attempt validation. Manual field inspection was used to confirm correctness for this exercise.

## Key Learnings

- The pseudo-header binds the transport-layer checksum to IP-layer addressing, so that a corrupted or misrouted IP header will invalidate the checksum even though the pseudo-header itself is never transmitted on the wire.
- Checksum computation is a 16-bit one's-complement sum with end-around carry folding, taken over the pseudo-header, the header (with the checksum field zeroed), and the payload.
- TCP's data-offset field expresses header length in 32-bit words, not bytes — this is what allows TCP options to extend the header while still letting a receiver locate where the payload begins.
- UDP checksum has a defined zero-value exception (RFC 768) that does not exist for TCP.
- Wireshark's protocol dissection is port-based, not content-based — using a well-known port number (e.g. 53) with a non-conforming payload will produce a dissector error, not a wire-format error.
- `SOCK_RAW` without `IP_HDRINCL` still delegates IP header construction to the kernel; full control over IP-layer fields requires `IP_HDRINCL`, covered in `raw-ip-icmp`.
