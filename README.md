# V2G

See what an electric vehicle and a charger say to each other, as signals in your Zelos workspace.

- **Every message, by name**: `CurrentDemandReq`, `DC_ChargeLoopRes`, `ChargeParameterDiscoveryRes`, ... each an event with its fields under their standard names, units and value tables
- **The whole link**: SLAC pairing, SDP discovery and the V2GTP message timeline, in order, one row per frame
- **DIN 70121, ISO 15118-2, ISO 15118-20**: DC and AC, the protocol picked per session from its handshake
- **TLS sessions**: decoded like cleartext ones when the charger or vehicle under test discloses its session secrets
- **Live or from a file**: capture on a network interface, or open a `.pcap`/`.pcapng`, plain or gzip/zstd compressed
- **One timeline**: charging messages line up with your CAN, power and sensor data
- **Demo**: a bundled DC charging session, for trying it without a charging link

Listen-only: the extension never sends on the link.

## Quick start

In the app:

1. **Install** V2G from the Extensions view
2. **Configure**: add an interface and pick the NIC that sees the charging link (a tap, a bridge, or the powerline modem's Ethernet side)
3. **Save & Start**
4. **Plot**: messages appear under **V2G → your interface**; drag `CurrentDemandRes → EVSEPresentVoltage` into the workspace

Live capture needs a one-time grant on the machine running the agent ([below](#granting-capture-rights)). Decoding a file needs nothing.

From the CLI, on the agent that can see the link:

```bash
zelos extensions install zeloscloud/zelos-extension-v2g
zelos extensions start zeloscloud.zelos-extension-v2g --config '{"interfaces": [{"interface": "eth0"}]}'
```

Decoding a file instead plays it once at the capture's pace, then the extension exits:

```bash
zelos extensions start zeloscloud.zelos-extension-v2g --config '{"advanced": {"replay_pcap": "session.pcapng"}}'
```

To turn a file into a `.trz` with the capture's own timestamps, run the **Convert** action or `uv run zelos-extension-v2g convert session.pcapng`.

## Try it without hardware

One ISO 15118-2 DC session ships with the extension, SDP to SessionStop, recorded between a software-in-the-loop charger and vehicle.

```bash
uv run zelos-extension-v2g --demo
```

It plays once and the extension exits.

## What you get

Everything lands under the **Prefix** source (default `V2G`), one branch per interface or file.

| Event | One row per | Fields |
| --- | --- | --- |
| `<name>/<Message>` | decoded message of that type | `session_id`, `protocol`, the header's fault and signature fields, then the message's fields under their schema names (`EVSEPresentVoltage`, `EVTargetCurrent`, `EVRESSSOC`, `ResponseCode`, ...) |
| `<name>/v2gtp` | V2GTP message | `direction`, `protocol`, `message`, `session_id`, `payload_type`, `length`, the EXI payload, `decode_error` |
| `<name>/sdp` | SDP request or response | `kind`, `secc_ip`, `secc_port`, `security`, `transport` |
| `<name>/slac` | HomePlug AV management frame | `name` (`CM_SLAC_PARM.REQ`, ...), `run_id`, sounds and attenuation, the matched EV and EVSE MAC addresses |
| `<name>/packets`, `<name>/stats` | captured frame, capture tick | addresses, ports, protocol, length, the first bytes of the frame; capture counters |
| `<name>/can/<iface>` | SocketCAN frame in a capture file | `arbitration_id`, `dlc`, `data`, flags |

- the event time is the capture time of the frame that completed the message
- a message several protocols share (`SessionSetupReq`, `PowerDeliveryReq`, ...) is one event; `protocol` says which sent the row
- physical values are scaled floats with their unit; enumerations are codes with value tables
- certificates, private keys and the SLAC network key are never recorded; `*_len` and `num_*` fields give their sizes and counts
- CAN frames in a capture are raw rows; signal decode from a DBC is the CAN extension's

## TLS sessions

A charger or vehicle under test can disclose its TLS session secrets, as test systems do. With them a TLS 1.2 or TLS 1.3 session decodes to the same rows as a cleartext one.

- **On the link**: an endpoint that sends its key log lines as UDP datagrams needs no configuration
- **From a file**: set **TLS Key Log File** to the key log file (NSS key log format) the endpoint writes. A live capture follows the file as it grows; a replay reads it once. The **Convert** action and the `convert` command take the file as their own argument

Secrets are used in memory to derive keys and never appear in a decoded row, counter or log line. The raw `packets` rows are the capture as captured: when an endpoint discloses secrets on the link, those datagrams are in `packets` like any other frame. Treat a trace of such a link as you would the key log itself.

## Granting capture rights

Capturing reads raw frames, which needs one grant per machine. Decoding a file does not.

```bash
uv run zelos-extension-v2g check        # when denied, prints the exact command for this machine
sudo /path/to/python -m zelos_packet install-helper
```

- **Linux** installs a small capture helper holding `cap_net_raw` only, and a `zelos-packet` group; **macOS** puts `/dev/bpf*` in the `access_bpf` group
- log out and back in, then restart the agent: a session's groups are fixed at login
- `python -m zelos_packet status` says whether capture would work right now
- **Windows**: `check` names the capture driver to install

A failed start says the same in the extension log. `V2G/check_permissions` reports it too, without the extension started.

## Settings

| Setting | Default | |
| --- | --- | --- |
| `interfaces[].interface` | | NIC that sees the charging link |
| `interfaces[].name` | interface name | Names this interface's branch in the tree |
| `tls_keylog` | | Key log file with the TLS session secrets, for live capture and replay |
| `advanced.prefix` | `V2G` | Trace source the rows land under |
| `advanced.promiscuous` | `true` | Receive frames addressed to other stations, as a tap or bridge needs |
| `advanced.replay_pcap` | | Decode this `.pcap`/`.pcapng` (plain or `.gz`/`.zst`) instead of capturing; plays once, then exits. `interfaces` is ignored |
| `advanced.log_level` | `INFO` | |

If any configured interface cannot be opened, the start fails with the reason in the log.

## Actions

| Action | |
| --- | --- |
| `V2G/convert` | Convert a capture to `.trz`, optionally with a TLS key log. Runs without the extension started |

From the CLI and Zelos AI, `V2G/list_interfaces`, `V2G/check_permissions`, `V2G/get_status` (per-interface capture and decoder counters) and `V2G/demo_capture_path` are also available. A capture that ends while running is logged and reported by `get_status`; when the last one ends, the extension logs the reason and exits with an error. Restart it to capture again.

## CLI

```bash
uv run zelos-extension-v2g interfaces                             # list NICs
uv run zelos-extension-v2g check                                  # probe permissions
uv run zelos-extension-v2g capture eth0 --tls-keylog keys.log     # capture, no app config
uv run zelos-extension-v2g replay session.pcapng                  # stream a file to the agent once, paced
uv run zelos-extension-v2g convert session.pcapng.gz              # write session.trz, no agent needed
uv run zelos-extension-v2g --demo                                 # the bundled capture, played once
```

`capture`, `replay` and `convert` take `--tls-keylog` and `--prefix`.

## Links

- [Documentation](https://docs.zeloscloud.io)
- [Issues](https://github.com/zeloscloud/zelos-extension-v2g/issues)

MIT. See [LICENSE](LICENSE).
