# Sample V2G captures

Standard, off-the-shelf captures from the [pyPLC](https://github.com/uhi22/pyPLC)
project's `results/` directory (real EVs against real/bench chargers, DIN 70121).
Used by the test suite and handy for the `convert` / live-replay flows.

| File | Vehicle | What it shows |
|------|---------|---------------|
| `2024-04-20_ModelY_pyPLC_stop_in_precharge.pcapng` | Tesla Model Y | Full SLAC pairing + SAP + DIN handshake through CableCheck and PreCharge, then SessionStop. Compact — the primary test fixture. |
| `2023-04-16_at_home_Ioniq_in_currentDemandLoop.pcapng` | Hyundai Ioniq | A complete DC session that runs the CurrentDemand loop — exercises the charging-telemetry decode end to end. |
| `2023-05-03_TaycanLeftside_slacFail.pcapng` | Porsche Taycan | SLAC pairing that never matches (6 PARM.REQ retries, no MATCH.CNF) — a real SLAC-init failure. |

Source: <https://github.com/uhi22/pyPLC/tree/master/results>. More captures (Polestar,
Audi Q4, Model X, Alpitronic/Compleo/ABB chargers, listen-mode, …) are available there.

Try one:

```bash
uv run python main.py convert tests/files/2023-04-16_at_home_Ioniq_in_currentDemandLoop.pcapng -o /tmp/ioniq.trz
```

## Combined CAN + V2G fixture

| File | Contents |
|------|----------|
| `combined_can_v2g.pcapng` | A two-interface capture with **both** CAN and V2G: the Model Y V2G session above (interface 1, Ethernet) plus a handful of **synthetic** SocketCAN frames (interface 0). No customer data. |
| `example.dbc` | A small example CAN database (`BMS_Status`, `VCU_ChargeCommand`) that decodes the synthetic CAN frames — scaled/signed signals + an enum value table. |

The synthetic CAN frames carry known values so decoding is verifiable: `BMS_Status`
(0x100) = PackVoltage 400.0 V, PackCurrent −50.0 A, SoC 55 %, ChargeState = Charging;
`VCU_ChargeCommand` (0x200) = TargetVoltage 420.0 V, TargetCurrent 125.0 A; plus one
unknown id (0x7FF) that stays raw-only. `make_combined_fixture.py` regenerates the
pcapng (`uv run python tests/files/make_combined_fixture.py`).

Convert it and you get one time-aligned trace with `can*/*` and `v2g/*`:

```bash
uv run python main.py convert tests/files/combined_can_v2g.pcapng --dbc tests/files/example.dbc -o /tmp/combined.trz
```
