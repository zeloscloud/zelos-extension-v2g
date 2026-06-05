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
