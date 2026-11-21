"""The bundled demo capture, for trying the extension without a charging link.

`v2g-demo.pcap`: one ISO 15118-2 DC session, SDP to SessionStop, recorded on a
software-in-the-loop EVSE and EV.
"""

from pathlib import Path

DEMO_PCAP = Path(__file__).resolve().with_name("v2g-demo.pcap")
