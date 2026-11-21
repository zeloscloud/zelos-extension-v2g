"""Windows: the Zelos agent starts extensions without PROCESSOR_ARCHITECTURE, so
`platform.machine()` is empty and zelos-packet finds no runnable capture helper.
Remove once the agent forwards it (Zelos 26.0.11) and the zelos floor is there.
"""

import os
import sys
import sysconfig

if sys.platform == "win32" and not os.environ.get("PROCESSOR_ARCHITECTURE"):
    os.environ["PROCESSOR_ARCHITECTURE"] = (
        "ARM64" if sysconfig.get_platform() == "win-arm64" else "AMD64"
    )
