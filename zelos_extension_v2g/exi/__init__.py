"""EXI decode for V2G application messages.

EXI (Efficient XML Interchange) is the bit-packed, schema-informed binary encoding
the V2G application layer uses. Field-level decode is delegated to EVerest's libcbv2g
via a small prebuilt shim called through stdlib ctypes — see ``libv2g``.
"""

from . import libv2g

__all__ = ["libv2g"]
