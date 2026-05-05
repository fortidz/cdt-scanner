"""External tool wrappers (wafw00f, whatweb, nikto, ...).

Phase 3 ships only ``WafW00fWrapper`` — wafw00f integrated as a library
(not a subprocess) per v0.4 §14.5.2.
"""

from __future__ import annotations

from cdt.tools.wafw00f_wrapper import WafDetection, WafW00fWrapper

__all__ = ["WafDetection", "WafW00fWrapper"]
