"""External tool wrappers (v0.4 §14.5.2).

Each wrapper has a thin async public API and returns a pydantic model; the
heavy lifting lives in synchronous helpers that the wrapper executes in a
worker thread (libraries) or as a subprocess (whatweb, nikto).
"""

from __future__ import annotations

from cdt.tools.builtwith_wrapper import BuiltWithResult, BuiltWithWrapper
from cdt.tools.censys_wrapper import (
    CensysCertResult,
    CensysHostResult,
    CensysWrapper,
)
from cdt.tools.nikto_wrapper import (
    NiktoFinding,
    NiktoResult,
    NiktoSkipAllowlist,
    NiktoWrapper,
)
from cdt.tools.shodan_wrapper import (
    ShodanHostResult,
    ShodanInternetDBResult,
    ShodanWrapper,
)
from cdt.tools.wafw00f_wrapper import WafDetection, WafW00fWrapper
from cdt.tools.wappalyzer_wrapper import WappalyzerResult, WappalyzerWrapper
from cdt.tools.whatweb_wrapper import WhatWebResult, WhatWebWrapper

__all__ = [
    "BuiltWithResult",
    "BuiltWithWrapper",
    "CensysCertResult",
    "CensysHostResult",
    "CensysWrapper",
    "NiktoFinding",
    "NiktoResult",
    "NiktoSkipAllowlist",
    "NiktoWrapper",
    "ShodanHostResult",
    "ShodanInternetDBResult",
    "ShodanWrapper",
    "WafDetection",
    "WafW00fWrapper",
    "WappalyzerResult",
    "WappalyzerWrapper",
    "WhatWebResult",
    "WhatWebWrapper",
]
