"""Discovery subpackage — implements v0.4 §4 (Validate / Discover / Expand modes).

Override on v0.4 §4: provider is Brave Search instead of Google CSE because Google
deprecated the "Search the entire web" option in new Programmable Search Engines.
See ``CLAUDE.md`` § "Search provider".
"""

from __future__ import annotations

from cdt.discovery.brave_search import BraveSearch
from cdt.discovery.cache import DiscoveryCache
from cdt.discovery.expander import Expander
from cdt.discovery.models import (
    DiscoveryResult,
    ExpansionResult,
    IssueCode,
    SearchResult,
    ValidationResult,
)
from cdt.discovery.validator import Validator

__all__ = [
    "BraveSearch",
    "DiscoveryCache",
    "DiscoveryResult",
    "ExpansionResult",
    "Expander",
    "IssueCode",
    "SearchResult",
    "ValidationResult",
    "Validator",
]
