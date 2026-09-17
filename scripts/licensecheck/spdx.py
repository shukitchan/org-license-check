"""Resolve SBOM license strings onto the OSO license names used by the matrix.

SBOMs report SPDX identifiers ("Apache-2.0", "GPL-3.0-or-later") and sometimes
SPDX expressions ("MIT OR Apache-2.0"). The requirements doc lists licenses under
Mend display names ("Apache 2.0", "GPL 3.0"). This module bridges the two.
"""

import re

UNKNOWN = "__unknown__"

_SEPARATORS = re.compile(r"[-_/,]+")
_WHITESPACE = re.compile(r"\s+")
_KEEP = re.compile(r"[^A-Z0-9.+ ]")

# SPDX marks GPL-family range semantics with -only / -or-later / a trailing '+'.
# The OSO matrix does not distinguish them, so they are folded away before
# lookup: "GPL-2.0-only WITH Classpath-exception-2.0" -> "GPL 2.0 WITH ...".
_VERSION_SUFFIX = re.compile(r"\s+(?:ONLY|OR LATER)\b")


def normalize(text):
    """Canonical form for matching: uppercase, separators collapsed to spaces.

    Version punctuation ('.') and the SPDX 'or later' marker ('+') survive, since
    they distinguish GPL 2.0 from GPL 3.0 and GPL-2.0 from GPL-2.0+.
    """
    if not text:
        return ""
    upper = text.upper().strip()
    upper = _SEPARATORS.sub(" ", upper)
    upper = _KEEP.sub(" ", upper)
    return _WHITESPACE.sub(" ", upper).strip()


def canonical(text):
    """Normalized form with SPDX version-range suffixes folded away."""
    norm = normalize(text)
    norm = _VERSION_SUFFIX.sub("", norm)
    if norm.endswith("+"):
        norm = norm[:-1].strip()
    return norm


def is_unknown(raw):
    """True for the placeholders SBOM producers use when no license was found."""
    return normalize(raw) in ("", "NOASSERTION", "NONE", "UNKNOWN", "NOTICE")


def is_opaque(raw):
    """True when the string carries no license information at all.

    Distinguishes "we could not determine a license" (NOASSERTION, LicenseRef-*)
    from "this is a real license the matrix simply does not list yet", which is
    an OSO review item rather than an undeclared dependency.
    """
    if is_unknown(raw):
        return True
    norm = normalize(raw)
    return norm.startswith("LICENSEREF") or norm.startswith("DOCUMENTREF")


class Resolver:
    """Maps a raw license string onto one or more OSO license names."""

    def __init__(self, matrix):
        self._aliases = {canonical(k): v for k, v in matrix.get("aliases", {}).items()}
        self._patterns = [
            (re.compile(p["match"]), p["license"]) for p in matrix.get("patterns", [])
        ]
        # Every name that appears anywhere in the matrix, so an SBOM that already
        # uses OSO naming resolves without an alias entry.
        self._known = {}
        for key in ("approved", "reject_server_side", "reject_distributed", "banned"):
            for name in matrix.get(key, []):
                self._known[canonical(name)] = name

    def resolve_one(self, raw):
        """Resolve a single license token to (oso_name_or_UNKNOWN, suspected)."""
        if is_opaque(raw):
            return UNKNOWN, False

        norm = canonical(raw)
        suspected = norm.startswith("SUSPECTED ")
        if suspected:
            norm = norm[len("SUSPECTED "):]

        name = self._known.get(norm) or self._aliases.get(norm)

        if name is None:
            for pattern, mapped in self._patterns:
                if pattern.search(norm):
                    name = mapped
                    break

        if name is None:
            return UNKNOWN, suspected
        return ("Suspected " + name if suspected else name), suspected


def split_expression(expression):
    """Split an SPDX expression into a tree of AND/OR operations.

    Returns a nested structure: ("OR"|"AND", [child, ...]) or ("LEAF", "MIT").
    'WITH' binds tighter than AND/OR and is kept inside the leaf, because the
    matrix lists exception-bearing licenses ("GPL 2.0 Classpath") as their own
    entries.
    """
    tokens = _tokenize(expression)
    if not tokens:
        return ("LEAF", "")
    node, index = _parse_or(tokens, 0)
    return node


def _tokenize(expression):
    raw = expression.replace("(", " ( ").replace(")", " ) ")
    return [t for t in raw.split() if t]


def _parse_or(tokens, index):
    node, index = _parse_and(tokens, index)
    children = [node]
    while index < len(tokens) and tokens[index].upper() == "OR":
        node, index = _parse_and(tokens, index + 1)
        children.append(node)
    if len(children) == 1:
        return children[0], index
    return ("OR", children), index


def _parse_and(tokens, index):
    node, index = _parse_atom(tokens, index)
    children = [node]
    while index < len(tokens) and tokens[index].upper() == "AND":
        node, index = _parse_atom(tokens, index + 1)
        children.append(node)
    if len(children) == 1:
        return children[0], index
    return ("AND", children), index


def _parse_atom(tokens, index):
    if index >= len(tokens):
        return ("LEAF", ""), index
    if tokens[index] == "(":
        node, index = _parse_or(tokens, index + 1)
        if index < len(tokens) and tokens[index] == ")":
            index += 1
        return node, index

    # Consume the identifier plus any trailing "WITH <exception>".
    parts = [tokens[index]]
    index += 1
    if index + 1 < len(tokens) and tokens[index].upper() == "WITH":
        parts.append(tokens[index])
        parts.append(tokens[index + 1])
        index += 2
    return ("LEAF", " ".join(parts)), index


def and_leaves(node):
    """Leaf identifiers of a top-level, purely conjunctive expression.

    Returns None when the expression is anything else -- notably when an OR
    appears anywhere, which means a human authored it and its AND groups are
    meaningful (`Apache-2.0 OR (Apache-2.0 AND MIT)` is a real choice).
    """
    kind, value = node
    if kind != "AND":
        return None
    collected = []
    for child in value:
        if child[0] != "LEAF":
            return None
        collected.append(child[1])
    return collected


def leaves(node):
    """Every license identifier in an expression tree, left to right."""
    kind, value = node
    if kind == "LEAF":
        return [value] if value else []
    collected = []
    for child in value:
        collected.extend(leaves(child))
    return collected
