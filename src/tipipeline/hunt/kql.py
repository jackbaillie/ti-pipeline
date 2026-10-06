"""Conservative KQL schema checks, not a KQL parser or execution guarantee."""
from __future__ import annotations

import re

from tipipeline.models import KqlValidation

# Hyphenated operators must be tokens, not three apparent column names.
_HYPHENATED = (
    "project-away", "project-keep", "project-rename", "project-reorder", "mv-expand",
    "mv-apply", "make-series", "parse-where", "parse-kv", "top-nested", "sample-distinct",
    "facet-with", "partition-by", "scan-order", "serialize-order",
)
_TOKEN = re.compile(
    "(?:" + "|".join(_HYPHENATED) + r")\b|[A-Za-z_][A-Za-z0-9_]*|"
    r"\d+(?:\.\d+)?(?:[A-Za-z]+)?|==|!=|=~|!~|<=|>=|[^\s]"
)
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_KEYWORDS = set("""
let where filter project extend summarize by distinct union join lookup on kind inner innerunique
leftouter rightouter fullouter leftanti rightanti leftsemi rightsemi anti semi isfuzzy best_effort
withsource hint strategy shuffle broadcast remote num_partitions shufflekey concurrency spread
true false null and or not in in~ has has_cs has_any has_all contains contains_cs startswith
startswith_cs endswith endswith_cs hassuffix hassuffix_cs hasprefix hasprefix_cs matches regex
between like limit take top sort order asc desc nulls first last count sample as with parse
parse-where parse-kv project-away project-keep project-rename project-reorder mv-expand mv-apply
make-series top-nested sample-distinct evaluate invoke range from to step print datatable externaldata
find search in-source pack bag list set dynamic datetime timespan bool boolean int long real double
decimal string guid typeof typeof_string default format options serialize render title accumulate
partition scan fork getschema consume reduce autocluster pivot bag_unpack narrow all any other
case_sensitive flags ignorecase output columns declare query_parameters restrict access materialized_view
materialize toscalar table database cluster view iff then else project-smart parse_json extract_json
""".split())
_PARAMETER_VALUES = {
    "kind", "isfuzzy", "withsource", "strategy", "remote", "shufflekey", "num_partitions",
    "concurrency", "spread", "best_effort", "flags", "format",
}
_STANDARD_COLUMNS = {
    "_BilledSize", "_IsBillable", "_ItemId", "_ResourceId", "_SubscriptionId", "_TimeReceived",
}


def strip_comments_and_strings(kql: str) -> str:
    """Blank comments/literal bodies while retaining offsets and line breaks.

    A string placeholder keeps a quoted union operand from becoming an apparent
    identifier. Bracket-quoted column identifiers are deliberately not interpreted.
    """
    out = list(kql)
    i = 0
    while i < len(kql):
        start = i
        if kql.startswith("//", i):
            end = kql.find("\n", i)
            i = end if end >= 0 else len(kql)
        elif kql.startswith("/*", i):
            end = kql.find("*/", i + 2)
            i = end + 2 if end >= 0 else len(kql)
        elif kql.startswith("```", i):
            end = kql.find("```", i + 3)
            i = end + 3 if end >= 0 else len(kql)
        elif kql[i] in "\"'" or (kql[i] == "@" and i + 1 < len(kql) and kql[i + 1] in "\"'"):
            verbatim = kql[i] == "@"
            if verbatim:
                i += 1
            quote = kql[i]
            i += 1
            while i < len(kql):
                if not verbatim and kql[i] == "\\":
                    i += 2
                elif kql[i] == quote:
                    if verbatim and i + 1 < len(kql) and kql[i + 1] == quote:
                        i += 2
                    else:
                        i += 1
                        break
                else:
                    i += 1
            # h/H marks obfuscated strings and is not a column reference.
            if start > 0 and kql[start - 1] in "hH" and (start == 1 or not kql[start - 2].isalnum()):
                start -= 1
        else:
            i += 1
            continue
        for j in range(start, min(i, len(kql))):
            if out[j] not in "\r\n":
                out[j] = " "
        if kql[start] not in "/":
            out[start] = "0"
    return "".join(out)


def rewrite_lookback(kql: str, days: int) -> str:
    """Set a behavioural query's ``let lookback`` binding to the configured window."""
    clean = strip_comments_and_strings(kql)
    match = re.search(r"\blet\s+lookback\s*=\s*[^;]+;", clean, re.IGNORECASE)
    binding = f"let lookback = {max(1, days)}d;"
    if match:
        return kql[:match.start()] + binding + kql[match.end():]
    return binding + "\n" + kql


def validate_kql(kql: str, schemas: dict[str, list[str]]) -> KqlValidation:
    """Find apparent table and column references against the configured schema.

    This checks a union of referenced columns; it cannot infer per-operator types,
    prove syntax, resolve dynamic properties or validate runtime connector coverage.
    """
    clean = strip_comments_and_strings(kql)
    matches = list(_TOKEN.finditer(clean))
    tokens = [m.group() for m in matches]
    defined: set[str] = set()
    parameter_tokens: set[int] = set()
    for i, token in enumerate(tokens):
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        prev = tokens[i - 1] if i else ""
        if _IDENT.match(token) and nxt in {"=", ":"}:
            defined.add(token)
            if token.lower() in _PARAMETER_VALUES and nxt == "=" and i + 2 < len(tokens):
                parameter_tokens.add(i + 2)
                # withsource creates a new column rather than referring to one.
                if token.lower() == "withsource":
                    defined.add(tokens[i + 2])
        if prev.lower() == "as" and _IDENT.match(token):
            defined.add(token)
    # Tuple assignment: extend (x, y) = function(...).
    for match in re.finditer(r"\(([A-Za-z_][\w\s,]*)\)\s*=", clean):
        defined.update(re.findall(r"\b[A-Za-z_]\w*\b", match.group(1)))
    # parse ... with ... creates named fields, including fields without type annotations.
    for match in re.finditer(r"\bparse(?:-where)?\b[^|;]*?\bwith\b([^|;]*)", clean):
        defined.update(re.findall(r"\b[A-Za-z_]\w*\b", match.group(1)))

    referenced: set[str] = {t for t in tokens if t in schemas and t not in defined}
    table_tokens: set[int] = set()
    unknown_tables: set[str] = set()

    def source(i: int) -> None:
        # Optional union/join flags: kind=..., hint.strategy=..., withsource=...
        while i < len(tokens):
            if tokens[i] in {"(", ","}:
                i += 1
                continue
            j = i + 1
            while j + 1 < len(tokens) and tokens[j] == ".":
                j += 2
            if j < len(tokens) and tokens[j] == "=":
                i = j + 2
                continue
            break
        if i >= len(tokens):
            return
        token = tokens[i]
        if not _IDENT.match(token) or token in defined or token.lower() in _KEYWORDS:
            return
        # Calls at expression starts may be table-valued functions. We cannot
        # check their result schema; do not pretend their names are tables.
        if i + 1 < len(tokens) and tokens[i + 1] == "(":
            return
        # Grouped scalar predicates/expressions are not tabular sources.
        if i + 1 < len(tokens) and tokens[i + 1].lower() in {
            "==", "!=", "=~", "!~", "<", ">", "<=", ">=", "+", "-", "*", "/",
            "in", "in~", "has", "has_any", "contains", "startswith", "endswith",
        }:
            return
        table_tokens.add(i)
        referenced.add(token)
        if token not in schemas:
            unknown_tables.add(token)

    # Statement starts, including let-bound tabular expressions.
    for i in range(len(tokens)):
        if i == 0 or tokens[i - 1] == ";":
            if tokens[i].lower() == "let":
                end = next((j for j in range(i + 1, len(tokens)) if tokens[j] in {"=", ";"}), len(tokens))
                if end < len(tokens) and tokens[end] == "=":
                    source(end + 1)
            elif tokens[i].lower() not in {"set", "declare", "restrict"}:
                source(i)
        if tokens[i].lower() in {"join", "lookup", "union"}:
            source(i + 1)
            if tokens[i].lower() == "union":
                # Commas at the union operand depth separate tables/subqueries,
                # not arguments to functions inside each operand.
                depth = 0
                for j in range(i + 1, len(tokens)):
                    if tokens[j] == "(" :
                        depth += 1
                    elif tokens[j] == ")":
                        if depth == 0:
                            break
                        depth -= 1
                    elif tokens[j] in {"|", ";"} and depth == 0:
                        break
                    elif tokens[j] == "," and depth == 0:
                        source(j + 1)
        if tokens[i] == "(" and i + 1 < len(tokens):
            prev = tokens[i - 1].lower() if i else ""
            # A bracket after a function, or scalar operator, is not generally
            # a tabular-expression start. A following pipe proves a subquery.
            following = tokens[i + 2] if i + 2 < len(tokens) else ""
            if (prev in {"materialize", "toscalar", "join", "lookup", "union", "="}
                or prev in {"", "(", ","} or following == "|"):
                source(i + 1)

    known = referenced & schemas.keys()
    columns = _STANDARD_COLUMNS | {c for table in known for c in schemas[table]}
    unknown_columns: set[str] = set()
    has_join = any(t.lower() in {"join", "lookup"} for t in tokens)
    for i, token in enumerate(tokens):
        if not _IDENT.match(token):
            continue
        prev = tokens[i - 1] if i else ""
        nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
        if (token in columns or token in referenced or token in defined
            or token.lower() in _KEYWORDS or i in parameter_tokens or i in table_tokens
            or nxt == "(" or prev in {".", "$"}):
            continue
        # Project wildcards and automatic summarize / join output names.
        if nxt == "*" and any(c.startswith(token) for c in columns):
            continue
        if has_join and re.sub(r"\d+$", "", token) in columns:
            continue
        if re.fullmatch(r"(?:count|countif|sum|avg|min|max|dcount|any|set|list|percentile)_\w*", token):
            continue
        unknown_columns.add(token)
    messages = []
    if unknown_tables:
        messages.append("Unrecognised apparent tables: " + ", ".join(sorted(unknown_tables)))
    if unknown_columns:
        messages.append("Apparent columns absent from the union of referenced table schemas: " + ", ".join(sorted(unknown_columns)))
    if not referenced:
        messages.append("No configured table reference found; this cannot be confirmed as a runnable hunt query.")
    status = "invalid" if unknown_tables or not referenced else "warnings" if unknown_columns else "schema_valid"
    return KqlValidation(
        status=status, tables=sorted(referenced), unknown_tables=sorted(unknown_tables),
        unknown_columns=sorted(unknown_columns), messages=messages,
    )
