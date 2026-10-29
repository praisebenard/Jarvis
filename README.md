# JARVIS

JARVIS is a Python command-line tool for scoped web review and local PHP source
analysis. It can inventory pages when explicitly asked to make web requests,
record review candidates, and statically inspect PHP input, query, helper, and
output patterns. Static source evidence is not proof that a vulnerability is
exploitable at runtime.

JARVIS does not execute PHP source during `php-flow`, execute SQL, or confirm a
vulnerability from a traced source-to-sink path. Its PHP analysis is a
conservative pattern analysis, not a complete PHP interpreter or general taint
engine. The interactive `audit`, `info`, and `session-check` commands can make
HTTP requests; the static PHP commands below do not.

## Requirements and installation

- Python 3
- The Python package `requests` (the only non-standard-library import used by
  `jarvis.py`)
- PHP source files on disk for PHP source analysis; a PHP runtime or database
  is not required for static analysis

There is no `requirements.txt`, `pyproject.toml`, or package installer in this
repository. From the project directory, create an environment and install the
runtime dependency:

```sh
cd ~/jarvis
python -m venv .venv
. .venv/bin/activate
python -m pip install requests
```

Start the interactive CLI with:

```sh
python jarvis.py
```

At the `You:` prompt, enter `help` for the command list and `exit` to quit.
JARVIS is interactive; it does not use command-line flags for these commands.

## Authorized scope

`scope.txt` is read from the directory containing `jarvis.py`. It is ignored by
Git and holds local authorization configuration. Keep the authorized bWAPP
scope on this exact line:

```text
ALLOW http://127.0.0.1:80/bWAPP/*
```

From the CLI, `scope` displays configured rules and
`check http://127.0.0.1:80/bWAPP/` checks the URL against the rules. Those two commands
only inspect scope configuration; they do not make a request. A successful
scope check means only that the URL matches the local authorization rule. It
does not itself initiate or authorize an audit beyond that configured rule.

## Static PHP source analysis

Run these commands from the repository directory so generated reports land in
`~/jarvis/reports/`:

```text
php-inspect /path/to/file.php
php-scan /path/to/php-directory
php-summary /path/to/php-directory
php-report /path/to/php-directory
php-flow /path/to/file.php
```

- `php-inspect` prints textual GET, POST, and REQUEST reference patterns found
  in one PHP file.
- `php-scan` lists those reference patterns in top-level PHP files in a
  directory.
- `php-summary` counts top-level PHP files and classifies training pages by
  filename. `php-report` also counts textual request-reference patterns.
  These classifications are review suggestions, not vulnerability findings.
  Directory scans are not recursive.
- `php-flow` produces a source-flow report for one PHP file, saved as
  `<sanitized-source-stem>_php_flow.txt`, with a numbered suffix if that name
  already exists. It can record
  request references, supported assignments, query construction and execution,
  selected helper-return evidence, prepared-statement bindings, and supported
  database-read-to-output paths. It also traces request data into a narrow set
  of direct calls to command execution, `eval`, `unserialize`, and file/network
  functions. These are operation observations, not confirmed vulnerabilities;
  unsupported or ambiguous relationships are left unresolved.
  For request parameters named like object identifiers (`id`, `*_id`, UUID/GUID),
  a traced database flow is reported as an object-access review observation.
  A nearby comparison is treated as authorization-like only when it references
  a variable in the traced flow and a session/user/owner/tenant identity. A
  narrow local helper can also be noted when its single parameter is compared
  with a session/owner identity and the call passes a tracked object variable.
  Session/login or role checks alone do not count as object-level authorization.
  These observations do not prove that a check is correct or effective;
  failure to recognize a guard is explicitly not evidence that authorization
  is absent. Helper parsing is limited to simple local declarations and bodies.
- `php-flow` also includes a limited offline upload review. It recognizes
  direct `$_FILES` references, simple same-file aliases of `tmp_name`, and
  same-line `move_uploaded_file()` or `file_put_contents()` calls. It records
  textual filename/extension, MIME, upload-error, and size checks, along with
  destination expressions. These patterns do not prove a check is effective;
  MIME or filename checks alone are never considered proof that an upload is
  safe. Indirect helper behavior, multipart runtime behavior, destination
  containment, overwrite behavior, storage permissions, and web-server
  execution policy remain unresolved. Results are observations with
  `UNCONFIRMED` status and conservative `NEEDS_REVIEW` severity. No upload is
  executed, and no runtime destination path is opened.
- `php-review` prints a manual review checklist; it does not analyze a target.

### Offline PHP analyzer benchmark

Run the table-driven synthetic regression benchmark with:

```sh
python -m unittest tests.test_php_benchmark
```

Its PHP fixtures under `tests/fixtures/php_benchmark/` cover SQL/query flow,
XSS output contexts, object-level access review, URL-fetch/SSRF, command
execution, file access, and uploads. Each category has supported positive
patterns, benign cases, and unresolved cases. Each fixture's expected result
and rationale are listed in the benchmark manifest. The benchmark invokes the
same offline `php-flow` analyzer used by the unit tests and checks report
evidence, locations, severity, and `UNCONFIRMED` status. It prints TP, TN, FP,
FN, and unresolved counts by category. FP and missed-pattern rates use only
the clearly labeled benign and positive cases; unresolved cases are asserted
separately and excluded from those denominators. These measurements describe
only this named synthetic fixture set and do not establish real-world
detection accuracy. Fixtures are read as text only; PHP is not executed, no
network request is made, and no path derived from fixture input is opened.

## Offline JavaScript source-flow analysis

Run `js-flow` on a locally available `.js`, `.mjs`, or `.cjs` file:

```text
js-flow /path/to/local-file.js
```

The command reads source text only. It never executes JavaScript or makes
network requests. Its deliberately small supported subset recognizes exact
`location.search`, `location.hash`, `document.referrer`, `window.name`, and
message event data expressions, simple one-line identifier assignments and
aliases, and one-line assignments to `.innerHTML`. It also recognizes the
narrow flow `new URLSearchParams(location.search)` followed by a static-key
`.get("name")` assignment, provided the receiver is the variable holding that
recognized constructor result. An arbitrary `.get()` call is not treated as a
source. Control flow, compound expressions, template literals, reassignment,
dynamic `.get()` keys, and other unsupported syntax are left unresolved or
cause traces to be withheld. This is not a JavaScript parser, interpreter, taint
engine, or proof of runtime reachability or exploitability. Every candidate is
labeled `UNCONFIRMED`. Reports use a JavaScript-specific filename with a
path-derived identifier and are created without overwriting an existing
report. A narrow literal check reports likely secret-named assignments without
printing the literal value; it cannot establish that a value is active or
privileged. Simple role/permission checks are listed as client-side review
notes only and do not establish a server-side authorization failure, IDOR, or
account takeover.

Static-flow candidates receive severity `NEEDS_REVIEW` when impact,
exploitability, trust boundary, authentication, scope, or reviewed control
effectiveness is unknown. Severity confidence is reported separately from the
finding's `UNCONFIRMED` status. The current analyzers do not generally detect
authorization flaws, IDOR, general SSRF/path traversal, uploads, cryptographic
misuse, or security configuration errors. Narrow URL-fetch and file-read
observations are review signals only. A missing candidate is not evidence that
such an issue is absent. Critical severity is never inferred from a pattern or
source-to-sink trace alone.

### Offline JavaScript analyzer benchmark

Run the synthetic benchmark with:

```sh
python -m unittest tests.test_js_benchmark
```

Fixtures under `tests/fixtures/js_benchmark/` cover direct `innerHTML` flows,
aliases, the supported static-key `URLSearchParams(location.search)` pattern,
text-only output, misleading variable names, safe-looking transformations,
and unsupported syntax. The benchmark manifest labels every fixture and gives
its rationale. The test checks candidate evidence, source/sink locations,
`NEEDS_REVIEW` severity, and `UNCONFIRMED` status where a candidate is
applicable. Counts are reported by category. TP/FN and TN/FP rates use only
clearly labeled positive and benign cases; unresolved cases are reported
separately and excluded from rates. Results apply only to this synthetic
fixture set and do not establish real-world detection accuracy. Fixtures are
read as text by the analyzer; JavaScript is not executed and no network request
is made.

PHP-flow and JavaScript-flow reports record UTC analysis times, the analyzer
source path and SHA-256, source paths and SHA-256 fingerprints, and whether the
analyzed source files still matched their snapshots when the report was
prepared. PHP-flow reports fingerprint the root file and statically read local
includes. These fingerprints let a reader compare the report with current
files; they do not validate runtime behavior or prove that dependencies outside
the recorded source set were unchanged.

For example, make a synthetic PHP fixture and analyze it without contacting a
web server:

```sh
cat > /tmp/jarvis-demo.php <<'PHP'
<?php
$message = $_GET['message'];
echo $message;
PHP
python jarvis.py
```

Then enter this at the JARVIS prompt:

```text
php-flow /tmp/jarvis-demo.php
exit
```

The report is written under `reports/` relative to the current working
directory. The fixture demonstrates a source pattern only; it does not test
browser handling or establish exploitability.

## Evidence and finding status

PHP-flow reports distinguish source observations (such as a request reference,
assignment, helper call, query, or echo expression) from a supported static
relationship between them. A reported source-to-sink path is still static
evidence. Automated findings remain `UNCONFIRMED`; reviewer validation is
recorded separately and does not change the saved report's automated status.
JARVIS does not promote a finding merely because a path was traced.

For a traced PHP output expression, the report may infer `HTML text`, a quoted
`HTML attribute`, or a `JavaScript string` context when the output statement
contains simple static markup around the tracked value. The report states the
static fragments used for that inference. Unsupported or indirect template
contexts remain unresolved. Context classification does not prove browser
interpretation, exploitability, or that an encoder is effective for the exact
runtime context.

Guards are recorded as branch conditions, not proof of input validation or
sanitization. A helper's name does not establish its behavior. SQL escaping is
not HTML output encoding, and a transformation is not presumed effective for
every context. Likewise, matching database table names alone does not prove
that a SELECT retrieved the same record as an earlier INSERT. Dynamic SQL,
conflicting assignments, unsupported helper or fetch syntax, and uncertain
record identity can remain explicitly unresolved.

## PHP URL-fetch review

PHP-flow adds a separate SSRF review observation when a supported request value
is statically traced to the first argument of `file_get_contents()`. It records
source and sink locations and narrowly recognizes `filter_var($url,
FILTER_VALIDATE_URL)` or `in_array($url, $allowed_urls, ...)` in a captured
guard. These are evidence notes only: URL-format validation does not constrain
the destination, and an allowlist's contents, URL equivalence, and coverage of
all paths are not verified. A request-to-fetch trace does not prove a remote
request, access to a restricted destination, or SSRF exploitability. Fixed
URLs do not create request-controlled flow observations; other network clients
and indirect URL construction remain unsupported or unresolved.

## PHP file-access review

PHP-flow also records a path-access review observation when traced request data
reaches the first argument of `file_get_contents()` or `readfile()`. A narrow
subset recognizes `basename()` and `realpath()` transformations and simple
`strpos()`/`str_starts_with()` comparisons against variables named as a base,
root, or directory. These are source-code observations, not proof of path
traversal or a successful file read. `basename()` does not establish directory
containment; `realpath()` alone does not enforce an intended root; and a prefix
check does not establish canonicalization, separator-aware containment,
symlink policy, or fail-closed behavior. Fixed paths do not create
request-controlled observations. Dynamic helper-built paths and other file
APIs remain unresolved or outside this narrow review. JARVIS reads only the
source files being analyzed; it does not open a runtime file selected by a
traced request value.

## PHP command-execution review

PHP-flow adds a separate command-injection review observation when traced
request data reaches the first argument of `exec()`, `system()`, `shell_exec()`,
`passthru()`, `popen()`, or `proc_open()`. It recognizes simple one-argument
uses of `escapeshellarg()` and `escapeshellcmd()` as transformation evidence.
That evidence does not establish safe command composition, argument boundaries,
option handling, executable behavior, or runtime effects. Static command strings
do not create request-flow observations; unsupported command builders remain
unresolved. Object methods such as `$database->exec()` are not classified as OS
command execution. This narrow source review does not prove command-injection
exploitability.

Useful report and review commands include:

```text
reports
view <filename>
summary
review-queue
review-note
validation-note
review-notes
review-progress
```

Generated reports are plain text under `reports/`, which is Git-ignored.
`finding` and `candidate` create review records there; candidate descriptions,
severity suggestions, and supplied evidence are not automatically trusted as
confirmed findings. Reviewer notes are stored separately in
`reports/review_notes/notes.jsonl`. Recording reviewer validation does not
rewrite the saved report's automated vulnerability status.

## Runtime review commands

Commands such as `info <target>`, `audit <target>`, and `session-check` can make
HTTP requests. `audit` is passive by default; `audit <target> --active` opts
into reflection probes and supports a bounded request budget. These commands
are separate from local static source analysis. Use them only when the target
and method are authorized by the current scope and the applicable rules.

## Tests and troubleshooting

The test suite uses Python's standard `unittest` framework. Run it from the
project directory:

```sh
python -m unittest discover -s tests
python -m py_compile jarvis.py
git diff --check
```

If startup reports that `requests` is missing, activate `.venv` and install it
with `python -m pip install requests`. If a target is rejected, inspect
`scope.txt`, then use the `scope` and `check <target>` commands; scope matching
includes the scheme, port, and path. If a PHP-flow report is incomplete, check
that the source file and any statically included local files are readable, and
review the report's unresolved-analysis notes. Unresolved evidence is a stated
analysis limit, not proof that a vulnerability is absent.

The repository has no declared dependency lockfile, automated accuracy
benchmark, or evidence supporting production-readiness or general coverage
claims. Review each result manually and retain uncertainty where source or
runtime behavior is not established.
