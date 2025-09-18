# AGENT NOTES

## DAP Support Recon
- Core debugger already exposes launch/attach, stepping, breakpoints, stack/variable/memory APIs that map onto DAP operations (`src/debugger/mod.rs`, `src/debugger/breakpoint.rs`, `src/debugger/debugee/*`).
- Event callbacks are delivered via `EventHook`; console mode uses `TerminalHook`. DAP will need its own hook to translate events into `tower_dap::Client` messages.
- Supervisor wiring currently handles only TUI and console branches; DAP flag is parsed but unused (and typoed in `main.rs`). Need a new branch that spins up a tokio runtime + tower-dap server, plus CLI fix.
- Debugee stdout/stderr already flow through `DebugeeOutReader`; DAP mode can reuse those to emit `output` events.
- Gaps: async facade around the synchronous ptrace debugger for tower-dap handlers, state bookkeeping for variables/scopes IDs, event bridging, runtime lifecycle and cleanup.
- Overall the foundation is solid but integration remains non-trivial due to async orchestration and protocol translation work.

## DAP Implementation Notes
- `bs --dap` launches a stdio DAP adapter backed by tower-dap; the supervisor now instantiates `ui::dap::DapApplication` which owns a Tokio runtime and serves a single session.
- `DapHook` forwards debugger callbacks into an async channel consumed by the adapter; the adapter queries the debugger on demand to populate stopped events and stack data.
- Stdout/stderr forwarding runs on blocking tasks that push `output` events into the same channel, keeping the runtime thread-safe.
- Breakpoints are reconciled on each `setBreakpoints` request; scopes currently expose locals as non-expandable placeholders until richer variable projection is wired in.
- Launch requests honor `stopOnEntry` (default true) with auto-continue handling, while terminate/pause map to SIGKILL/SIGINT respectively; exit paths emit `exited` and `terminated` events.

## Context Compactification
- New `src/ui/dap` adapter wraps the synchronous debugger inside a Tokio runtime and serves tower-dap over stdio.
- Supports launch/attach, continue/step/pause/terminate, threads/stackTrace, and setBreakpoints; everything else returns safe empty responses.
- `DapHook` plus `DebugeeOutReader` emit stop/output events into tower-dap so clients mirror console behaviour.
- CLI `--dap` branch now wires the adapter via the supervisor; docs flag scopes/variables as future work.
- Latest validation ran `cargo fmt` and `CFLAGS='-std=gnu89' cargo check`.
- Scopes expose locals and arguments with expandable variable trees; evaluate requests parse BugStalker DQEs and return inspectable results via the same variable store.
- Evaluate currently reuses the variable cache; verify real clients keep references alive across steps and consider adding paging if lists become large.
