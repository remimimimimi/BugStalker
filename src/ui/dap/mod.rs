use std::collections::HashMap;
use std::io::Read;
use std::sync::atomic::{AtomicI32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use anyhow::Context;
use chumsky::Parser;
use nix::sys::signal::{self, Signal};
use nix::unistd::Pid;
use serde_json::Value;
use tokio::runtime::Builder as RuntimeBuilder;
use tokio::sync::{Mutex as AsyncMutex, mpsc};
use tokio::task;
use tower_dap::{CapabilitiesBuilder, Client, DapError, DebugAdapter, Server, types as t};

use crate::debugger::process::{Child, Installed};
use crate::debugger::variable::dqe::{Dqe, Selector};
use crate::debugger::variable::execute::{QueryResult, QueryResultKind};
use crate::debugger::variable::render::{RenderValue, ValueLayout};
use crate::debugger::variable::value::Value as DebugValue;
use crate::debugger::{BreakpointViewOwned, Debugger, DebuggerBuilder, Error as DebuggerError};
use crate::ui::DebugeeOutReader;
use crate::ui::command::parser::expression;

const STOP_ON_ENTRY_DEFAULT: bool = true;

pub struct DapApplication {
    debugger_builder: DebuggerBuilder,
    process: Child<Installed>,
    stdout: DebugeeOutReader,
    stderr: DebugeeOutReader,
}

impl DapApplication {
    pub fn new(
        debugger_builder: DebuggerBuilder,
        process: Child<Installed>,
        stdout: DebugeeOutReader,
        stderr: DebugeeOutReader,
    ) -> Self {
        Self {
            debugger_builder,
            process,
            stdout,
            stderr,
        }
    }

    pub fn run(self) -> anyhow::Result<()> {
        let (event_tx, event_rx) = mpsc::unbounded_channel();
        let process_pid = Arc::new(AtomicI32::new(self.process.pid().as_raw()));

        let hook = DapHook::new(event_tx.clone(), process_pid.clone());
        let mut debugger = self
            .debugger_builder
            .build(self.process)
            .context("Build debugger")?;
        debugger.set_hook(hook);

        let debugger = Arc::new(DebuggerHandle::new(debugger));
        let shared = Arc::new(DapSharedState::new(debugger, event_tx, process_pid));
        let adapter = BugStalkerAdapter::new(shared, event_rx, self.stdout, self.stderr);

        let runtime = RuntimeBuilder::new_multi_thread()
            .enable_all()
            .thread_name("bugstalker-dap")
            .build()
            .context("Create tokio runtime")?;

        runtime
            .block_on(async { Server::new().serve(adapter).await })
            .map_err(anyhow::Error::from)
    }
}

struct DebuggerHandle(Mutex<Debugger>);

impl DebuggerHandle {
    fn new(debugger: Debugger) -> Self {
        Self(Mutex::new(debugger))
    }

    fn lock(&self) -> MutexGuard<'_, Debugger> {
        self.0.lock().expect("mutex poisoned")
    }
}

unsafe impl Send for DebuggerHandle {}
unsafe impl Sync for DebuggerHandle {}

struct SessionState {
    stop_on_entry: bool,
    configured: bool,
    started: bool,
    thread_map: HashMap<i32, u32>,
    variables: VariableHandles,
}

impl Default for SessionState {
    fn default() -> Self {
        Self {
            stop_on_entry: STOP_ON_ENTRY_DEFAULT,
            configured: false,
            started: false,
            thread_map: HashMap::new(),
            variables: VariableHandles::default(),
        }
    }
}

struct DapSharedState {
    debugger: Arc<DebuggerHandle>,
    session: Mutex<SessionState>,
    events: mpsc::UnboundedSender<DapEvent>,
    process_pid: Arc<AtomicI32>,
}

impl DapSharedState {
    fn new(
        debugger: Arc<DebuggerHandle>,
        events: mpsc::UnboundedSender<DapEvent>,
        process_pid: Arc<AtomicI32>,
    ) -> Self {
        Self {
            debugger,
            session: Mutex::new(SessionState::default()),
            events,
            process_pid,
        }
    }

    fn debugger(&self) -> Arc<DebuggerHandle> {
        self.debugger.clone()
    }

    fn session(&self) -> MutexGuard<'_, SessionState> {
        self.session.lock().expect("mutex poisoned")
    }

    fn event_sender(&self) -> mpsc::UnboundedSender<DapEvent> {
        self.events.clone()
    }

    fn process_pid(&self) -> Pid {
        Pid::from_raw(self.process_pid.load(Ordering::Acquire))
    }
}

struct BugStalkerAdapter {
    shared: Arc<DapSharedState>,
    receiver: AsyncMutex<Option<mpsc::UnboundedReceiver<DapEvent>>>,
    stdout: DebugeeOutReader,
    stderr: DebugeeOutReader,
}

impl BugStalkerAdapter {
    fn new(
        shared: Arc<DapSharedState>,
        receiver: mpsc::UnboundedReceiver<DapEvent>,
        stdout: DebugeeOutReader,
        stderr: DebugeeOutReader,
    ) -> Self {
        Self {
            shared,
            receiver: AsyncMutex::new(Some(receiver)),
            stdout,
            stderr,
        }
    }

    async fn with_debugger<F, R>(&self, f: F) -> Result<R, DapError>
    where
        F: FnOnce(&mut Debugger) -> Result<R, DebuggerError> + Send + 'static,
        R: Send + 'static,
    {
        let handle = self.shared.debugger();
        let result = task::spawn_blocking(move || {
            let mut dbg = handle.lock();
            f(&mut dbg)
        })
        .await
        .map_err(|e| DapError::Internal(format!("blocking task error: {e}")))?;
        result.map_err(map_debugger_err)
    }

    async fn spawn_event_loop(&self, client: &Client) {
        let mut receiver = self.receiver.lock().await.take();
        if let Some(mut rx) = receiver.take() {
            let shared = self.shared.clone();
            let client = client.clone();
            task::spawn(async move {
                while let Some(event) = rx.recv().await {
                    if let Err(err) = handle_event(event, &client, &shared).await {
                        log::warn!(target: "dap", "event handling error: {err}");
                    }
                }
            });
        }
    }

    async fn spawn_output_forwarders(&self) {
        let stdout = self.stdout.clone();
        let stderr = self.stderr.clone();
        let tx_out = self.shared.event_sender();
        let tx_err = self.shared.event_sender();

        task::spawn_blocking(move || forward_output(stdout, "stdout", tx_out));
        task::spawn_blocking(move || forward_output(stderr, "stderr", tx_err));
    }

    async fn ensure_thread_number(&self, pid: Pid) -> Result<u32, DapError> {
        if let Some(number) = {
            let session = self.shared.session();
            session.thread_map.get(&pid.as_raw()).copied()
        } {
            return Ok(number);
        }

        let pid_raw = pid.as_raw();
        let snapshots = self.with_debugger(|dbg| dbg.thread_state()).await?;
        let mut session = self.shared.session();
        for snapshot in snapshots {
            session
                .thread_map
                .insert(snapshot.thread.pid.as_raw(), snapshot.thread.number);
        }
        session
            .thread_map
            .get(&pid_raw)
            .copied()
            .ok_or_else(|| DapError::Invalid(format!("thread pid {pid_raw} not found")))
    }
}

#[async_trait::async_trait]
impl DebugAdapter for BugStalkerAdapter {
    async fn initialize(
        &self,
        _client: &Client,
        _params: t::InitializeRequestArguments,
    ) -> Result<t::Capabilities, DapError> {
        let mut caps = CapabilitiesBuilder::new()
            .supports_configuration_done_request(true)
            .supports_cancel_request(true)
            .build();
        caps.supports_restart_request = Some(false);
        caps.supports_terminate_request = Some(true);
        Ok(caps)
    }

    async fn on_initialized(&self, client: &Client) -> Result<(), DapError> {
        client
            .initialized()
            .await
            .map_err(|e| DapError::Internal(format!("send initialized event: {e}")))?;
        self.spawn_event_loop(client).await;
        self.spawn_output_forwarders().await;
        Ok(())
    }

    async fn configuration_done(
        &self,
        client: &Client,
        _params: t::ConfigurationDoneArguments,
    ) -> Result<(), DapError> {
        {
            let mut session = self.shared.session();
            session.configured = true;
        }
        self.start_if_needed(client).await
    }

    async fn launch(
        &self,
        client: &Client,
        params: t::LaunchRequestArguments,
    ) -> Result<(), DapError> {
        if let Some(flag) = parse_stop_on_entry(&params.raw) {
            let mut session = self.shared.session();
            session.stop_on_entry = flag;
        }
        self.start_if_needed(client).await
    }

    async fn attach(
        &self,
        client: &Client,
        params: t::AttachRequestArguments,
    ) -> Result<(), DapError> {
        if let Some(flag) = parse_stop_on_entry(&params.raw) {
            let mut session = self.shared.session();
            session.stop_on_entry = flag;
        }
        self.start_if_needed(client).await
    }

    async fn r#continue(
        &self,
        client: &Client,
        _params: t::ContinueArguments,
    ) -> Result<t::ContinueResponse, DapError> {
        client
            .continued(t::ContinuedEvent {
                thread_id: self.shared.process_pid().as_raw() as u64,
                all_threads_continued: Some(true),
            })
            .await
            .map_err(|e| DapError::Internal(format!("send continued event: {e}")))?;
        self.with_debugger(|dbg| dbg.continue_debugee()).await?;
        Ok(t::ContinueResponse {
            all_threads_continued: Some(true),
        })
    }

    async fn next(&self, _client: &Client, _params: t::NextArguments) -> Result<(), DapError> {
        self.with_debugger(|dbg| dbg.step_over()).await
    }

    async fn step_in(&self, _client: &Client, _params: t::StepInArguments) -> Result<(), DapError> {
        self.with_debugger(|dbg| dbg.step_into()).await
    }

    async fn step_out(
        &self,
        _client: &Client,
        _params: t::StepOutArguments,
    ) -> Result<(), DapError> {
        self.with_debugger(|dbg| dbg.step_out()).await
    }

    async fn threads(&self, _client: &Client) -> Result<t::ThreadsResponse, DapError> {
        let snapshots = self.with_debugger(|dbg| dbg.thread_state()).await?;
        let mut threads = Vec::new();
        let mut map = self.shared.session();
        map.thread_map.clear();
        for snapshot in snapshots {
            map.thread_map
                .insert(snapshot.thread.pid.as_raw(), snapshot.thread.number);
            threads.push(t::Thread {
                id: snapshot.thread.pid.as_raw() as u64,
                name: format!("Thread {}", snapshot.thread.pid),
            });
        }
        Ok(t::ThreadsResponse { threads })
    }

    async fn stack_trace(
        &self,
        _client: &Client,
        params: t::StackTraceArguments,
    ) -> Result<t::StackTraceResponse, DapError> {
        let thread_pid = Pid::from_raw(params.thread_id as i32);
        let start = params.start_frame.map(|v| v as u32);
        let levels = params.levels.map(|v| v as u32);
        let (frames, total) = self
            .with_debugger(move |dbg| collect_stack_frames(dbg, thread_pid, start, levels))
            .await?;
        Ok(t::StackTraceResponse {
            stack_frames: frames,
            total_frames: Some(total as u64),
        })
    }

    async fn scopes(
        &self,
        _client: &Client,
        params: t::ScopesArguments,
    ) -> Result<t::ScopesResponse, DapError> {
        let (thread_pid, frame_index) = decode_frame_id(params.frame_id);
        let thread_number = self.ensure_thread_number(thread_pid).await?;
        let (locals, arguments) = self
            .with_debugger(move |dbg| {
                with_thread_frame(dbg, thread_number, thread_pid, frame_index, |dbg| {
                    let locals = dbg.read_local_variables()?;
                    let args = dbg.read_argument(Dqe::Variable(Selector::Any))?;
                    Ok::<_, DebuggerError>((
                        query_results_to_nodes(locals, "local"),
                        query_results_to_nodes(args, "arg"),
                    ))
                })
            })
            .await?;

        let locals_len = locals.len();
        let arguments_len = arguments.len();

        let mut session = self.shared.session();
        let locals_handle = session.variables.insert(VariableEntry::new(locals));
        let arguments_handle = session.variables.insert(VariableEntry::new(arguments));
        drop(session);

        let scopes = vec![
            t::Scope {
                column: None,
                end_column: None,
                end_line: None,
                expensive: false,
                indexed_variables: None,
                line: None,
                name: "Locals".into(),
                named_variables: Some(locals_len.min(u32::MAX as usize) as u32),
                presentation_hint: Some(t::ScopePresentationHint::Locals),
                source: None,
                variables_reference: locals_handle,
            },
            t::Scope {
                column: None,
                end_column: None,
                end_line: None,
                expensive: false,
                indexed_variables: None,
                line: None,
                name: "Arguments".into(),
                // Use named to signal count; treat as named values.
                named_variables: Some(arguments_len.min(u32::MAX as usize) as u32),
                presentation_hint: Some(t::ScopePresentationHint::Arguments),
                source: None,
                variables_reference: arguments_handle,
            },
        ];

        Ok(t::ScopesResponse { scopes })
    }

    async fn variables(
        &self,
        _client: &Client,
        params: t::VariablesArguments,
    ) -> Result<t::VariablesResponse, DapError> {
        if params.variables_reference == 0 {
            return Ok(t::VariablesResponse {
                variables: Vec::new(),
            });
        }
        let mut session = self.shared.session();
        let variables = session.variables.render(params.variables_reference)?;
        Ok(t::VariablesResponse { variables })
    }

    async fn evaluate(
        &self,
        _client: &Client,
        params: t::EvaluateArguments,
    ) -> Result<t::EvaluateResponse, DapError> {
        let expression_text = params.expression.clone();
        let dqe = parse_expression(&params.expression)?;

        let target = if let Some(frame_id) = params.frame_id {
            let (pid, frame_index) = decode_frame_id(frame_id);
            let thread_number = self.ensure_thread_number(pid).await?;
            Some((pid, frame_index, thread_number))
        } else {
            None
        };

        let dqe_for_eval = dqe.clone();
        let mut nodes = self
            .with_debugger(move |dbg| {
                let eval = |dbg: &mut Debugger| -> Result<Vec<VariableNode>, DebuggerError> {
                    let results = dbg.read_variable(dqe_for_eval.clone())?;
                    Ok(query_results_to_nodes(results, "eval"))
                };
                if let Some((pid, frame_index, thread_number)) = target {
                    with_thread_frame(dbg, thread_number, pid, frame_index, |dbg| eval(dbg))
                } else {
                    eval(dbg)
                }
            })
            .await?;

        if let Some(first) = nodes.first_mut() {
            first.evaluate_name = Some(expression_text.clone());
            if first.name.is_none() {
                first.name = Some(expression_text.clone());
            }
        }

        let (result_value, result_type, memory_reference) = nodes
            .first()
            .map(|node| {
                (
                    node.value_summary.clone(),
                    node.type_name.clone(),
                    node.memory_reference.clone(),
                )
            })
            .unwrap_or_else(|| (String::new(), None, None));

        let variables_reference = if nodes.is_empty() {
            0
        } else {
            let mut session = self.shared.session();
            session.variables.insert(VariableEntry::new(nodes))
        };

        Ok(t::EvaluateResponse {
            indexed_variables: None,
            memory_reference,
            named_variables: None,
            presentation_hint: None,
            result: result_value,
            ty: result_type,
            value_location_reference: None,
            variables_reference,
        })
    }

    async fn pause(&self, _client: &Client, _params: t::PauseArguments) -> Result<(), DapError> {
        signal::kill(self.shared.process_pid(), Signal::SIGINT)
            .map_err(|e| DapError::Internal(format!("send SIGINT: {e}")))
    }

    async fn terminate(
        &self,
        _client: &Client,
        _params: t::TerminateArguments,
    ) -> Result<(), DapError> {
        signal::kill(self.shared.process_pid(), Signal::SIGTERM)
            .map_err(|e| DapError::Internal(format!("send SIGTERM: {e}")))
    }

    async fn disconnect(
        &self,
        _client: &Client,
        _params: t::DisconnectArguments,
    ) -> Result<(), DapError> {
        Ok(())
    }

    async fn set_breakpoints(
        &self,
        _client: &Client,
        params: t::SetBreakpointsArguments,
    ) -> Result<t::SetBreakpointsResponse, DapError> {
        let source_path = params
            .source
            .path
            .ok_or_else(|| DapError::Invalid("source path required".into()))?;

        let breakpoints = params.breakpoints.unwrap_or_default();
        let mut results = Vec::new();
        for bp in breakpoints {
            let path = source_path.clone();
            let line = bp.line;
            let view = self
                .with_debugger(move |dbg| {
                    let views = dbg.set_breakpoint_at_line(&path, line as u64)?;
                    Ok::<Vec<BreakpointViewOwned>, DebuggerError>(
                        views.into_iter().map(|view| view.to_owned()).collect(),
                    )
                })
                .await;
            match view {
                Ok(mut list) => {
                    let response = list.pop();
                    results.push(convert_breakpoint(response, bp.line, &source_path));
                }
                Err(err) => {
                    results.push(t::Breakpoint {
                        verified: false,
                        line: Some(bp.line),
                        message: Some(err.message()),
                        ..Default::default()
                    });
                }
            }
        }

        Ok(t::SetBreakpointsResponse {
            breakpoints: results,
        })
    }
}

impl BugStalkerAdapter {
    async fn start_if_needed(&self, client: &Client) -> Result<(), DapError> {
        let (should_start, stop_on_entry) = {
            let mut session = self.shared.session();
            if session.started || !session.configured {
                (false, session.stop_on_entry)
            } else {
                session.started = true;
                (true, session.stop_on_entry)
            }
        };

        if should_start {
            self.with_debugger(|dbg| dbg.start_debugee()).await?;
            if !stop_on_entry {
                client
                    .continued(t::ContinuedEvent {
                        thread_id: self.shared.process_pid().as_raw() as u64,
                        all_threads_continued: Some(true),
                    })
                    .await
                    .map_err(|e| DapError::Internal(format!("send continued event: {e}")))?;
                self.with_debugger(|dbg| dbg.continue_debugee()).await?;
            }
        }
        Ok(())
    }
}

fn parse_stop_on_entry(raw: &Value) -> Option<bool> {
    raw.get("stopOnEntry")
        .or_else(|| raw.get("stop_on_entry"))
        .and_then(|v| v.as_bool())
}

fn collect_stack_frames(
    dbg: &mut Debugger,
    thread_pid: Pid,
    start: Option<u32>,
    levels: Option<u32>,
) -> Result<(Vec<t::StackFrame>, usize), DebuggerError> {
    let snapshots = dbg.thread_state()?;
    if let Some(number) = snapshots
        .iter()
        .find(|snap| snap.thread.pid == thread_pid)
        .map(|snap| snap.thread.number)
    {
        let _ = dbg.set_thread_into_focus(number)?;
    }
    let backtrace = dbg.backtrace(thread_pid)?;
    let total = backtrace.len();
    let start = start.unwrap_or(0) as usize;
    let count = levels.unwrap_or(total as u32) as usize;

    let mut frames = Vec::new();
    for (index, frame) in backtrace.into_iter().enumerate().skip(start).take(count) {
        let frame_id = ((thread_pid.as_raw() as u64) << 32) | index as u64;
        let mut source = None;
        let mut line = 0;
        let mut column = 0;
        if let Some(place) = frame.place {
            line = place.line_number as u32;
            column = (if place.column_number == 0 {
                1
            } else {
                place.column_number
            }) as u32;
            source = Some(t::Source {
                name: place
                    .file
                    .file_name()
                    .map(|os| os.to_string_lossy().to_string()),
                path: Some(place.file.to_string_lossy().to_string()),
                ..Default::default()
            });
        }
        frames.push(t::StackFrame {
            can_restart: None,
            column,
            end_column: None,
            end_line: None,
            id: frame_id,
            instruction_pointer_reference: None,
            line,
            module_id: None,
            name: frame.func_name.unwrap_or_else(|| "<unknown>".into()),
            presentation_hint: None,
            source,
        });
    }

    Ok((frames, total))
}

fn convert_breakpoint(
    view: Option<crate::debugger::BreakpointViewOwned>,
    line: u32,
    path: &str,
) -> t::Breakpoint {
    if let Some(view) = view {
        let source = view.place.as_ref().map(|place| t::Source {
            name: place
                .file
                .file_name()
                .map(|os| os.to_string_lossy().to_string()),
            path: Some(place.file.to_string_lossy().to_string()),
            adapter_data: None,
            checksums: None,
            origin: None,
            presentation_hint: None,
            source_reference: None,
            sources: None,
        });
        t::Breakpoint {
            id: Some(view.number as u64),
            verified: true,
            line: Some(
                view.place
                    .as_ref()
                    .map(|p| p.line_number as u32)
                    .unwrap_or(line),
            ),
            source,
            ..Default::default()
        }
    } else {
        t::Breakpoint {
            verified: false,
            source: Some(t::Source {
                name: std::path::Path::new(path)
                    .file_name()
                    .map(|os| os.to_string_lossy().to_string()),
                path: Some(path.to_string()),
                adapter_data: None,
                checksums: None,
                origin: None,
                presentation_hint: None,
                source_reference: None,
                sources: None,
            }),
            line: Some(line),
            message: Some("Failed to set breakpoint".into()),
            ..Default::default()
        }
    }
}

#[derive(Default)]
struct VariableHandles {
    next_id: u32,
    entries: HashMap<u32, VariableEntry>,
}

impl VariableHandles {
    fn insert(&mut self, entry: VariableEntry) -> u32 {
        let id = self.next_id.max(1);
        self.next_id = id.saturating_add(1);
        self.entries.insert(id, entry);
        id
    }

    fn render(&mut self, handle: u32) -> Result<Vec<t::Variable>, DapError> {
        let entry = self
            .entries
            .get(&handle)
            .cloned()
            .ok_or_else(|| DapError::Invalid(format!("unknown variablesReference {handle}")))?;
        let mut rendered = Vec::with_capacity(entry.variables.len());
        for node in entry.variables {
            rendered.push(node.into_dap_variable(self));
        }
        Ok(rendered)
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.next_id = 1;
    }
}

#[derive(Clone)]
struct VariableEntry {
    variables: Vec<VariableNode>,
}

impl VariableEntry {
    fn new(variables: Vec<VariableNode>) -> Self {
        Self { variables }
    }
}

#[derive(Clone)]
struct VariableNode {
    name: Option<String>,
    type_name: Option<String>,
    evaluate_name: Option<String>,
    value_summary: String,
    presentation_hint: Option<t::VariablePresentationHint>,
    memory_reference: Option<String>,
    children: ChildKind,
}

#[derive(Clone)]
enum ChildKind {
    None,
    Deferred(ValueChildren),
    Precomputed(ExpandedChildren),
}

#[derive(Clone)]
struct ValueChildren {
    value: DebugValue,
    eval_name: Option<String>,
}

#[derive(Clone)]
struct ExpandedChildren {
    nodes: Vec<VariableNode>,
    kind: CollectionKind,
}

#[derive(Clone, Copy)]
enum CollectionKind {
    Named,
    Indexed,
}

impl VariableNode {
    fn into_dap_variable(self, store: &mut VariableHandles) -> t::Variable {
        let (variables_reference, named, indexed) = match self.children {
            ChildKind::None => (0, None, None),
            ChildKind::Deferred(children) => {
                let ExpandedChildren { nodes, kind } = children.expand();
                let len = nodes.len();
                if len == 0 {
                    (0, None, None)
                } else {
                    let handle = store.insert(VariableEntry::new(nodes));
                    let (named, indexed) = kind.counts(len);
                    (handle, named, indexed)
                }
            }
            ChildKind::Precomputed(expanded) => {
                let ExpandedChildren { nodes, kind } = expanded;
                let len = nodes.len();
                if len == 0 {
                    (0, None, None)
                } else {
                    let handle = store.insert(VariableEntry::new(nodes));
                    let (named, indexed) = kind.counts(len);
                    (handle, named, indexed)
                }
            }
        };

        t::Variable {
            declaration_location_reference: None,
            evaluate_name: self.evaluate_name,
            indexed_variables: indexed,
            memory_reference: self.memory_reference,
            name: self.name.unwrap_or_default(),
            named_variables: named,
            presentation_hint: self.presentation_hint,
            ty: self.type_name,
            value: self.value_summary,
            value_location_reference: None,
            variables_reference,
        }
    }
}

impl ValueChildren {
    fn expand(&self) -> ExpandedChildren {
        match self.value.value_layout() {
            Some(ValueLayout::Structure(members)) => {
                let nodes = members
                    .iter()
                    .map(|member| {
                        let child_eval = self.eval_name.as_ref().and_then(|base| {
                            member.field_name.as_ref().map(|f| format!("{base}.{f}"))
                        });
                        let name = member.field_name.clone();
                        let value = member.value.clone();
                        make_variable_node(name, value, child_eval)
                    })
                    .collect();
                ExpandedChildren {
                    nodes,
                    kind: CollectionKind::Named,
                }
            }
            Some(ValueLayout::IndexedList(items)) => {
                let nodes = items
                    .iter()
                    .map(|item| {
                        let idx = item.index;
                        let name = Some(format!("[{idx}]"));
                        let eval = self.eval_name.as_ref().map(|base| format!("{base}[{idx}]"));
                        make_variable_node(name, item.value.clone(), eval)
                    })
                    .collect();
                ExpandedChildren {
                    nodes,
                    kind: CollectionKind::Indexed,
                }
            }
            Some(ValueLayout::NonIndexedList(values)) => {
                let nodes = values
                    .iter()
                    .enumerate()
                    .map(|(idx, value)| {
                        let name = Some(format!("[{idx}]"));
                        let eval = self.eval_name.as_ref().map(|base| format!("{base}[{idx}]"));
                        make_variable_node(name, value.clone(), eval)
                    })
                    .collect();
                ExpandedChildren {
                    nodes,
                    kind: CollectionKind::Indexed,
                }
            }
            Some(ValueLayout::Map(kvs)) => {
                let nodes = kvs
                    .iter()
                    .enumerate()
                    .map(|(idx, (key, val))| {
                        let key_summary = summarize_value(key);
                        let entry_name = if key_summary.is_empty() {
                            format!("[{idx}]")
                        } else {
                            key_summary
                        };
                        let key_node = make_variable_node(Some("key".into()), key.clone(), None);
                        let value_node =
                            make_variable_node(Some("value".into()), val.clone(), None);
                        VariableNode {
                            name: Some(entry_name),
                            type_name: Some(val.r#type().name_fmt().to_string()),
                            evaluate_name: None,
                            value_summary: summarize_value(val),
                            presentation_hint: None,
                            memory_reference: None,
                            children: ChildKind::Precomputed(ExpandedChildren {
                                nodes: vec![key_node, value_node],
                                kind: CollectionKind::Named,
                            }),
                        }
                    })
                    .collect();
                ExpandedChildren {
                    nodes,
                    kind: CollectionKind::Named,
                }
            }
            _ => ExpandedChildren {
                nodes: Vec::new(),
                kind: CollectionKind::Named,
            },
        }
    }
}

impl CollectionKind {
    fn counts(self, len: usize) -> (Option<u32>, Option<u32>) {
        let len = len.min(u32::MAX as usize) as u32;
        match self {
            CollectionKind::Named => (Some(len), None),
            CollectionKind::Indexed => (None, Some(len)),
        }
    }
}

fn make_variable_node(
    name: Option<String>,
    value: DebugValue,
    eval_name: Option<String>,
) -> VariableNode {
    let type_name = Some(value.r#type().name_fmt().to_string());
    let value_summary = summarize_value(&value);
    let memory_reference = value.in_memory_location().map(|addr| format!("{addr:#x}"));

    let presentation_hint = None;
    let children = match value.value_layout() {
        Some(ValueLayout::Structure(_))
        | Some(ValueLayout::IndexedList(_))
        | Some(ValueLayout::NonIndexedList(_))
        | Some(ValueLayout::Map(_)) => ChildKind::Deferred(ValueChildren {
            value: value.clone(),
            eval_name: eval_name.clone(),
        }),
        Some(ValueLayout::Wrapped(inner)) => {
            let inner_node = make_variable_node(None, inner.clone(), eval_name.clone());
            ChildKind::Precomputed(ExpandedChildren {
                nodes: vec![inner_node],
                kind: CollectionKind::Named,
            })
        }
        _ => ChildKind::None,
    };

    VariableNode {
        name,
        type_name,
        evaluate_name: eval_name,
        value_summary,
        presentation_hint,
        memory_reference,
        children,
    }
}

fn summarize_value(value: &DebugValue) -> String {
    match value.value_layout() {
        Some(ValueLayout::PreRendered(rendered)) => rendered.to_string(),
        Some(ValueLayout::Referential(addr)) => format!("{:#x}", addr as usize),
        Some(ValueLayout::Structure(_)) => {
            format!("{} {{…}}", value.r#type().name_fmt())
        }
        Some(ValueLayout::IndexedList(items)) => {
            format!("{} [{}]", value.r#type().name_fmt(), items.len())
        }
        Some(ValueLayout::NonIndexedList(values)) => {
            format!("{} [{}]", value.r#type().name_fmt(), values.len())
        }
        Some(ValueLayout::Map(entries)) => {
            format!("{} [{}]", value.r#type().name_fmt(), entries.len())
        }
        Some(ValueLayout::Wrapped(inner)) => {
            format!("{}({})", value.r#type().name_fmt(), summarize_value(inner))
        }
        None => value.r#type().name_fmt().to_string(),
    }
}

fn query_results_to_nodes<'a>(
    results: Vec<QueryResult<'a>>,
    fallback_prefix: &str,
) -> Vec<VariableNode> {
    results
        .into_iter()
        .enumerate()
        .map(|(idx, result)| query_result_to_node(result, fallback_prefix, idx))
        .collect()
}

fn query_result_to_node(
    result: QueryResult<'_>,
    fallback_prefix: &str,
    index: usize,
) -> VariableNode {
    let identity = result.identity().clone();
    let eval_name = if result.kind() == QueryResultKind::Root {
        let text = identity.to_string();
        if text.is_empty() { None } else { Some(text) }
    } else {
        None
    };
    let name = identity
        .name
        .clone()
        .filter(|n| !n.is_empty())
        .or_else(|| Some(format!("{fallback_prefix}{index}")));
    let value: DebugValue = result.into_value();
    make_variable_node(name, value, eval_name)
}

fn decode_frame_id(frame_id: u64) -> (Pid, u32) {
    let thread_raw = (frame_id >> 32) as i32;
    let frame_index = (frame_id & 0xFFFF_FFFF) as u32;
    (Pid::from_raw(thread_raw), frame_index)
}

fn with_thread_frame<F, R>(
    dbg: &mut Debugger,
    thread_number: u32,
    thread_pid: Pid,
    frame_index: u32,
    f: F,
) -> Result<R, DebuggerError>
where
    F: FnOnce(&mut Debugger) -> Result<R, DebuggerError>,
{
    let original_ctx = dbg.exploration_ctx().clone();
    let original_pid = original_ctx.pid_on_focus();
    let original_frame = original_ctx.frame_num();

    let mut original_thread_number = None;
    if original_pid != thread_pid {
        let snapshots = dbg.thread_state()?;
        original_thread_number = snapshots
            .iter()
            .find(|snap| snap.thread.pid == original_pid)
            .map(|snap| snap.thread.number);
        if original_thread_number.is_none() {
            return Err(DebuggerError::TraceeNotFound(original_pid.as_raw() as u32));
        }
    }

    if original_pid != thread_pid {
        dbg.set_thread_into_focus(thread_number)?;
    }
    if dbg.exploration_ctx().frame_num() != frame_index {
        dbg.set_frame_into_focus(frame_index)?;
    }

    let result = f(dbg);

    if original_pid != thread_pid {
        if let Some(orig_number) = original_thread_number {
            dbg.set_thread_into_focus(orig_number)?;
            if original_frame != 0 {
                dbg.set_frame_into_focus(original_frame)?;
            }
        }
    } else if original_frame != frame_index {
        dbg.set_frame_into_focus(original_frame)?;
    }

    result
}

fn parse_expression(expr: &str) -> Result<Dqe, DapError> {
    expression::parser()
        .parse(expr)
        .into_result()
        .map_err(|errs| {
            let msg = errs
                .into_iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join(", ");
            DapError::Invalid(format!("invalid expression: {msg}"))
        })
}

fn forward_output(
    mut reader: DebugeeOutReader,
    category: &'static str,
    tx: mpsc::UnboundedSender<DapEvent>,
) {
    let mut buf = [0u8; 4096];
    loop {
        match reader.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                let _ = tx.send(DapEvent::Output {
                    category: category.to_string(),
                    message: chunk,
                });
            }
            Err(err) => {
                let _ = tx.send(DapEvent::Output {
                    category: "stderr".into(),
                    message: format!("I/O error: {err}"),
                });
                break;
            }
        }
    }
}

async fn handle_event(
    event: DapEvent,
    client: &Client,
    shared: &Arc<DapSharedState>,
) -> Result<(), DapError> {
    match event {
        DapEvent::Stopped(reason) => {
            {
                let mut session = shared.session();
                session.variables.clear();
            }
            let snapshot = snapshot_focus(shared).await?;
            let dap_reason = match reason {
                StopEvent::Breakpoint { .. } => t::StoppedEventReason::Breakpoint,
                StopEvent::Step => t::StoppedEventReason::Step,
                StopEvent::Signal { .. } => t::StoppedEventReason::Exception,
                StopEvent::Watchpoint => t::StoppedEventReason::DataBreakpoint,
            };
            let text = match reason {
                StopEvent::Breakpoint { id } => Some(format!("Hit breakpoint #{id}")),
                StopEvent::Signal { signal } => Some(format!("Signal {signal}")),
                StopEvent::Watchpoint => Some("Watchpoint triggered".into()),
                StopEvent::Step => None,
            };

            let mut event = t::StoppedEvent {
                all_threads_stopped: Some(true),
                description: None,
                hit_breakpoint_ids: match reason {
                    StopEvent::Breakpoint { id } => Some(vec![id as u64]),
                    _ => None,
                },
                preserve_focus_hint: None,
                reason: dap_reason,
                text: None,
                thread_id: Some(snapshot.thread_id),
            };
            event.text = text;
            client
                .stopped(event)
                .await
                .map_err(|e| DapError::Internal(format!("send stopped event: {e}")))
        }
        DapEvent::Output { category, message } => client
            .output(Some(&category), message)
            .await
            .map_err(|e| DapError::Internal(format!("send output event: {e}"))),
        DapEvent::Exited { code } => {
            {
                let mut session = shared.session();
                session.variables.clear();
            }
            client
                .exited(t::ExitedEvent {
                    exit_code: code as u64,
                })
                .await
                .map_err(|e| DapError::Internal(format!("send exited event: {e}")))?;
            client
                .terminated(t::TerminatedEvent { restart: None })
                .await
                .map_err(|e| DapError::Internal(format!("send terminated event: {e}")))
        }
    }
}

async fn snapshot_focus(shared: &Arc<DapSharedState>) -> Result<StopSnapshot, DapError> {
    let debugger = shared.debugger();
    let result = task::spawn_blocking(move || {
        let dbg = debugger.lock();
        let ctx = dbg.exploration_ctx();
        let pid = ctx.pid_on_focus();
        Ok::<_, DebuggerError>(StopSnapshot {
            thread_id: pid.as_raw() as u64,
        })
    })
    .await
    .map_err(|e| DapError::Internal(format!("snapshot join error: {e}")))?;
    result.map_err(map_debugger_err)
}

struct StopSnapshot {
    thread_id: u64,
}

fn map_debugger_err(err: DebuggerError) -> DapError {
    DapError::Internal(format!("debugger error: {err:#}"))
}

#[derive(Clone)]
enum DapEvent {
    Stopped(StopEvent),
    Output { category: String, message: String },
    Exited { code: i32 },
}

#[derive(Clone)]
enum StopEvent {
    Breakpoint { id: u32 },
    Step,
    Signal { signal: Signal },
    Watchpoint,
}

#[derive(Clone)]
struct DapHook {
    events: mpsc::UnboundedSender<DapEvent>,
    process_pid: Arc<AtomicI32>,
}

impl DapHook {
    fn new(events: mpsc::UnboundedSender<DapEvent>, process_pid: Arc<AtomicI32>) -> Self {
        Self {
            events,
            process_pid,
        }
    }
}

impl crate::debugger::EventHook for DapHook {
    fn on_breakpoint(
        &self,
        _: crate::debugger::address::RelocatedAddress,
        num: u32,
        _: Option<crate::debugger::PlaceDescriptor>,
        _: Option<&crate::debugger::FunctionDie>,
    ) -> anyhow::Result<()> {
        let _ = self
            .events
            .send(DapEvent::Stopped(StopEvent::Breakpoint { id: num }));
        Ok(())
    }

    fn on_watchpoint(
        &self,
        _: crate::debugger::address::RelocatedAddress,
        _: u32,
        _: Option<crate::debugger::PlaceDescriptor>,
        _: crate::debugger::register::debug::BreakCondition,
        _: Option<&str>,
        _: Option<&crate::debugger::variable::value::Value>,
        _: Option<&crate::debugger::variable::value::Value>,
        _: bool,
    ) -> anyhow::Result<()> {
        let _ = self.events.send(DapEvent::Stopped(StopEvent::Watchpoint));
        Ok(())
    }

    fn on_step(
        &self,
        _: crate::debugger::address::RelocatedAddress,
        _: Option<crate::debugger::PlaceDescriptor>,
        _: Option<&crate::debugger::FunctionDie>,
    ) -> anyhow::Result<()> {
        let _ = self.events.send(DapEvent::Stopped(StopEvent::Step));
        Ok(())
    }

    fn on_async_step(
        &self,
        _: crate::debugger::address::RelocatedAddress,
        _: Option<crate::debugger::PlaceDescriptor>,
        _: Option<&crate::debugger::FunctionDie>,
        _: u64,
        _: bool,
    ) -> anyhow::Result<()> {
        let _ = self.events.send(DapEvent::Stopped(StopEvent::Step));
        Ok(())
    }

    fn on_signal(&self, signal: Signal) {
        let _ = self
            .events
            .send(DapEvent::Stopped(StopEvent::Signal { signal }));
    }

    fn on_exit(&self, code: i32) {
        let _ = self.events.send(DapEvent::Exited { code });
    }

    fn on_process_install(&self, pid: Pid, _: Option<&object::File>) {
        self.process_pid.store(pid.as_raw(), Ordering::Release);
    }
}
