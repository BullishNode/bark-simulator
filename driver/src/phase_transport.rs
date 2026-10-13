//! Client-only gRPC capture/gate, scoped to one selected wallet invocation.
//!
//! The upstream Channel is the operator-pinned channel already used for server
//! identity/TLS verification. No upstream endpoint or global SDK route changes.
//! Captures preserve raw gRPC body bytes and decoded HTTP headers/trailers;
//! they do not claim to retain encrypted packets or HPACK wire encodings.
use anyhow::{Context, Result, ensure};
use bitcoin::hashes::{Hash, sha256};
use bytes::Bytes;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, StreamBody};
use hyper::{Request, Response, body::Incoming, service::service_fn};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    convert::Infallible,
    fs,
    io::Write,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    task::{Context as PollContext, Poll},
};
use tokio::{net::TcpListener, sync::Notify, task::JoinHandle};
use tonic::transport::Channel;
use tower::ServiceExt;

const MAX_REQUEST: usize = 4 * 1024 * 1024;
const MAX_CAPTURE: u64 = 64 * 1024 * 1024;
const MAX_REQUESTS: u64 = 128;
fn hash(bytes: &[u8]) -> String {
    sha256::Hash::hash(bytes).to_string()
}
fn headers(value: &hyper::HeaderMap) -> Vec<u8> {
    serde_json::to_vec(&value.iter().map(|(name,value)|json!({"name":name.as_str(),"value_hex":value.as_bytes().iter().map(|b|format!("{b:02x}")).collect::<String>()})).collect::<Vec<_>>()).unwrap()
}
fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    fs::File::open(path.parent().context("capture parent")?)?.sync_all()?;
    Ok(())
}

/// Every RPC must be explicitly declared. Money RPCs have bounded counts;
/// read-only RPCs are also bounded so SDK retry loops cannot exhaust storage.
#[derive(Clone)]
pub struct Plan {
    pub actor: String,
    pub action_id: String,
    pub intent_sha256: String,
    pub manifest_sha256: String,
    pub expected_server_pubkey: String,
    pub service_prefix: String,
    pub rpc_limits: HashMap<String, u32>,
    pub barrier_rpc: String,
    pub barrier_requests: u64,
}
/// Validate actual decoded SDK request semantics against the frozen input/
/// output/fee intent. The validator must reject mismatches before forwarding;
/// a client-side validation failure never qualifies a server refusal scenario.
pub type Validator = Arc<dyn Fn(&str, &[u8]) -> Result<Value> + Send + Sync>;

pub struct Gate {
    plan: Plan,
    root: PathBuf,
    validator: Validator,
    counts: Mutex<HashMap<String, u32>>,
    next: AtomicU64,
    captured: AtomicU64,
    prepared: AtomicU64,
    released: AtomicBool,
    failed: AtomicBool,
    ready: Notify,
    release: Notify,
}
impl Gate {
    pub fn create(plan: Plan, root: PathBuf, validator: Validator) -> Result<Arc<Self>> {
        ensure!(
            plan.actor.starts_with("actor-")
                && plan.actor.len() == 8
                && plan.actor[6..].parse::<u8>().is_ok()
                && !matches!(plan.actor.as_str(), "actor-03" | "actor-09" | "actor-10"),
            "only one online non-absent client can use transport gate"
        );
        ensure!(
            !plan.action_id.is_empty()
                && plan.intent_sha256.len() == 64
                && plan.manifest_sha256.len() == 64,
            "immutable invocation declaration missing"
        );
        ensure!(
            plan.service_prefix.starts_with('/')
                && plan.service_prefix.ends_with('/')
                && plan.barrier_requests > 0
                && plan.barrier_requests <= 2
                && plan
                    .rpc_limits
                    .get(&plan.barrier_rpc)
                    .is_some_and(|limit| u64::from(*limit) == plan.barrier_requests),
            "one declared barrier RPC required"
        );
        ensure!(
            plan.rpc_limits
                .get("SubmitPayment")
                .is_none_or(|count| *count <= 1),
            "second SubmitPayment must never be forwarded"
        );
        ensure!(!root.is_symlink(), "private capture scope is symlink");
        // This invocation cannot be resumed: SDK signing nonces are process-only.
        fs::create_dir(&root).context("capture invocation exists; reconcile without retry")?;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
        save(
            &root.join("scope.json"),
            &serde_json::to_vec(
                &json!({"actor":plan.actor,"action_id":plan.action_id,"intent_sha256":plan.intent_sha256,"manifest_sha256":plan.manifest_sha256,"server_pubkey":plan.expected_server_pubkey,"barrier_rpc":plan.barrier_rpc,"rpc_limits":plan.rpc_limits,"capture_scope":"exact gRPC body bytes, decoded HTTP metadata/trailers; no HPACK/encrypted packet claim","automatic_restart_continuation":false}),
            )?,
        )?;
        fs::File::open(root.parent().context("capture parent missing")?)?.sync_all()?;
        Ok(Arc::new(Self {
            plan,
            root,
            validator,
            counts: Mutex::new(HashMap::new()),
            next: AtomicU64::new(1),
            captured: AtomicU64::new(0),
            prepared: AtomicU64::new(0),
            released: AtomicBool::new(false),
            failed: AtomicBool::new(false),
            ready: Notify::new(),
            release: Notify::new(),
        }))
    }
    fn capture(&self, id: u64, side: &str, sequence: u64, kind: &str, bytes: &[u8]) -> Result<()> {
        self.captured
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |old| {
                old.checked_add(bytes.len() as u64)
                    .filter(|size| *size <= MAX_CAPTURE)
            })
            .map_err(|_| {
                anyhow::anyhow!("private invocation capture bound exceeded; outcome unknown")
            })?;
        save(
            &self.root.join(format!("{id}-{side}-{sequence}-{kind}.bin")),
            bytes,
        )?;
        save(
            &self
                .root
                .join(format!("{id}-{side}-{sequence}-{kind}.json")),
            &serde_json::to_vec(
                &json!({"request_ordinal":id,"side":side,"sequence":sequence,"kind":kind,"bytes":bytes.len(),"sha256":hash(bytes),"actor":self.plan.actor,"action_id":self.plan.action_id,"observed_at_ns":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()}),
            )?,
        )?;
        Ok(())
    }
    fn admit(&self, method: &str, body: &[u8]) -> Result<Value> {
        let limit = *self
            .plan
            .rpc_limits
            .get(method)
            .context("undeclared client RPC; no forwarding")?;
        let decoded = (self.validator)(method, body)?;
        let mut counts = self
            .counts
            .lock()
            .map_err(|_| anyhow::anyhow!("capture gate poisoned"))?;
        let count = counts.entry(method.to_string()).or_default();
        ensure!(
            *count < limit,
            "RPC invocation budget exhausted; no SDK retry forwarded"
        );
        *count += 1;
        Ok(decoded)
    }
    pub fn has_failed(&self) -> bool {
        self.failed.load(Ordering::Acquire)
    }
    pub fn invoked(&self, method: &str) -> bool {
        self.counts
            .lock()
            .map(|counts| counts.get(method).copied().unwrap_or(0) > 0)
            .unwrap_or(true)
    }
    pub async fn wait_prepared(&self) -> Result<()> {
        loop {
            let notified = self.ready.notified();
            if self.prepared.load(Ordering::Acquire) >= self.plan.barrier_requests {
                return Ok(());
            }
            tokio::time::timeout(std::time::Duration::from_secs(30), notified)
                .await
                .context("SDK did not produce frozen barrier request before deadline")?;
        }
    }
    pub fn release_once(&self) -> Result<()> {
        ensure!(
            self.prepared.load(Ordering::Acquire) >= self.plan.barrier_requests,
            "SDK request is not durably frozen"
        );
        ensure!(
            !self.released.swap(true, Ordering::AcqRel),
            "barrier release already consumed"
        );
        self.release.notify_waiters();
        Ok(())
    }
    async fn hold(&self, method: &str) -> Result<()> {
        if method != self.plan.barrier_rpc {
            return Ok(());
        }
        self.prepared.fetch_add(1, Ordering::AcqRel);
        self.ready.notify_waiters();
        loop {
            let notified = self.release.notified();
            if self.released.load(Ordering::Acquire) {
                return Ok(());
            }
            tokio::time::timeout(std::time::Duration::from_secs(30), notified)
                .await
                .context("frozen request was not released; no forwarding")?;
        }
    }
}

struct CapturedBody {
    inner: tonic::body::Body,
    gate: Arc<Gate>,
    id: u64,
    sequence: u64,
}
impl Body for CapturedBody {
    type Data = Bytes;
    type Error = tonic::Status;
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut PollContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, tonic::Status>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let captured = if let Some(data) = frame.data_ref() {
                    this.gate
                        .capture(this.id, "response", this.sequence, "data", data)
                } else if let Some(trailers) = frame.trailers_ref() {
                    this.gate.capture(
                        this.id,
                        "response",
                        this.sequence,
                        "trailers",
                        &headers(trailers),
                    )
                } else {
                    Err(anyhow::anyhow!("unknown body frame; capture incomplete"))
                };
                if let Some(trailers) = frame.trailers_ref() {
                    if trailers
                        .get("grpc-status")
                        .is_some_and(|value| value.as_bytes() != b"0")
                    {
                        this.gate.failed.store(true, Ordering::Release);
                    }
                }
                if captured.is_err() {
                    this.gate.failed.store(true, Ordering::Release);
                    return Poll::Ready(Some(Err(tonic::Status::internal(
                        "private capture failed; financial outcome unknown",
                    ))));
                }
                this.sequence += 1;
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(error))) => {
                this.gate.failed.store(true, Ordering::Release);
                let _ = this.gate.capture(
                    this.id,
                    "response",
                    this.sequence,
                    "error",
                    error.to_string().as_bytes(),
                );
                Poll::Ready(Some(Err(error)))
            }
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}
fn client_refusal() -> Response<tonic::body::Body> {
    // Explicitly a client capture/control failure, never evidence from captaind.
    let mut trailers = hyper::HeaderMap::new();
    trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("10"));
    trailers.insert(
        "grpc-message",
        hyper::header::HeaderValue::from_static(
            "client%20capture%20gate%20held%3B%20outcome%20unknown",
        ),
    );
    let body = StreamBody::new(futures::stream::iter(vec![Ok::<_, Infallible>(
        Frame::trailers(trailers),
    )]));
    Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(tonic::body::Body::new(body))
        .unwrap()
}
async fn proxy(
    upstream: Channel,
    gate: Arc<Gate>,
    request: Request<Incoming>,
) -> Result<Response<tonic::body::Body>> {
    let id = gate.next.fetch_add(1, Ordering::Relaxed);
    ensure!(id <= MAX_REQUESTS, "invocation request bound exceeded");
    let (parts, mut body) = request.into_parts();
    let Some(method) = parts
        .uri
        .path()
        .strip_prefix(gate.plan.service_prefix.as_str())
    else {
        return Ok(client_refusal());
    };
    ensure!(
        !method.contains('/'),
        "RPC path differs from declared service"
    );
    let method = method.to_string();
    let request_headers = serde_json::to_vec(
        &json!({"method":parts.method.as_str(),"uri":parts.uri.to_string(),"http_version":format!("{:?}",parts.version),"headers_hex":headers(&parts.headers).iter().map(|b|format!("{b:02x}")).collect::<String>()}),
    )?;
    gate.capture(id, "request", 0, "headers", &request_headers)?;
    let mut frames = Vec::new();
    let mut wire = Vec::new();
    let mut sequence = 1;
    while let Some(frame) = body.frame().await {
        let frame = frame?;
        if let Some(data) = frame.data_ref() {
            ensure!(
                wire.len()
                    .checked_add(data.len())
                    .is_some_and(|len| len <= MAX_REQUEST),
                "client request exceeds capture bound"
            );
            wire.extend_from_slice(data);
            gate.capture(id, "request", sequence, "data", data)?;
        } else if let Some(trailers) = frame.trailers_ref() {
            gate.capture(id, "request", sequence, "trailers", &headers(trailers))?;
        } else {
            anyhow::bail!("unknown request frame");
        }
        sequence += 1;
        ensure!(sequence <= 8192, "request frame count exceeded");
        frames.push(frame);
    }
    // No bytes have been forwarded. Semantic validation and durable public
    // request checkpoint both precede the release of the original SDK request.
    let decoded = match gate.admit(&method, &wire) {
        Ok(value) => value,
        Err(error) => {
            gate.failed.store(true, Ordering::Release);
            gate.capture(
                id,
                "request",
                sequence,
                "client_gate_refusal",
                error.to_string().as_bytes(),
            )?;
            return Ok(client_refusal());
        }
    };
    save(
        &gate.root.join(format!("{id}-request-frozen.json")),
        &serde_json::to_vec(
            &json!({"method":method,"wire_sha256":hash(&wire),"decoded":decoded,"request_ordinal":id,"intent_sha256":gate.plan.intent_sha256,"forwarded":false,"sdk_nonces_process_only":true}),
        )?,
    )?;
    gate.hold(&method).await?;
    save(
        &gate.root.join(format!("{id}-forwarded.json")),
        &serde_json::to_vec(
            &json!({"method":method,"wire_sha256":hash(&wire),"submitted_at_ns":std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)?.as_nanos()}),
        )?,
    )?;
    let stream = StreamBody::new(futures::stream::iter(
        frames.into_iter().map(Ok::<_, Infallible>),
    ));
    let request = Request::from_parts(parts, tonic::body::Body::new(stream));
    // Channel retains its original physical origin and TLS peer authentication.
    let response = upstream.oneshot(request).await?;
    let (parts, body) = response.into_parts();
    if parts
        .headers
        .get("grpc-status")
        .is_some_and(|value| value.as_bytes() != b"0")
    {
        gate.failed.store(true, Ordering::Release);
    }
    gate.capture(id,"response",0,"headers",&serde_json::to_vec(&json!({"http_status":parts.status.as_u16(),"http_version":format!("{:?}",parts.version),"headers_hex":headers(&parts.headers).iter().map(|b|format!("{b:02x}")).collect::<String>()}))?)?;
    Ok(Response::from_parts(
        parts,
        tonic::body::Body::new(CapturedBody {
            inner: body,
            gate,
            id,
            sequence: 1,
        }),
    ))
}

pub struct ClientTransport {
    pub endpoint: String,
    task: JoinHandle<()>,
    gate: Arc<Gate>,
}
impl Drop for ClientTransport {
    fn drop(&mut self) {
        let _=save(&self.gate.root.join("client-transport-dropped.json"),&serde_json::to_vec(&json!({"action_id":self.gate.plan.action_id,"process_signing_session":"ended","restart_continuation":false})).unwrap_or_default());
        self.task.abort();
    }
}
impl ClientTransport {
    /// Caller passes a Channel whose physical endpoint and TLS roots were
    /// checked against the manifest. Only this invocation's Config clone gets
    /// endpoint; never save it to the wallet config or publish it globally.
    pub async fn start(upstream: Channel, gate: Arc<Gate>) -> Result<Self> {
        let mut identity =
            server_rpc::protos::ark_service_client::ArkServiceClient::new(upstream.clone());
        let info = identity
            .get_ark_info(server_rpc::protos::Empty {})
            .await?
            .into_inner();
        ensure!(
            info.network == "signet"
                && info
                    .server_pubkey
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<String>()
                    == gate.plan.expected_server_pubkey,
            "physical upstream network/server identity differs"
        );
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let endpoint = format!("http://{}", listener.local_addr()?);
        let task_gate = gate.clone();
        let task = tokio::spawn(async move {
            let gate = task_gate;
            // A second SDK connection is deliberately unsupported: reconnects
            // cannot restart the signing session or erase its request fence.
            match listener.accept().await {
                Ok((socket, _)) => {
                    let terminal_gate = gate.clone();
                    let service = service_fn(move |request| {
                        let upstream = upstream.clone();
                        let gate = gate.clone();
                        async move {
                            Ok::<_, Infallible>(
                                match proxy(upstream, gate.clone(), request).await {
                                    Ok(response) => response,
                                    Err(error) => {
                                        gate.failed.store(true, Ordering::Release);
                                        let _=save(&gate.root.join(format!("transport-gap-{}.json",gate.next.fetch_add(1,Ordering::Relaxed))),&serde_json::to_vec(&json!({"error":format!("{error:#}"),"financial_outcome":"unknown","source":"client_capture_guard"})).unwrap_or_default());
                                        client_refusal()
                                    }
                                },
                            )
                        }
                    });
                    let result = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                        .max_concurrent_streams(4)
                        .serve_connection(TokioIo::new(socket), service)
                        .await;
                    if result.is_err() {
                        terminal_gate.failed.store(true, Ordering::Release);
                    }
                    let _=save(&terminal_gate.root.join("connection-end.json"),&serde_json::to_vec(&json!({"error":result.err().map(|error|error.to_string()),"financial_outcome":"not inferred from connection termination"})).unwrap_or_default());
                }
                Err(error) => {
                    let _ = save(
                        &gate.root.join("accept-gap.json"),
                        &serde_json::to_vec(
                            &json!({"error":error.to_string(),"financial_outcome":"unknown"}),
                        )
                        .unwrap_or_default(),
                    );
                }
            }
        });
        Ok(Self {
            endpoint,
            task,
            gate,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "grpc-capture-unit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ))
    }
    fn plan() -> Plan {
        Plan {
            actor: "actor-11".into(),
            action_id: "unit-invocation".into(),
            intent_sha256: "a1".repeat(32),
            manifest_sha256: "b1".repeat(32),
            expected_server_pubkey: "02".to_string() + &"c1".repeat(32),
            service_prefix: "/bark_server.ArkService/".into(),
            rpc_limits: HashMap::from([("SubmitPayment".into(), 1)]),
            barrier_rpc: "SubmitPayment".into(),
            barrier_requests: 1,
        }
    }
    #[test]
    fn second_submit_and_reopened_private_invocation_never_forward() {
        let directory = root();
        let gate = Gate::create(
            plan(),
            directory.clone(),
            Arc::new(|_, _| Ok(json!({"unit_capture_only":true}))),
        )
        .unwrap();
        assert!(gate.admit("SubmitPayment", b"first-exact-request").is_ok());
        assert!(
            gate.admit("SubmitPayment", b"second-distinct-request")
                .is_err()
        );
        assert!(Gate::create(plan(), directory.clone(), Arc::new(|_, _| Ok(Value::Null))).is_err());
        let mut unsafe_plan = plan();
        unsafe_plan.actor = "actor-09".into();
        assert!(Gate::create(unsafe_plan, root(), Arc::new(|_, _| Ok(Value::Null))).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
    #[tokio::test]
    async fn real_body_frames_and_nonzero_status_trailers_are_preserved() {
        let directory = root();
        let gate =
            Gate::create(plan(), directory.clone(), Arc::new(|_, _| Ok(Value::Null))).unwrap();
        let mut trailers = hyper::HeaderMap::new();
        trailers.insert("grpc-status", hyper::header::HeaderValue::from_static("3"));
        trailers.append(
            "grpc-message",
            hyper::header::HeaderValue::from_static("actual%20node%20refusal"),
        );
        let original = vec![
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"\0\0\0\0\x02ab"))),
            Ok(Frame::data(Bytes::from_static(b"\0\0\0\0\x02cd"))),
            Ok(Frame::trailers(trailers.clone())),
        ];
        let mut body = CapturedBody {
            inner: tonic::body::Body::new(StreamBody::new(futures::stream::iter(original))),
            gate,
            id: 1,
            sequence: 1,
        };
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"\0\0\0\0\x02ab")
        );
        assert_eq!(
            body.frame().await.unwrap().unwrap().into_data().unwrap(),
            Bytes::from_static(b"\0\0\0\0\x02cd")
        );
        assert_eq!(
            body.frame()
                .await
                .unwrap()
                .unwrap()
                .into_trailers()
                .unwrap(),
            trailers
        );
        assert!(body.frame().await.is_none());
        assert_eq!(
            fs::read(directory.join("1-response-1-data.bin")).unwrap(),
            b"\0\0\0\0\x02ab"
        );
        assert_eq!(
            fs::read(directory.join("1-response-3-trailers.bin")).unwrap(),
            headers(&trailers)
        );
        fs::remove_dir_all(directory).unwrap();
    }
    #[tokio::test]
    async fn capture_failure_stops_frame_delivery_and_cannot_be_a_node_refusal() {
        let directory = root();
        let gate =
            Gate::create(plan(), directory.clone(), Arc::new(|_, _| Ok(Value::Null))).unwrap();
        fs::remove_dir_all(&directory).unwrap();
        let mut body = CapturedBody {
            inner: tonic::body::Body::new(StreamBody::new(futures::stream::iter(vec![Ok::<
                _,
                Infallible,
            >(
                Frame::data(Bytes::from_static(b"uncaptured")),
            )]))),
            gate,
            id: 1,
            sequence: 1,
        };
        let error = body.frame().await.unwrap().unwrap_err();
        assert_eq!(error.code(), tonic::Code::Internal);
        assert!(!server_rpc::StatusExt::is_expiry_settled(&error));
    }
}
