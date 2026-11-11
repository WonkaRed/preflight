//! Shared by the deployed-contract tests: recorded RPC responses, an in-process replay [`Transport`], and a
//! loopback HTTP server that serves them, so the real HTTP client is exercised without touching the network.

// Each test binary compiles this module and uses a different part of it; without this, every binary would warn
// about the helpers the other one uses.
#![allow(dead_code)]

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::Duration;

use preflight::deployed::{Transport, TransportError};
use serde_json::Value;

/// Recorded responses of one run, by request kind: the `request_type` of a `query`, or the method name of any
/// other call. Files in `tests/data/` hold real responses from a public mainnet RPC node, untrimmed.
#[derive(Clone)]
pub struct Fixture {
    responses: BTreeMap<String, Value>,
}

fn data(name: &str) -> Value {
    let path = format!("{}/tests/data/{name}.json", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))).unwrap()
}

impl Fixture {
    /// The recorded run for a contract, such as `no-keys.example`.
    pub fn account(name: &str) -> Self {
        let doc = data(name);
        let responses = doc["responses"].as_object().unwrap().iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        Self { responses }
    }

    pub fn with(mut self, kind: &str, response: Value) -> Self {
        self.responses.insert(kind.to_owned(), response);
        self
    }

    pub fn without(mut self, kind: &str) -> Self {
        self.responses.remove(kind);
        self
    }

    pub fn response(&self, kind: &str) -> &Value {
        &self.responses[kind]
    }

    /// Edits the `result` of a recorded response in place.
    pub fn edit(mut self, kind: &str, edit: impl FnOnce(&mut Value)) -> Self {
        edit(self.responses.get_mut(kind).unwrap_or_else(|| panic!("no recorded {kind}")));
        self
    }

    fn answer(&self, request: &str) -> Result<String, String> {
        let request: Value = serde_json::from_str(request).map_err(|e| format!("request is not JSON: {e}"))?;
        let kind = kind_of(&request);
        let response = self.responses.get(&kind).ok_or_else(|| format!("no recorded response for {kind}"))?;
        Ok(response.to_string())
    }
}

/// A real node response that was recorded for a failure case, by name (see `tests/data/errors.json`).
pub fn recorded_error(name: &str) -> Value {
    data("errors")["responses"][name].clone()
}

/// The kind a request is answered under. A `view_state` for the empty prefix, which asks whether the account
/// stores anything at all, is `view_state_any`; one for the `STATE` key is `view_state`.
pub fn kind_of(request: &Value) -> String {
    let method = request["method"].as_str().unwrap_or_default();
    let params = &request["params"];
    match (method, params["request_type"].as_str().unwrap_or_default()) {
        ("query", "view_state") if params["prefix_base64"] == "" => "view_state_any".to_owned(),
        ("query", request_type) => request_type.to_owned(),
        (other, _) => other.to_owned(),
    }
}

/// Answers from a [`Fixture`] and remembers every request it was sent.
pub struct Replay {
    fixture: Fixture,
    requests: RefCell<Vec<Value>>,
}

impl Replay {
    pub fn new(fixture: Fixture) -> Self {
        Self { fixture, requests: RefCell::new(Vec::new()) }
    }

    pub fn requests(&self) -> Vec<Value> {
        self.requests.borrow().clone()
    }
}

impl Transport for Replay {
    fn post(&self, request: &str, max_bytes: usize) -> Result<Vec<u8>, TransportError> {
        self.requests.borrow_mut().push(serde_json::from_str(request).expect("the client sends JSON"));
        let body = self.fixture.answer(request).map_err(TransportError::Network)?;
        if body.len() > max_bytes {
            return Err(TransportError::TooLarge { limit: max_bytes });
        }
        Ok(body.into_bytes())
    }

    fn endpoint(&self) -> &str {
        "replay://recorded"
    }
}

/// What the loopback server does with one request.
pub enum Reply {
    /// HTTP 200 with this body.
    Body(String),
    Status(u16, String),
    /// Waits this long, then answers like [`Reply::Body`].
    Slow(Duration, String),
    /// HTTP 200 announcing and sending this many bytes of `x`.
    Huge(usize),
    /// Closes the connection without answering.
    Hangup,
}

pub struct Server {
    pub url: String,
    pub requests: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Server {
    pub fn start(handler: impl Fn(&str) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (counter, flag, handler) = (requests.clone(), stop.clone(), Arc::new(handler));
        thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let (counter, handler) = (counter.clone(), handler.clone());
                        thread::spawn(move || serve(stream, &*handler, &counter));
                    }
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self { url, requests, stop }
    }

    /// Serves a recorded run over HTTP.
    pub fn replaying(fixture: Fixture) -> Self {
        Self::start(move |body| match fixture.answer(body) {
            Ok(response) => Reply::Body(response),
            Err(why) => Reply::Status(500, why),
        })
    }

    /// Serves a recorded run over HTTP, each answer taking `delay`.
    pub fn replaying_slowly(fixture: Fixture, delay: Duration) -> Self {
        Self::start(move |body| match fixture.answer(body) {
            Ok(response) => Reply::Slow(delay, response),
            Err(why) => Reply::Status(500, why),
        })
    }

    pub fn request_count(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn serve(mut stream: TcpStream, handler: &dyn Fn(&str) -> Reply, counter: &AtomicUsize) {
    stream.set_nonblocking(false).unwrap();
    let Some(body) = read_request(&mut stream) else { return };
    counter.fetch_add(1, Ordering::SeqCst);
    let write = |stream: &mut TcpStream, status: &str, len: usize| {
        write!(
            stream,
            "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {len}\r\nconnection: close\r\n\r\n"
        )
    };
    let _ = match handler(&body) {
        Reply::Body(text) => write(&mut stream, "200 OK", text.len()).and_then(|()| stream.write_all(text.as_bytes())),
        Reply::Status(code, text) => {
            write(&mut stream, &format!("{code} Error"), text.len()).and_then(|()| stream.write_all(text.as_bytes()))
        }
        Reply::Slow(delay, text) => {
            thread::sleep(delay);
            write(&mut stream, "200 OK", text.len()).and_then(|()| stream.write_all(text.as_bytes()))
        }
        Reply::Huge(len) => write(&mut stream, "200 OK", len).and_then(|()| {
            let chunk = [b'x'; 8192];
            let mut left = len;
            while left > 0 {
                let n = left.min(chunk.len());
                stream.write_all(&chunk[..n])?;
                left -= n;
            }
            Ok(())
        }),
        Reply::Hangup => Ok(()),
    };
}

fn read_request(stream: &mut TcpStream) -> Option<String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    while !buf.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).ok()?;
        buf.push(byte[0]);
    }
    let head = String::from_utf8_lossy(&buf).to_lowercase();
    let length: usize = head.lines().find_map(|line| line.strip_prefix("content-length:"))?.trim().parse().ok()?;
    let mut body = vec![0; length];
    stream.read_exact(&mut body).ok()?;
    Some(String::from_utf8_lossy(&body).into_owned())
}
