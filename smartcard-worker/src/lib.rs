use std::sync::mpsc::{self, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use smartcard_apdu::{CommandApdu, ResponseApdu};
use smartcard_core::{ReaderHealth, ReaderInfo, Result, SharedTransport, SmartcardError};

const SESSION_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

pub struct ReaderWorker {
    request_tx: Sender<WorkerRequest>,
    state: Arc<Mutex<ReaderInfo>>,
    command_timeout: Duration,
    slow_call_threshold: Duration,
}

impl ReaderWorker {
    pub fn start(
        transport: SharedTransport,
        reader: impl Into<String>,
        connect_timeout: Duration,
        command_timeout: Duration,
        slow_call_threshold: Duration,
    ) -> Result<Self> {
        let reader = reader.into();
        let state = Arc::new(Mutex::new(
            ReaderInfo::new(reader.clone()).with_health(ReaderHealth::Resetting),
        ));
        let (request_tx, request_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::channel();

        thread::Builder::new()
            .name(format!("smartcard-reader-{reader}"))
            .spawn({
                let state = Arc::clone(&state);
                move || {
                    worker_main(
                        transport,
                        reader,
                        request_rx,
                        ready_tx,
                        state,
                        slow_call_threshold,
                    )
                }
            })
            .map_err(|error| {
                SmartcardError::transport(format!("failed to spawn reader worker: {error}"))
            })?;

        match ready_rx.recv_timeout(connect_timeout) {
            Ok(result) => result?,
            Err(RecvTimeoutError::Timeout) => {
                set_health(&state, ReaderHealth::Unresponsive);
                return Err(SmartcardError::timeout("connect", connect_timeout));
            }
            Err(RecvTimeoutError::Disconnected) => {
                set_health(&state, ReaderHealth::Unresponsive);
                return Err(SmartcardError::WorkerClosed);
            }
        }

        Ok(Self {
            request_tx,
            state,
            command_timeout,
            slow_call_threshold,
        })
    }

    pub fn snapshot(&self) -> ReaderInfo {
        self.state
            .lock()
            .map(|state| state.clone())
            .unwrap_or_else(|_| {
                ReaderInfo::new("poisoned-reader").with_health(ReaderHealth::Unresponsive)
            })
    }

    pub fn transmit(&self, command: CommandApdu) -> Result<ResponseApdu> {
        let (response_tx, response_rx) = mpsc::channel();
        self.request_tx
            .send(WorkerRequest::Transmit {
                command,
                response_tx,
            })
            .map_err(|_| SmartcardError::WorkerClosed)?;

        let started = Instant::now();
        match response_rx.recv_timeout(self.command_timeout) {
            Ok(Ok(response)) => {
                set_health(
                    &self.state,
                    ReaderHealth::from_elapsed(started.elapsed(), self.slow_call_threshold),
                );
                Ok(response)
            }
            Ok(Err(error)) => {
                set_health(&self.state, ReaderHealth::Resetting);
                Err(error)
            }
            Err(RecvTimeoutError::Timeout) => {
                set_health(&self.state, ReaderHealth::Unresponsive);
                Err(SmartcardError::timeout("transmit", self.command_timeout))
            }
            Err(RecvTimeoutError::Disconnected) => {
                set_health(&self.state, ReaderHealth::Unresponsive);
                Err(SmartcardError::WorkerClosed)
            }
        }
    }
}

impl Drop for ReaderWorker {
    fn drop(&mut self) {
        let _ = self.request_tx.send(WorkerRequest::Shutdown);
    }
}

enum WorkerRequest {
    Transmit {
        command: CommandApdu,
        response_tx: Sender<Result<ResponseApdu>>,
    },
    Shutdown,
}

fn worker_main(
    transport: SharedTransport,
    reader: String,
    request_rx: Receiver<WorkerRequest>,
    ready_tx: Sender<Result<()>>,
    state: Arc<Mutex<ReaderInfo>>,
    slow_call_threshold: Duration,
) {
    let started = Instant::now();
    match transport.connect(&reader) {
        Ok(session) => {
            let health = ReaderHealth::from_elapsed(started.elapsed(), slow_call_threshold);
            if let Ok(mut snapshot) = state.lock() {
                snapshot.health = health;
                snapshot.atr = session.atr().map(|atr| atr.to_vec());
            }
            drop(session);
            let _ = ready_tx.send(Ok(()));
        }
        Err(error) => {
            set_health(&state, ReaderHealth::Unresponsive);
            let _ = ready_tx.send(Err(error));
            return;
        }
    }

    let mut session: Option<Box<dyn smartcard_core::CardSession>> = None;

    loop {
        let request = if session.is_some() {
            match request_rx.recv_timeout(SESSION_IDLE_TIMEOUT) {
                Ok(req) => req,
                Err(RecvTimeoutError::Timeout) => {
                    session = None;
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => break,
            }
        } else {
            match request_rx.recv() {
                Ok(req) => req,
                Err(_) => break,
            }
        };

        match request {
            WorkerRequest::Transmit {
                command,
                response_tx,
            } => {
                if session.is_none() {
                    session = transport.connect(&reader).ok();
                }
                let result = match session.as_mut() {
                    Some(s) => s.transmit(&command),
                    None => Err(SmartcardError::transport("failed to connect to card")),
                };
                if result.is_err() {
                    session = None;
                }
                let _ = response_tx.send(result);
            }
            WorkerRequest::Shutdown => break,
        }
    }
}

fn set_health(state: &Arc<Mutex<ReaderInfo>>, health: ReaderHealth) {
    if let Ok(mut snapshot) = state.lock() {
        snapshot.health = health;
    }
}
