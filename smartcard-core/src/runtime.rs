use std::sync::Arc;
use std::time::Duration;

use smartcard_apdu::{CommandApdu, ResponseApdu};

use crate::{CardSession, ReaderInfo, Result, SharedTransport, SmartcardError, Transport};

#[derive(Clone, Debug)]
pub struct RuntimeConfig {
    pub connect_timeout: Duration,
    pub command_timeout: Duration,
    pub slow_call_threshold: Duration,
    pub max_follow_up_commands: usize,
    pub max_response_bytes: usize,
}

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_millis(1_500),
            command_timeout: Duration::from_millis(1_500),
            slow_call_threshold: Duration::from_millis(250),
            max_follow_up_commands: 8,
            max_response_bytes: 16 * 1024,
        }
    }
}

pub struct SmartcardRuntime {
    transport: SharedTransport,
    config: RuntimeConfig,
}

impl SmartcardRuntime {
    pub fn new<T>(transport: T, config: RuntimeConfig) -> Self
    where
        T: Transport + 'static,
    {
        Self {
            transport: Arc::new(transport),
            config,
        }
    }

    pub fn from_shared(transport: SharedTransport, config: RuntimeConfig) -> Self {
        Self { transport, config }
    }

    pub fn list_readers(&self) -> Result<Vec<ReaderInfo>> {
        self.transport.list_readers()
    }

    pub fn exchange<F>(&self, command: CommandApdu, mut transmit: F) -> Result<ResponseApdu>
    where
        F: FnMut(CommandApdu) -> Result<ResponseApdu>,
    {
        let mut current = command;
        let mut response_data = Vec::new();
        let mut follow_up_count = 0usize;
        let mut retried_length = false;

        loop {
            let response = transmit(current.clone())?;

            match response.sw1 {
                0x61 => {
                    self.extend_response_data(&mut response_data, &response.data)?;
                    follow_up_count += 1;
                    if follow_up_count > self.config.max_follow_up_commands {
                        return Err(SmartcardError::protocol(format!(
                            "too many follow-up APDUs while reading response"
                        )));
                    }

                    current = CommandApdu::new(
                        current.cla,
                        0xC0,
                        0x00,
                        0x00,
                        Vec::new(),
                        Some(response.sw2),
                    );
                    retried_length = false;
                }
                0x6C => {
                    follow_up_count += 1;
                    if follow_up_count > self.config.max_follow_up_commands {
                        return Err(SmartcardError::protocol(format!(
                            "too many follow-up APDUs while retrying corrected length"
                        )));
                    }

                    if retried_length {
                        return Err(SmartcardError::protocol(format!(
                            "card requested corrected Le more than once for the same command"
                        )));
                    }

                    current.le = Some(response.sw2);
                    retried_length = true;
                }
                _ => {
                    self.extend_response_data(&mut response_data, &response.data)?;
                    return Ok(ResponseApdu {
                        data: response_data,
                        sw1: response.sw1,
                        sw2: response.sw2,
                    });
                }
            }
        }
    }

    pub fn exchange_session(
        &self,
        session: &mut dyn CardSession,
        command: CommandApdu,
    ) -> Result<ResponseApdu> {
        self.exchange(command, |command| session.transmit(&command))
    }

    pub fn transport(&self) -> SharedTransport {
        Arc::clone(&self.transport)
    }

    pub fn config(&self) -> &RuntimeConfig {
        &self.config
    }

    fn extend_response_data(&self, destination: &mut Vec<u8>, chunk: &[u8]) -> Result<()> {
        if destination.len() + chunk.len() > self.config.max_response_bytes {
            return Err(SmartcardError::protocol(format!(
                "response exceeded {} bytes",
                self.config.max_response_bytes
            )));
        }

        destination.extend_from_slice(chunk);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{RuntimeConfig, SmartcardRuntime};
    use crate::{ReaderInfo, Result, SmartcardError, Transport};
    use smartcard_apdu::{CommandApdu, ResponseApdu};
    use std::collections::VecDeque;

    struct NoopTransport;

    impl Transport for NoopTransport {
        fn list_readers(&self) -> Result<Vec<ReaderInfo>> {
            Ok(Vec::new())
        }

        fn connect(&self, _reader: &str) -> Result<Box<dyn crate::CardSession>> {
            Err(SmartcardError::not_found("no test session"))
        }
    }

    #[test]
    fn exchange_returns_single_response() {
        let runtime = SmartcardRuntime::new(NoopTransport, RuntimeConfig::default());
        let command = CommandApdu::new(0x00, 0x84, 0x00, 0x00, Vec::new(), Some(0x08));
        let mut sent = Vec::new();

        let response = runtime
            .exchange(command, |command| {
                sent.push(command.encode().unwrap());
                Ok(ResponseApdu {
                    data: vec![1, 2, 3],
                    sw1: 0x90,
                    sw2: 0x00,
                })
            })
            .expect("single APDU exchange should succeed");

        assert_eq!(sent, vec![vec![0x00, 0x84, 0x00, 0x00, 0x08]]);
        assert_eq!(response.data, vec![1, 2, 3]);
        assert_eq!(response.status_word(), 0x9000);
    }

    #[test]
    fn exchange_chases_get_response_until_complete() {
        let runtime = SmartcardRuntime::new(NoopTransport, RuntimeConfig::default());
        let command = CommandApdu::new(0x00, 0xA4, 0x04, 0x00, vec![0xA0, 0x00, 0x00], Some(0x00));
        let mut sent = Vec::new();
        let mut responses = VecDeque::from([
            ResponseApdu {
                data: vec![0x61, 0x4F],
                sw1: 0x61,
                sw2: 0x03,
            },
            ResponseApdu {
                data: vec![0x01, 0x02, 0x03],
                sw1: 0x90,
                sw2: 0x00,
            },
        ]);

        let response = runtime
            .exchange(command, |command| {
                sent.push(command.encode().unwrap());
                Ok(responses
                    .pop_front()
                    .expect("response queue should not be empty"))
            })
            .expect("GET RESPONSE exchange should succeed");

        assert_eq!(
            sent,
            vec![
                vec![0x00, 0xA4, 0x04, 0x00, 0x03, 0xA0, 0x00, 0x00, 0x00],
                vec![0x00, 0xC0, 0x00, 0x00, 0x03],
            ]
        );
        assert_eq!(response.data, vec![0x61, 0x4F, 0x01, 0x02, 0x03]);
        assert_eq!(response.status_word(), 0x9000);
    }

    #[test]
    fn exchange_retries_with_corrected_length() {
        let runtime = SmartcardRuntime::new(NoopTransport, RuntimeConfig::default());
        let command = CommandApdu::new(0x00, 0xCB, 0x3F, 0xFF, vec![0x5C, 0x03], Some(0x00));
        let mut sent = Vec::new();
        let mut responses = VecDeque::from([
            ResponseApdu {
                data: Vec::new(),
                sw1: 0x6C,
                sw2: 0x10,
            },
            ResponseApdu {
                data: vec![0x53, 0x03, 0xAA],
                sw1: 0x90,
                sw2: 0x00,
            },
        ]);

        let response = runtime
            .exchange(command, |command| {
                sent.push(command.encode().unwrap());
                Ok(responses
                    .pop_front()
                    .expect("response queue should not be empty"))
            })
            .expect("length-corrected retry should succeed");

        assert_eq!(
            sent,
            vec![
                vec![0x00, 0xCB, 0x3F, 0xFF, 0x02, 0x5C, 0x03, 0x00],
                vec![0x00, 0xCB, 0x3F, 0xFF, 0x02, 0x5C, 0x03, 0x10],
            ]
        );
        assert_eq!(response.data, vec![0x53, 0x03, 0xAA]);
        assert_eq!(response.status_word(), 0x9000);
    }

    #[test]
    fn exchange_fails_when_follow_up_limit_is_exceeded() {
        let config = RuntimeConfig {
            max_follow_up_commands: 1,
            ..RuntimeConfig::default()
        };
        let runtime = SmartcardRuntime::new(NoopTransport, config);
        let command = CommandApdu::new(0x00, 0xCA, 0x00, 0x00, Vec::new(), Some(0x00));
        let mut responses = VecDeque::from([
            ResponseApdu {
                data: vec![0x01],
                sw1: 0x61,
                sw2: 0x01,
            },
            ResponseApdu {
                data: vec![0x02],
                sw1: 0x61,
                sw2: 0x01,
            },
        ]);

        let error = runtime
            .exchange(command, |_command| {
                Ok(responses
                    .pop_front()
                    .expect("response queue should not be empty"))
            })
            .expect_err("exchange should fail after too many follow-ups");

        assert!(
            matches!(error, SmartcardError::Protocol(message) if message.contains("too many follow-up APDUs"))
        );
    }

    #[test]
    fn exchange_fails_when_response_is_too_large() {
        let config = RuntimeConfig {
            max_response_bytes: 3,
            ..RuntimeConfig::default()
        };
        let runtime = SmartcardRuntime::new(NoopTransport, config);
        let command = CommandApdu::new(0x00, 0xCA, 0x00, 0x00, Vec::new(), Some(0x00));
        let mut responses = VecDeque::from([
            ResponseApdu {
                data: vec![0x01, 0x02],
                sw1: 0x61,
                sw2: 0x02,
            },
            ResponseApdu {
                data: vec![0x03, 0x04],
                sw1: 0x90,
                sw2: 0x00,
            },
        ]);

        let error = runtime
            .exchange(command, |_command| {
                Ok(responses
                    .pop_front()
                    .expect("response queue should not be empty"))
            })
            .expect_err("exchange should fail when response grows too large");

        assert!(
            matches!(error, SmartcardError::Protocol(message) if message.contains("response exceeded 3 bytes"))
        );
    }
}
