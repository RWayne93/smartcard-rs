use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use sha2::{Digest, Sha256};
use smartcard_apdu::{CommandApdu, ResponseApdu, bytes_to_hex, hex_to_bytes};
use smartcard_core::{ReaderInfo, RuntimeConfig, SmartcardRuntime};
use smartcard_pcsc::PcscTransport;
use smartcard_piv::{
    CertificateObject, CertificateSlot, PRIMARY_CERTIFICATE_SLOTS, SelectResponse,
    build_sign_commands, infer_sign_algorithm, parse_certificate_response, parse_select_response,
    parse_sign_response, parse_verify_pin_response, prepare_signing_input_sha256,
    read_certificate_command, select_piv_application, summarize_certificate, verify_pin_command,
    verify_signature_sha256,
};
use smartcard_worker::ReaderWorker;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || matches!(args[0].as_str(), "-h" | "--help" | "help") {
        print_usage();
        return Ok(());
    }

    let command = parse_command(&args)?;
    let transport = PcscTransport::establish_user().map_err(|error| error.to_string())?;
    let runtime = SmartcardRuntime::new(transport, RuntimeConfig::default());

    let readers = runtime.list_readers().map_err(|error| error.to_string())?;
    if matches!(command, CliCommand::Readers) {
        print_reader_list(&readers);
        return Ok(());
    }

    let selection = resolve_reader(&readers, command.reader_hint())?;
    if selection.report {
        eprintln!("Using reader with a card: {}", selection.name);
    }
    let reader = selection.name;

    match command {
        CliCommand::Readers => unreachable!("readers already returned"),
        CliCommand::Atr { timeout, .. } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let snapshot = worker.snapshot();
            match snapshot.atr {
                Some(atr) => println!("{}", bytes_to_hex(&atr)),
                None => println!("(no ATR reported by the reader)"),
            }
        }
        CliCommand::Apdu {
            command, timeout, ..
        } => {
            let apdu = CommandApdu::from_hex(&command).map_err(|error| error.to_string())?;
            let worker = open_worker(&runtime, reader, timeout)?;
            let response = runtime
                .exchange(apdu, |command| worker.transmit(command))
                .map_err(|error| error.to_string())?;
            print_response(&response);
        }
        CliCommand::PivSelect { timeout, .. } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let response = runtime
                .exchange(select_piv_application(), |command| worker.transmit(command))
                .map_err(|error| error.to_string())?;
            print_response(&response);
            let parsed =
                parse_select_response(&response.data).map_err(|error| error.to_string())?;
            print_piv_select_response(&parsed);
        }
        CliCommand::PivCerts { timeout, .. } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let select_response = runtime
                .exchange(select_piv_application(), |command| worker.transmit(command))
                .map_err(|error| error.to_string())?;
            if select_response.status_word() != 0x9000 {
                return Err(format!(
                    "PIV SELECT failed with status {:04X}",
                    select_response.status_word()
                ));
            }

            for slot in PRIMARY_CERTIFICATE_SLOTS {
                let response = runtime
                    .exchange(read_certificate_command(slot), |command| {
                        worker.transmit(command)
                    })
                    .map_err(|error| error.to_string())?;

                match parse_certificate_response(slot, &response)
                    .map_err(|error| error.to_string())?
                {
                    Some(certificate) => print_certificate_summary(&certificate),
                    None => println!("{} {} missing", slot.key_reference_hex(), slot.short_name),
                }
            }
        }
        CliCommand::PivVerifyPin { pin, timeout, .. } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            ensure_piv_selected(&runtime, &worker)?;
            verify_pin(&runtime, &worker, &pin)?;
            println!("PIN verified");
        }
        CliCommand::PivSign {
            slot,
            pin,
            hash_hex,
            timeout,
            ..
        } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let digest = hex_to_bytes(&hash_hex).map_err(|error| error.to_string())?;
            let (_, signature) = sign_digest(&runtime, &worker, slot, &pin, &digest)?;

            println!("slot: {}", slot.key_reference_hex());
            println!("signature: {}", bytes_to_hex(&signature));
        }
        CliCommand::PivSignVerify {
            slot,
            pin,
            hash_hex,
            timeout,
            ..
        } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let digest = hex_to_bytes(&hash_hex).map_err(|error| error.to_string())?;
            let (certificate, signature) = sign_digest(&runtime, &worker, slot, &pin, &digest)?;
            verify_signature_sha256(&certificate, &digest, &signature)
                .map_err(|error| error.to_string())?;

            println!("slot: {}", slot.key_reference_hex());
            println!("digest: {}", bytes_to_hex(&digest));
            println!("signature: {}", bytes_to_hex(&signature));
            println!("verified: yes");
        }
        CliCommand::PivSignFile {
            slot,
            pin,
            file,
            timeout,
            ..
        } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let digest = sha256_digest_file(&file)?;
            let (certificate, signature) = sign_digest(&runtime, &worker, slot, &pin, &digest)?;
            verify_signature_sha256(&certificate, &digest, &signature)
                .map_err(|error| error.to_string())?;

            println!("file: {}", file.display());
            println!("slot: {}", slot.key_reference_hex());
            println!("digest: {}", bytes_to_hex(&digest));
            println!("signature: {}", bytes_to_hex(&signature));
            println!("verified: yes");
        }
    }

    Ok(())
}

fn open_worker(
    runtime: &SmartcardRuntime,
    reader: String,
    command_timeout: Duration,
) -> Result<ReaderWorker, String> {
    ReaderWorker::start(
        runtime.transport(),
        reader,
        runtime.config().connect_timeout,
        command_timeout,
        runtime.config().slow_call_threshold,
    )
    .map_err(|error| error.to_string())
}

fn print_reader_list(readers: &[ReaderInfo]) {
    if readers.is_empty() {
        println!("No PC/SC readers found.");
        return;
    }

    for (index, reader) in readers.iter().enumerate() {
        let presence = if reader.card_present { "card" } else { "empty" };
        println!("{index} {presence} {}", reader.name);
    }
}

#[derive(Debug)]
struct ReaderSelection {
    name: String,
    report: bool,
}

fn resolve_reader(readers: &[ReaderInfo], hint: Option<&str>) -> Result<ReaderSelection, String> {
    let Some(hint) = hint else {
        let reader = readers
            .iter()
            .find(|reader| reader.card_present)
            .ok_or_else(|| {
                if readers.is_empty() {
                    "No PC/SC readers found.".to_owned()
                } else {
                    "No card is present.".to_owned()
                }
            })?;
        return Ok(ReaderSelection {
            name: reader.name.clone(),
            report: true,
        });
    };

    if let Some(reader) = readers.iter().find(|reader| reader.name == hint) {
        return Ok(ReaderSelection {
            name: reader.name.clone(),
            report: false,
        });
    }

    if hint.chars().all(|character| character.is_ascii_digit())
        && let Ok(index) = hint.parse::<usize>()
    {
        let reader = readers.get(index).ok_or_else(|| {
            format!(
                "reader index {index} is out of range ({} readers)",
                readers.len()
            )
        })?;
        return Ok(ReaderSelection {
            name: reader.name.clone(),
            report: true,
        });
    }

    let needle = hint.to_ascii_lowercase();
    let matches: Vec<&ReaderInfo> = readers
        .iter()
        .filter(|reader| reader.name.to_ascii_lowercase().contains(&needle))
        .collect();
    match matches.as_slice() {
        [reader] => Ok(ReaderSelection {
            name: reader.name.clone(),
            report: true,
        }),
        [] => Err(format!("reader {hint:?} not found")),
        matches => {
            let mut message = format!("reader {hint:?} matches multiple readers:");
            for reader in matches {
                message.push('\n');
                message.push_str(&reader.name);
            }
            Err(message)
        }
    }
}

fn print_response(response: &ResponseApdu) {
    println!("data: {}", bytes_to_hex(&response.data));
    println!("status: {:04X}", response.status_word());
}

fn print_piv_select_response(response: &SelectResponse) {
    println!("aid: {}", bytes_to_hex(&response.aid));
    if let Some(label) = &response.label {
        println!("label: {label}");
    }

    for aid in &response.coexistent_aids {
        println!("coexistent-aid: {}", bytes_to_hex(aid));
    }
}

fn print_certificate_summary(certificate: &CertificateObject) {
    println!(
        "{} {} object={} cert-bytes={} compressed={}",
        certificate.slot.key_reference_hex(),
        certificate.slot.short_name,
        bytes_to_hex(&certificate.slot.object_id),
        certificate.der.len(),
        if certificate.is_compressed {
            "yes"
        } else {
            "no"
        }
    );

    match summarize_certificate(certificate) {
        Ok(summary) => {
            println!("  subject: {}", summary.subject);
            println!("  issuer: {}", summary.issuer);
            println!("  serial: {}", summary.serial_number);
            println!("  sha256: {}", summary.sha256_fingerprint);
            println!("  not-before: {}", summary.not_before);
            println!("  not-after: {}", summary.not_after);
        }
        Err(error) => println!("  metadata-error: {error}"),
    }
}

fn ensure_piv_selected(runtime: &SmartcardRuntime, worker: &ReaderWorker) -> Result<(), String> {
    let response = runtime
        .exchange(select_piv_application(), |command| worker.transmit(command))
        .map_err(|error| error.to_string())?;
    if response.status_word() != 0x9000 {
        return Err(format!(
            "PIV SELECT failed with status {:04X}",
            response.status_word()
        ));
    }
    Ok(())
}

fn verify_pin(runtime: &SmartcardRuntime, worker: &ReaderWorker, pin: &str) -> Result<(), String> {
    let command = verify_pin_command(pin).map_err(|error| error.to_string())?;
    let response = runtime
        .exchange(command, |command| worker.transmit(command))
        .map_err(|error| error.to_string())?;

    match parse_verify_pin_response(&response).map_err(|error| error.to_string())? {
        smartcard_piv::VerifyPinStatus::Verified => Ok(()),
        smartcard_piv::VerifyPinStatus::Incorrect { tries_remaining } => Err(format!(
            "PIN verification failed; retries remaining: {tries_remaining}"
        )),
        smartcard_piv::VerifyPinStatus::Blocked => Err("PIN is blocked".to_owned()),
    }
}

fn fetch_certificate(
    runtime: &SmartcardRuntime,
    worker: &ReaderWorker,
    slot: CertificateSlot,
) -> Result<CertificateObject, String> {
    let response = runtime
        .exchange(read_certificate_command(slot), |command| {
            worker.transmit(command)
        })
        .map_err(|error| error.to_string())?;

    parse_certificate_response(slot, &response)
        .map_err(|error| error.to_string())?
        .ok_or_else(|| {
            format!(
                "certificate slot {} is not populated",
                slot.key_reference_hex()
            )
        })
}

fn sign_digest(
    runtime: &SmartcardRuntime,
    worker: &ReaderWorker,
    slot: CertificateSlot,
    pin: &str,
    digest: &[u8],
) -> Result<(CertificateObject, Vec<u8>), String> {
    ensure_piv_selected(runtime, worker)?;

    let certificate = fetch_certificate(runtime, worker, slot)?;
    let algorithm = infer_sign_algorithm(&certificate).map_err(|error| error.to_string())?;
    let signing_input =
        prepare_signing_input_sha256(algorithm, digest).map_err(|error| error.to_string())?;
    let commands =
        build_sign_commands(slot, algorithm, &signing_input).map_err(|error| error.to_string())?;

    if commands.is_empty() {
        return Err("sign operation did not produce any APDUs".to_owned());
    }

    verify_pin(runtime, worker, pin)?;

    for command in &commands[..commands.len() - 1] {
        let response = worker
            .transmit(command.clone())
            .map_err(|error| error.to_string())?;
        if response.status_word() != 0x9000 {
            return Err(format!(
                "sign command chain failed with status {:04X}",
                response.status_word()
            ));
        }
    }

    let response = runtime
        .exchange(
            commands.last().expect("commands is not empty").clone(),
            |command| worker.transmit(command),
        )
        .map_err(|error| error.to_string())?;
    let signature = parse_sign_response(&response).map_err(|error| error.to_string())?;

    Ok((certificate, signature))
}

fn sha256_digest_file(path: &Path) -> Result<Vec<u8>, String> {
    let mut file =
        File::open(path).map_err(|error| format!("failed to open {}: {error}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| format!("failed to read {}: {error}", path.display()))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().to_vec())
}

fn parse_command(args: &[String]) -> Result<CliCommand, String> {
    let command = args[0].as_str();
    let mut reader = None;
    let mut apdu = None;
    let mut slot = None;
    let mut pin = None;
    let mut pin_env = None;
    let mut file = None;
    let mut hash_hex = None;
    let mut timeout_ms = None;

    let mut index = 1;
    while index < args.len() {
        match args[index].as_str() {
            "--reader" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--reader requires a value".to_owned())?;
                reader = Some(value.clone());
            }
            "--command" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--command requires a value".to_owned())?;
                apdu = Some(value.clone());
            }
            "--pin" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--pin requires a value".to_owned())?;
                pin = Some(value.clone());
            }
            "--pin-env" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--pin-env requires a value".to_owned())?;
                pin_env = Some(value.clone());
            }
            "--file" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--file requires a value".to_owned())?;
                file = Some(PathBuf::from(value));
            }
            "--slot" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--slot requires a value".to_owned())?;
                slot = Some(parse_slot(value)?);
            }
            "--hash-hex" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--hash-hex requires a value".to_owned())?;
                hash_hex = Some(value.clone());
            }
            "--timeout-ms" => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| "--timeout-ms requires a value".to_owned())?;
                timeout_ms = Some(parse_timeout_ms(value)?);
            }
            flag => return Err(format!("unknown argument: {flag}")),
        }

        index += 1;
    }

    match command {
        "readers" => Ok(CliCommand::Readers),
        "atr" => Ok(CliCommand::Atr {
            reader,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "apdu" => Ok(CliCommand::Apdu {
            reader,
            command: apdu.ok_or_else(|| "apdu requires --command".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-select" => Ok(CliCommand::PivSelect {
            reader,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-certs" => Ok(CliCommand::PivCerts {
            reader,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-verify-pin" => Ok(CliCommand::PivVerifyPin {
            reader,
            pin: resolve_pin(pin, pin_env)?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-sign" => Ok(CliCommand::PivSign {
            reader,
            slot: slot.ok_or_else(|| "piv-sign requires --slot".to_owned())?,
            pin: resolve_pin(pin, pin_env)?,
            hash_hex: hash_hex.ok_or_else(|| "piv-sign requires --hash-hex".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-sign-verify" => Ok(CliCommand::PivSignVerify {
            reader,
            slot: slot.ok_or_else(|| "piv-sign-verify requires --slot".to_owned())?,
            pin: resolve_pin(pin, pin_env)?,
            hash_hex: hash_hex.ok_or_else(|| "piv-sign-verify requires --hash-hex".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-sign-file" => Ok(CliCommand::PivSignFile {
            reader,
            slot: slot.ok_or_else(|| "piv-sign-file requires --slot".to_owned())?,
            pin: resolve_pin(pin, pin_env)?,
            file: file.ok_or_else(|| "piv-sign-file requires --file".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        other => Err(format!("unknown command: {other}")),
    }
}

fn parse_timeout_ms(value: &str) -> Result<Duration, String> {
    let timeout_ms = value
        .parse::<u64>()
        .map_err(|_| format!("invalid timeout: {value}"))?;
    Ok(Duration::from_millis(timeout_ms))
}

fn resolve_pin(pin: Option<String>, pin_env: Option<String>) -> Result<String, String> {
    match (pin, pin_env) {
        (Some(_), Some(_)) => Err("use either --pin or --pin-env, not both".to_owned()),
        (Some(pin), None) => Ok(pin),
        (None, Some(env_var)) => {
            env::var(&env_var).map_err(|_| format!("environment variable {env_var} is not set"))
        }
        (None, None) => Err("this command requires --pin or --pin-env".to_owned()),
    }
}

fn parse_slot(value: &str) -> Result<CertificateSlot, String> {
    let normalized = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
        .unwrap_or(value);
    let key_reference = u8::from_str_radix(normalized, 16)
        .map_err(|_| format!("invalid slot reference: {value}"))?;

    PRIMARY_CERTIFICATE_SLOTS
        .iter()
        .copied()
        .find(|slot| slot.key_reference == key_reference)
        .ok_or_else(|| format!("unsupported slot: {value}"))
}

fn print_usage() {
    println!("smartcard-cli readers");
    println!("smartcard-cli atr [--reader <name>] [--timeout-ms <ms>]");
    println!("smartcard-cli apdu --command <hex> [--reader <name>] [--timeout-ms <ms>]");
    println!("smartcard-cli piv-select [--reader <name>] [--timeout-ms <ms>]");
    println!("smartcard-cli piv-certs [--reader <name>] [--timeout-ms <ms>]");
    println!(
        "smartcard-cli piv-verify-pin (--pin <pin> | --pin-env <env>) [--reader <name>] [--timeout-ms <ms>]"
    );
    println!(
        "smartcard-cli piv-sign --slot <9A|9C|9D|9E> --hash-hex <sha256> (--pin <pin> | --pin-env <env>) [--reader <name>] [--timeout-ms <ms>]"
    );
    println!(
        "smartcard-cli piv-sign-verify --slot <9A|9C|9D|9E> --hash-hex <sha256> (--pin <pin> | --pin-env <env>) [--reader <name>] [--timeout-ms <ms>]"
    );
    println!(
        "smartcard-cli piv-sign-file --slot <9A|9C|9D|9E> --file <path> (--pin <pin> | --pin-env <env>) [--reader <name>] [--timeout-ms <ms>]"
    );
}

enum CliCommand {
    Readers,
    Atr {
        reader: Option<String>,
        timeout: Duration,
    },
    Apdu {
        reader: Option<String>,
        command: String,
        timeout: Duration,
    },
    PivSelect {
        reader: Option<String>,
        timeout: Duration,
    },
    PivCerts {
        reader: Option<String>,
        timeout: Duration,
    },
    PivVerifyPin {
        reader: Option<String>,
        pin: String,
        timeout: Duration,
    },
    PivSign {
        reader: Option<String>,
        slot: CertificateSlot,
        pin: String,
        hash_hex: String,
        timeout: Duration,
    },
    PivSignVerify {
        reader: Option<String>,
        slot: CertificateSlot,
        pin: String,
        hash_hex: String,
        timeout: Duration,
    },
    PivSignFile {
        reader: Option<String>,
        slot: CertificateSlot,
        pin: String,
        file: PathBuf,
        timeout: Duration,
    },
}

impl CliCommand {
    fn reader_hint(&self) -> Option<&str> {
        match self {
            Self::Readers => None,
            Self::Atr { reader, .. }
            | Self::Apdu { reader, .. }
            | Self::PivSelect { reader, .. }
            | Self::PivCerts { reader, .. }
            | Self::PivVerifyPin { reader, .. }
            | Self::PivSign { reader, .. }
            | Self::PivSignVerify { reader, .. }
            | Self::PivSignFile { reader, .. } => reader.as_deref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::resolve_reader;
    use smartcard_core::ReaderInfo;

    fn reader(name: &str, card_present: bool) -> ReaderInfo {
        ReaderInfo::new(name).with_card_present(card_present)
    }

    #[test]
    fn defaults_to_the_first_reader_with_a_card() {
        let readers = vec![
            reader("empty slot", false),
            reader("Broadcom contact", true),
            reader("second card", true),
        ];

        let selection = resolve_reader(&readers, None).unwrap();
        assert_eq!(selection.name, "Broadcom contact");
        assert!(selection.report);
    }

    #[test]
    fn reports_when_no_card_is_present() {
        let readers = vec![reader("empty slot", false)];
        let error = resolve_reader(&readers, None).unwrap_err();
        assert_eq!(error, "No card is present.");
    }

    #[test]
    fn reports_when_no_readers_exist() {
        let error = resolve_reader(&[], None).unwrap_err();
        assert_eq!(error, "No PC/SC readers found.");
    }

    #[test]
    fn matches_an_exact_name_without_announcing_it() {
        let readers = vec![reader("Broadcom contact", true)];
        let selection = resolve_reader(&readers, Some("Broadcom contact")).unwrap();
        assert_eq!(selection.name, "Broadcom contact");
        assert!(!selection.report);
    }

    #[test]
    fn matches_a_unique_substring() {
        let readers = vec![
            reader(
                "Broadcom Corp 58200 [Contacted SmartCard] (0123456789ABCD) 00 00",
                true,
            ),
            reader(
                "Broadcom Corp 58200 [Contactless SmartCard] (0123456789ABCD) 01 00",
                false,
            ),
        ];

        let selection = resolve_reader(&readers, Some("contacted")).unwrap();
        assert!(selection.name.contains("Contacted"));
        assert!(selection.report);
    }

    #[test]
    fn matches_a_reader_index() {
        let readers = vec![reader("first", false), reader("second", true)];
        let selection = resolve_reader(&readers, Some("1")).unwrap();
        assert_eq!(selection.name, "second");
        assert!(selection.report);
    }

    #[test]
    fn rejects_an_ambiguous_substring() {
        let readers = vec![
            reader("Broadcom contact", true),
            reader("Broadcom contactless", false),
        ];
        let error = resolve_reader(&readers, Some("broadcom")).unwrap_err();
        assert!(error.contains("matches multiple readers"));
    }
}
