use std::env;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use sha2::{Digest, Sha256};
use smartcard_apdu::{CommandApdu, ResponseApdu, bytes_to_hex, hex_to_bytes};
use smartcard_core::{RuntimeConfig, SmartcardRuntime};
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

    match command {
        CliCommand::Readers => {
            let readers = runtime.list_readers().map_err(|error| error.to_string())?;
            if readers.is_empty() {
                println!("No PC/SC readers found.");
            } else {
                for reader in readers {
                    println!("{}", reader.name);
                }
            }
        }
        CliCommand::Atr { reader, timeout } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let snapshot = worker.snapshot();
            match snapshot.atr {
                Some(atr) => println!("{}", bytes_to_hex(&atr)),
                None => println!("(no ATR reported by the reader)"),
            }
        }
        CliCommand::Apdu {
            reader,
            command,
            timeout,
        } => {
            let apdu = CommandApdu::from_hex(&command).map_err(|error| error.to_string())?;
            let worker = open_worker(&runtime, reader, timeout)?;
            let response = runtime
                .exchange(apdu, |command| worker.transmit(command))
                .map_err(|error| error.to_string())?;
            print_response(&response);
        }
        CliCommand::PivSelect { reader, timeout } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let response = runtime
                .exchange(select_piv_application(), |command| worker.transmit(command))
                .map_err(|error| error.to_string())?;
            print_response(&response);
            let parsed =
                parse_select_response(&response.data).map_err(|error| error.to_string())?;
            print_piv_select_response(&parsed);
        }
        CliCommand::PivCerts { reader, timeout } => {
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
        CliCommand::PivVerifyPin {
            reader,
            pin,
            timeout,
        } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            ensure_piv_selected(&runtime, &worker)?;
            verify_pin(&runtime, &worker, &pin)?;
            println!("PIN verified");
        }
        CliCommand::PivSign {
            reader,
            slot,
            pin,
            hash_hex,
            timeout,
        } => {
            let worker = open_worker(&runtime, reader, timeout)?;
            let digest = hex_to_bytes(&hash_hex).map_err(|error| error.to_string())?;
            let (_, signature) = sign_digest(&runtime, &worker, slot, &pin, &digest)?;

            println!("slot: {}", slot.key_reference_hex());
            println!("signature: {}", bytes_to_hex(&signature));
        }
        CliCommand::PivSignVerify {
            reader,
            slot,
            pin,
            hash_hex,
            timeout,
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
            reader,
            slot,
            pin,
            file,
            timeout,
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
            reader: reader.ok_or_else(|| "atr requires --reader".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "apdu" => Ok(CliCommand::Apdu {
            reader: reader.ok_or_else(|| "apdu requires --reader".to_owned())?,
            command: apdu.ok_or_else(|| "apdu requires --command".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-select" => Ok(CliCommand::PivSelect {
            reader: reader.ok_or_else(|| "piv-select requires --reader".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-certs" => Ok(CliCommand::PivCerts {
            reader: reader.ok_or_else(|| "piv-certs requires --reader".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-verify-pin" => Ok(CliCommand::PivVerifyPin {
            reader: reader.ok_or_else(|| "piv-verify-pin requires --reader".to_owned())?,
            pin: resolve_pin(pin, pin_env)?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-sign" => Ok(CliCommand::PivSign {
            reader: reader.ok_or_else(|| "piv-sign requires --reader".to_owned())?,
            slot: slot.ok_or_else(|| "piv-sign requires --slot".to_owned())?,
            pin: resolve_pin(pin, pin_env)?,
            hash_hex: hash_hex.ok_or_else(|| "piv-sign requires --hash-hex".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-sign-verify" => Ok(CliCommand::PivSignVerify {
            reader: reader.ok_or_else(|| "piv-sign-verify requires --reader".to_owned())?,
            slot: slot.ok_or_else(|| "piv-sign-verify requires --slot".to_owned())?,
            pin: resolve_pin(pin, pin_env)?,
            hash_hex: hash_hex.ok_or_else(|| "piv-sign-verify requires --hash-hex".to_owned())?,
            timeout: timeout_ms.unwrap_or(Duration::from_millis(1_500)),
        }),
        "piv-sign-file" => Ok(CliCommand::PivSignFile {
            reader: reader.ok_or_else(|| "piv-sign-file requires --reader".to_owned())?,
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
    println!("smartcard-cli atr --reader <name> [--timeout-ms <ms>]");
    println!("smartcard-cli apdu --reader <name> --command <hex> [--timeout-ms <ms>]");
    println!("smartcard-cli piv-select --reader <name> [--timeout-ms <ms>]");
    println!("smartcard-cli piv-certs --reader <name> [--timeout-ms <ms>]");
    println!(
        "smartcard-cli piv-verify-pin --reader <name> (--pin <pin> | --pin-env <env>) [--timeout-ms <ms>]"
    );
    println!(
        "smartcard-cli piv-sign --reader <name> --slot <9A|9C|9D|9E> --hash-hex <sha256> (--pin <pin> | --pin-env <env>) [--timeout-ms <ms>]"
    );
    println!(
        "smartcard-cli piv-sign-verify --reader <name> --slot <9A|9C|9D|9E> --hash-hex <sha256> (--pin <pin> | --pin-env <env>) [--timeout-ms <ms>]"
    );
    println!(
        "smartcard-cli piv-sign-file --reader <name> --slot <9A|9C|9D|9E> --file <path> (--pin <pin> | --pin-env <env>) [--timeout-ms <ms>]"
    );
}

enum CliCommand {
    Readers,
    Atr {
        reader: String,
        timeout: Duration,
    },
    Apdu {
        reader: String,
        command: String,
        timeout: Duration,
    },
    PivSelect {
        reader: String,
        timeout: Duration,
    },
    PivCerts {
        reader: String,
        timeout: Duration,
    },
    PivVerifyPin {
        reader: String,
        pin: String,
        timeout: Duration,
    },
    PivSign {
        reader: String,
        slot: CertificateSlot,
        pin: String,
        hash_hex: String,
        timeout: Duration,
    },
    PivSignVerify {
        reader: String,
        slot: CertificateSlot,
        pin: String,
        hash_hex: String,
        timeout: Duration,
    },
    PivSignFile {
        reader: String,
        slot: CertificateSlot,
        pin: String,
        file: PathBuf,
        timeout: Duration,
    },
}
