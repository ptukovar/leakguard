//! `leakguard` CLI -- redact secrets & PII from stdin (or files) and write to stdout.
//!
//! Examples:
//!   tail -f app.log | leakguard
//!   leakguard access.log > clean.log
//!   leakguard --mask char --only email,ipv4 < input.txt
//!   leakguard --without phone app.log
//!   cat data.txt | leakguard --check --verbose   # exit 1 and report kinds found

use std::io::{self, BufRead, BufReader, BufWriter, Write};
use std::process::ExitCode;

use leakguard::{Kind, Mask, Redactor};

const HELP: &str = "\
leakguard -- redact secrets & PII from text

USAGE:
    leakguard [OPTIONS] [FILES...]

    Reads from the given files (or stdin if none) and writes redacted text to
    stdout. Line endings are preserved; multiline PEM private keys are redacted
    as a single block.

OPTIONS:
    --mask <MODE>     label (default) | fixed | char | partial | hash
    --fixed <STR>     replacement string for --mask fixed (default: [REDACTED])
    --char <C>        fill char for char/partial masks (default: *)
    --keep <N>        characters to keep for --mask partial (default: 4)
    --only <LIST>     comma-separated kinds to detect (e.g. email,ipv4,jwt)
    --without <LIST>  comma-separated kinds to skip from the selected detectors
    --format <FMT>    output format: text (default) or json
    --json            shortcut for --format json
    --check           don't print; exit 1 if any sensitive data is found
    -v, --verbose     with --check, print matched kinds and offsets to stderr
    --list-kinds      print supported kind names, then exit
    -h, --help        print this help
    -V, --version     print version

KINDS:
    email, credit_card, ipv4, ipv6, jwt, us_ssn, mac, aws_access_key,
    url_credentials, phone, github_token, slack_token, stripe_key,
    google_api_key, openai_key, private_key, iban, azure_connection_string,
    telegram_token, discord_token
";

const KIND_NAMES: &[&str] = &[
    "email",
    "credit_card",
    "ipv4",
    "ipv6",
    "jwt",
    "us_ssn",
    "mac",
    "aws_access_key",
    "url_credentials",
    "phone",
    "github_token",
    "slack_token",
    "stripe_key",
    "google_api_key",
    "openai_key",
    "private_key",
    "iban",
    "azure_connection_string",
    "telegram_token",
    "discord_token",
];

fn parse_kind(s: &str) -> Option<Kind> {
    Some(match s.trim().to_ascii_lowercase().as_str() {
        "email" => Kind::Email,
        "credit_card" | "creditcard" | "cc" => Kind::CreditCard,
        "ipv4" | "ip" => Kind::IpV4,
        "ipv6" => Kind::IpV6,
        "jwt" => Kind::Jwt,
        "us_ssn" | "ssn" => Kind::UsSsn,
        "mac" => Kind::MacAddress,
        "aws_access_key" | "aws" => Kind::AwsAccessKey,
        "url_credentials" | "url" => Kind::UrlCredentials,
        "phone" => Kind::PhoneNumber,
        "github_token" | "github" | "gh" => Kind::GitHubToken,
        "slack_token" | "slack" => Kind::SlackToken,
        "stripe_key" | "stripe" => Kind::StripeKey,
        "google_api_key" | "google" | "gcp" => Kind::GoogleApiKey,
        "openai_key" | "openai" => Kind::OpenAiKey,
        "private_key" | "pem" => Kind::PrivateKey,
        "iban" => Kind::Iban,
        "azure_connection_string" | "azure" => Kind::AzureConnectionString,
        "telegram_token" | "telegram" | "tg" => Kind::TelegramToken,
        "discord_token" | "discord" => Kind::DiscordToken,
        _ => return None,
    })
}

fn parse_kind_list(value: &str, flag: &str) -> io::Result<Vec<Kind>> {
    let mut kinds = Vec::new();
    for part in value.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match parse_kind(part) {
            Some(k) => kinds.push(k),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown kind for {flag}: {part}"),
                ))
            }
        }
    }
    Ok(kinds)
}

fn print_kinds() {
    for kind in KIND_NAMES {
        println!("{kind}");
    }
}

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("leakguard: {e}");
            ExitCode::from(2)
        }
    }
}

fn run() -> io::Result<ExitCode> {
    let mut args = std::env::args().skip(1).peekable();

    let mut mask_mode = String::from("label");
    let mut fixed = String::from("[REDACTED]");
    let mut fill = '*';
    let mut keep = 4usize;
    let mut format = String::from("text");
    let mut only: Vec<Kind> = Vec::new();
    let mut without: Vec<Kind> = Vec::new();
    let mut check = false;
    let mut verbose = false;
    let mut files: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(ExitCode::SUCCESS);
            }
            "-V" | "--version" => {
                println!("leakguard {}", env!("CARGO_PKG_VERSION"));
                return Ok(ExitCode::SUCCESS);
            }
            "--list-kinds" => {
                print_kinds();
                return Ok(ExitCode::SUCCESS);
            }
            "--mask" => mask_mode = next_val(&mut args, "--mask")?,
            "--fixed" => fixed = next_val(&mut args, "--fixed")?,
            "--char" => {
                fill = next_val(&mut args, "--char")?.chars().next().unwrap_or('*');
            }
            "--keep" => {
                keep = next_val(&mut args, "--keep")?.parse().map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidInput, "--keep needs a number")
                })?;
            }
            "--format" => format = next_val(&mut args, "--format")?,
            "--json" => format = String::from("json"),
            "--only" => only.extend(parse_kind_list(&next_val(&mut args, "--only")?, "--only")?),
            "--without" | "--exclude" => without.extend(parse_kind_list(
                &next_val(&mut args, "--without")?,
                "--without",
            )?),
            "--check" => check = true,
            "-v" | "--verbose" => verbose = true,
            other if other.starts_with('-') && other != "-" => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!("unknown option: {other} (try --help)"),
                ));
            }
            other => files.push(other.to_string()),
        }
    }

    let mask = match mask_mode.as_str() {
        "label" => Mask::Label,
        "fixed" => Mask::fixed(fixed),
        "char" => Mask::Char(fill),
        "partial" => Mask::Partial {
            keep_last: keep,
            ch: fill,
        },
        "hash" => Mask::Hash,
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("unknown mask: {other}"),
            ))
        }
    };

    let detects_private_keys = (only.is_empty() || only.contains(&Kind::PrivateKey))
        && !without.contains(&Kind::PrivateKey);
    let mut redactor = if only.is_empty() {
        Redactor::new()
    } else {
        Redactor::only(&only)
    };
    for kind in &without {
        redactor = redactor.without(kind);
    }
    let redactor = redactor.mask(mask);

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut found_any = false;

    if files.is_empty() {
        let stdin = io::stdin();
        let mut reader = stdin.lock();
        let mut ctx = ProcessCtx::new(
            &redactor,
            check,
            detects_private_keys,
            verbose,
            &format,
            "<stdin>",
            &mut out,
            &mut found_any,
        );
        process_reader(&mut reader, &mut ctx)?;
    } else {
        for f in &files {
            if f == "-" {
                let stdin = io::stdin();
                let mut reader = stdin.lock();
                let mut ctx = ProcessCtx::new(
                    &redactor,
                    check,
                    detects_private_keys,
                    verbose,
                    &format,
                    "<stdin>",
                    &mut out,
                    &mut found_any,
                );
                process_reader(&mut reader, &mut ctx)?;
            } else {
                let file = std::fs::File::open(f)?;
                let mut reader = BufReader::new(file);
                let mut ctx = ProcessCtx::new(
                    &redactor,
                    check,
                    detects_private_keys,
                    verbose,
                    &format,
                    f,
                    &mut out,
                    &mut found_any,
                );
                process_reader(&mut reader, &mut ctx)?;
            }
        }
    }

    out.flush()?;
    if check && found_any {
        return Ok(ExitCode::from(1));
    }
    Ok(ExitCode::SUCCESS)
}

struct ProcessCtx<'a, W: Write> {
    redactor: &'a Redactor,
    check: bool,
    detects_private_keys: bool,
    verbose: bool,
    format: &'a str,
    source: &'a str,
    out: &'a mut W,
    found_any: &'a mut bool,
}

impl<'a, W: Write> ProcessCtx<'a, W> {
    #[allow(clippy::too_many_arguments)]
    fn new(
        redactor: &'a Redactor,
        check: bool,
        detects_private_keys: bool,
        verbose: bool,
        format: &'a str,
        source: &'a str,
        out: &'a mut W,
        found_any: &'a mut bool,
    ) -> Self {
        Self {
            redactor,
            check,
            detects_private_keys,
            verbose,
            format,
            source,
            out,
            found_any,
        }
    }
}

fn process_reader<R: BufRead, W: Write>(
    reader: &mut R,
    ctx: &mut ProcessCtx<'_, W>,
) -> io::Result<()> {
    let mut pending_private_key = String::new();
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            break;
        }

        if pending_private_key.is_empty()
            && ctx.detects_private_keys
            && starts_private_key_block(&line)
        {
            pending_private_key.push_str(&line);
            if private_key_block_has_end(&pending_private_key) {
                process_chunk(&pending_private_key, ctx)?;
                pending_private_key.clear();
            }
            continue;
        }

        if !pending_private_key.is_empty() {
            pending_private_key.push_str(&line);
            if private_key_block_has_end(&pending_private_key) {
                process_chunk(&pending_private_key, ctx)?;
                pending_private_key.clear();
            }
            continue;
        }

        process_chunk(&line, ctx)?;
    }

    // If EOF arrives before an END marker, do not drop buffered input. The
    // normal redactor will still clean any single-line secrets in the fragment.
    if !pending_private_key.is_empty() {
        process_chunk(&pending_private_key, ctx)?;
    }

    Ok(())
}

fn process_chunk<W: Write>(input: &str, ctx: &mut ProcessCtx<'_, W>) -> io::Result<()> {
    let matches = ctx.redactor.find(input);
    if !matches.is_empty() {
        *ctx.found_any = true;
    }
    if ctx.format == "json" {
        if !matches.is_empty() || !ctx.check {
            let mut json = String::new();
            json.push_str("{\n  \"source\": ");
            json.push_str(&json_escape(ctx.source));
            json.push_str(",\n  \"matches\": [\n");
            for (idx, m) in matches.iter().enumerate() {
                if idx > 0 {
                    json.push_str(",\n");
                }
                let matched_text = m.text(input);
                json.push_str(&format!(
                    "    {{ \"kind\": \"{}\", \"start\": {}, \"end\": {}, \"text\": {} }}",
                    m.kind.label(),
                    m.start,
                    m.end,
                    json_escape(matched_text)
                ));
            }
            json.push_str("\n  ]\n}\n");
            ctx.out.write_all(json.as_bytes())?;
        }
    } else {
        if ctx.check {
            if !matches.is_empty() && ctx.verbose {
                for m in matches {
                    eprintln!(
                        "leakguard: {}: found {} at {}..{}",
                        ctx.source, m.kind, m.start, m.end
                    );
                }
            }
        } else {
            ctx.out.write_all(ctx.redactor.clean(input).as_bytes())?;
        }
    }
    Ok(())
}

fn json_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len() + 2);
    escaped.push('"');
    for c in s.chars() {
        match c {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            other => escaped.push(other),
        }
    }
    escaped.push('"');
    escaped
}

fn starts_private_key_block(input: &str) -> bool {
    let begin = "-----BEGIN ";
    let mut from = 0;
    while let Some(rel) = input[from..].find(begin) {
        let start = from + rel;
        let after = start + begin.len();
        if let Some(header_rel) = input[after..].find("-----") {
            let header_end = after + header_rel;
            if input[after..header_end].contains("PRIVATE KEY") {
                return true;
            }
            from = after;
        } else {
            return false;
        }
    }
    false
}

fn private_key_block_has_end(input: &str) -> bool {
    let end_marker = "-----END ";
    input
        .find(end_marker)
        .and_then(|start| input[start + end_marker.len()..].find("-----"))
        .is_some()
}

fn next_val<I: Iterator<Item = String>>(
    args: &mut std::iter::Peekable<I>,
    flag: &str,
) -> io::Result<String> {
    args.next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, format!("{flag} needs a value")))
}
