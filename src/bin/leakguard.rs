//! `leakguard` CLI -- redact secrets & PII from stdin (or files) and write to stdout.
//!
//! Examples:
//!   tail -f app.log | leakguard
//!   leakguard access.log > clean.log
//!   leakguard --mask char --only email,ipv4 < input.txt
//!   leakguard --without phone app.log
//!   cat data.txt | leakguard --check --verbose   # exit 1 and report kinds found
//!   tail -f app.log | leakguard --json           # NDJSON findings, no values

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

MASKING:
    --mask <MODE>       label (default) | fixed | char | partial | hash | template
    --template <STR>    template string for --mask template (default: <{LABEL}>)
    --fixed <STR>       replacement string for --mask fixed (default: [REDACTED])
    --char <C>          fill char for char/partial masks (default: *)
    --keep <N>          characters to keep for --mask partial (default: 4;
                        clamped to at most half the match, so a mask can never
                        return the value unchanged)

DETECTION:
    --only <LIST>       comma-separated kinds to detect (e.g. email,ipv4,jwt)
    --without <LIST>    comma-separated kinds to skip from the selected detectors
    --ignore <LIST>     comma-separated literal strings to allowlist/skip
    --ignore-file <F>   read newline-separated allowlist strings from file <F>
    --redact-word <W>   redact a specific word or phrase as [REDACTED:KEYWORD]
    --redact-literal <S> redact a literal, optionally with a kind:
                        WORD        -> [REDACTED:KEYWORD]
                        WORD:KIND    -> [REDACTED:KIND]: a built-in kind name,
                                        or any custom label (uppercased), e.g.
                                        AcmeCorp:CLIENT
    --redact-words-file <F> read newline-separated word literals from file <F>

OUTPUT:
    --format <FMT>      output format: text (default) or json (NDJSON: one
                        compact JSON object per input chunk; matched values are
                        omitted unless --show-values)
    --json              shortcut for --format json
    --show-values       include the matched secret text in --json output
                        (omitted by default so findings can be logged safely)
    --stats             print a summary of redacted matches to stderr
    --check             don't print; exit 1 if any sensitive data is found
    -v, --verbose       with --check, write one line per finding to stderr:
                          leakguard: SOURCE: line N: col M: found KIND at S..E
                        (kind, offsets, line and column only -- never values)

META:
    --list-kinds        print supported kind names, then exit
    -h, --help          print this help
    -V, --version       print version

EXIT STATUS:
    0   no sensitive data found
    1   sensitive data found under --check
    2   usage error, unreadable file, or I/O error

KINDS:
    email, credit_card, ipv4, ipv6, jwt, us_ssn, mac, aws_access_key,
    url_credentials, phone, github_token, slack_token, stripe_key,
    google_api_key, openai_key, private_key, iban, azure_connection_string,
    telegram_token, discord_token, generic_secret (opt-in high-entropy scan)
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
    "generic_secret",
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
        "generic_secret" | "generic" | "high_entropy" => Kind::GenericSecret,
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
                    format!(
                        "unknown kind for {flag}: {part}\nvalid kinds: {}",
                        KIND_NAMES.join(", ")
                    ),
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
    let mut template = String::from("<{LABEL}>");
    let mut fixed = String::from("[REDACTED]");
    let mut fill = '*';
    let mut keep = 4usize;
    let mut format = String::from("text");
    let mut only: Vec<Kind> = Vec::new();
    let mut without: Vec<Kind> = Vec::new();
    let mut check = false;
    let mut verbose = false;
    let mut show_values = false;
    let mut show_stats = false;
    let mut ignore_vals: Vec<String> = Vec::new();
    let mut ignore_files: Vec<String> = Vec::new();
    let mut redact_words: Vec<String> = Vec::new();
    let mut redact_literals: Vec<(String, Kind)> = Vec::new();
    let mut redact_words_files: Vec<String> = Vec::new();
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
            "--template" => template = next_val(&mut args, "--template")?,
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
            "--ignore" => {
                for part in next_val(&mut args, "--ignore")?.split(',') {
                    let trim = part.trim();
                    if !trim.is_empty() {
                        ignore_vals.push(trim.to_string());
                    }
                }
            }
            "--ignore-file" => ignore_files.push(next_val(&mut args, "--ignore-file")?),
            "--redact-word" => redact_words.push(next_val(&mut args, "--redact-word")?),
            "--redact-literal" => {
                let spec = next_val(&mut args, "--redact-literal")?;
                if let Some((word, kind_str)) = spec.split_once(':') {
                    // A built-in kind name, or any custom label (uppercased so
                    // `AcmeCorp:client` and `AcmeCorp:CLIENT` behave alike).
                    // Kind::Custom holds a &'static str, so custom labels are
                    // deliberately leaked: one tiny allocation per --redact-literal
                    // flag in a short-lived process is preferable to copying or
                    // a lifetime bookkeeping table.
                    let kind = match parse_kind(kind_str) {
                        Some(k) => k,
                        None => {
                            let label: &'static str =
                                Box::leak(kind_str.to_ascii_uppercase().into_boxed_str());
                            Kind::Custom(label)
                        }
                    };
                    redact_literals.push((word.to_string(), kind));
                } else {
                    redact_literals.push((spec, Kind::Custom("KEYWORD")));
                }
            }
            "--redact-words-file" => {
                redact_words_files.push(next_val(&mut args, "--redact-words-file")?)
            }
            "--check" => check = true,
            "--show-values" => show_values = true,
            "--stats" | "--summary" => show_stats = true,
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
        "template" => Mask::template(template),
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
    for val in &ignore_vals {
        redactor = redactor.ignore(val);
    }
    for f in &ignore_files {
        let content = std::fs::read_to_string(f)?;
        for line in content.lines() {
            let trim = line.trim();
            if !trim.is_empty() && !trim.starts_with('#') {
                redactor = redactor.ignore(trim);
            }
        }
    }
    if !redact_words.is_empty() {
        redactor = redactor.redact_words(&redact_words, Kind::Custom("KEYWORD"));
    }
    for (word, kind) in &redact_literals {
        redactor = redactor.redact_literal(word, kind.clone());
    }
    for f in &redact_words_files {
        let content = std::fs::read_to_string(f)?;
        let words: Vec<String> = content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect();
        if !words.is_empty() {
            redactor = redactor.redact_words(&words, Kind::Custom("KEYWORD"));
        }
    }
    let redactor = redactor.mask(mask);

    let stdout = io::stdout();
    let mut out = BufWriter::new(stdout.lock());
    let mut stats = leakguard::RedactionStats::new();
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
            show_values,
            &mut stats,
            show_stats,
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
                    show_values,
                    &mut stats,
                    show_stats,
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
                    show_values,
                    &mut stats,
                    show_stats,
                    f,
                    &mut out,
                    &mut found_any,
                );
                process_reader(&mut reader, &mut ctx)?;
            }
        }
    }

    out.flush()?;
    if show_stats {
        eprintln!("=== leakguard redaction summary ===");
        eprintln!("{}", stats);
    }
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
    show_values: bool,
    stats: &'a mut leakguard::RedactionStats,
    show_stats: bool,
    current_line: usize,
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
        show_values: bool,
        stats: &'a mut leakguard::RedactionStats,
        show_stats: bool,
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
            show_values,
            stats,
            show_stats,
            current_line: 1,
            source,
            out,
            found_any,
        }
    }
}

/// Upper bound on a buffered PEM block before it is flushed as ordinary text.
/// Guards against an unterminated `-----BEGIN ... PRIVATE KEY-----` line
/// causing unbounded memory growth.
const MAX_PENDING_BYTES: usize = 1024 * 1024;
/// Line-count companion to [`MAX_PENDING_BYTES`].
const MAX_PENDING_LINES: usize = 10_000;

fn process_reader<R: BufRead, W: Write>(
    reader: &mut R,
    ctx: &mut ProcessCtx<'_, W>,
) -> io::Result<()> {
    let mut pending_private_key = String::new();
    let mut pending_lines = 0usize;
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
            pending_lines = 1;
            // Only the newly read line is inspected for the END marker, so the
            // accumulated buffer is never re-scanned (that was quadratic).
            if private_key_block_has_end(&line) {
                process_chunk(&pending_private_key, ctx)?;
                pending_private_key.clear();
                pending_lines = 0;
            }
            continue;
        }

        if !pending_private_key.is_empty() {
            pending_private_key.push_str(&line);
            pending_lines += 1;
            // Flush either because the block is complete, or because it has
            // grown past the cap -- a malformed block with no END marker must
            // not buffer the rest of the stream. Both cases emit what we have
            // and resume normal line-by-line streaming, so no input is dropped.
            let block_complete = private_key_block_has_end(&line);
            let over_cap = pending_private_key.len() >= MAX_PENDING_BYTES
                || pending_lines >= MAX_PENDING_LINES;
            if block_complete || over_cap {
                process_chunk(&pending_private_key, ctx)?;
                pending_private_key.clear();
                pending_lines = 0;
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
    let located = ctx.redactor.find_located(input);
    if !located.is_empty() {
        *ctx.found_any = true;
    }
    if ctx.show_stats {
        for loc in &located {
            ctx.stats.record(&loc.matched);
        }
    }
    if ctx.format == "json" {
        if !located.is_empty() || !ctx.check {
            // NDJSON: exactly one compact object per input chunk, so the output
            // stays streamable (`tail -f`) and greppable, and each line parses
            // independently.
            let mut json = String::new();
            json.push('{');
            json.push_str("\"source\":");
            json.push_str(&json_escape(ctx.source));
            json.push_str(",\"matches\":[");
            for (idx, loc) in located.iter().enumerate() {
                let m = &loc.matched;
                if idx > 0 {
                    json.push(',');
                }
                let file_line = ctx.current_line - 1 + loc.line;
                json.push_str(&format!(
                    "{{\"kind\":\"{}\",\"start\":{},\"end\":{},\"line\":{},\"column\":{}",
                    m.kind.label(),
                    m.start,
                    m.end,
                    file_line,
                    loc.column
                ));
                // The matched text is a secret: only emit it when explicitly
                // requested, never by default and never merely because
                // `--check` was passed.
                if ctx.show_values {
                    json.push_str(",\"text\":");
                    json.push_str(&json_escape(m.text(input)));
                }
                json.push('}');
            }
            json.push_str("]}\n");
            ctx.out.write_all(json.as_bytes())?;
        }
    } else if ctx.check {
        if !located.is_empty() && ctx.verbose {
            for loc in located {
                let m = &loc.matched;
                let file_line = ctx.current_line - 1 + loc.line;
                eprintln!(
                    "leakguard: {}: line {}: col {}: found {} at {}..{}",
                    ctx.source, file_line, loc.column, m.kind, m.start, m.end
                );
            }
        }
    } else {
        ctx.out.write_all(ctx.redactor.clean(input).as_bytes())?;
    }
    ctx.current_line += input.bytes().filter(|&b| b == b'\n').count();
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
            // RFC 8259 requires every code point below 0x20 to be escaped.
            c if (c as u32) < 0x20 => escaped.push_str(&format!("\\u{:04x}", c as u32)),
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
