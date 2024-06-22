use std::fmt;
use std::io::prelude::*;
use std::net::TcpStream;
use std::path::PathBuf;

use native_tls::{HandshakeError, TlsStream};

const DEF_NS_PORT: u16 = 443;
const DEF_TGT_FILE: &'static str = "/tmp/bget-latest";
const DEF_MAX_WAIT: u64 = 330;
const DEF_MAX_AGE: u64 = 1800;

const WAIT_EXTRA: u64 = 5;
const LATE_INTERVAL: u64 = 5;
const LATE_BACKOFF: u64 = 2;

const CFG_REL_PATH: &'static str = ".config/bget/bget.cfg";

const HELP: &'static str = "bget, a tool to retrieve blood glucose readings from Nighscout

Usage: bget [-h] [-o] [-c <path to config>]

Reads information about your Nightscout instance from a configuration
file at `$HOME/.config/bget/bget.cfg`. Retrieves the latest reading
and delta; writes both to the target file `/tmp/bget-latest`. Attempts
to retrieve and write a new reading about every five minutes until
termination.

Options:
-h : print this help, then terminate
-o : retrieve and write only one reading, then terminate
-c <path to config> : read configuration from the provided file";

const USAGE: &'static str = "bget [-h] [-o] [-c <path to config>]";

#[derive(Debug)]
struct Cfg {
    ns_url: String,
    ns_token: String,
    ns_port: u16,

    tgt_file: PathBuf,

    max_wait: u64,
    max_age: u64,
}

const ARROW_STRS: [&[u8]; 7] = [
    b"DoubleDown",
    b"SingleDown",
    b"FortyFiveDown",
    b"Flat",
    b"FortyFiveUp",
    b"SingleUp",
    b"DoubleUp",
];

#[derive(Debug)]
#[repr(u8)]
enum Arrow {
    DoubleDown = 0,    // ⇊
    SingleDown = 1,    // ↓
    FortyFiveDown = 2, // ↘
    Flat = 3,          // →
    FortyFiveUp = 4,   // ↗
    SingleUp = 5,      // ↑
    DoubleUp = 6,      // ⇈
}

impl TryFrom<u8> for Arrow {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use Arrow::*;
        match value {
            0 => Ok(DoubleDown),
            1 => Ok(SingleDown),
            2 => Ok(FortyFiveDown),
            3 => Ok(Flat),
            4 => Ok(FortyFiveUp),
            5 => Ok(SingleUp),
            6 => Ok(DoubleUp),
            _ => Err(()),
        }
    }
}

#[derive(Debug)]
struct Entry {
    secs: u64,
    bg: u16,
    arr: Arrow,
}

macro_rules! errc {
    ( $code:literal $mode:ident $(,s $attc:expr)? $(,p $pass:ident)? ) => {
        BgetErr {
            code: $code,
            mode: BgetErrKind::$mode,
            $(attc: Some(String::from($attc)),)?
            $(pass: Some(Box::from($pass)),)?
            ..Default::default()
        }
    };
}

enum BgetErrKind {
    WrongArg,
    CfgNoHome,
    CfgNotFound,
    CfgBadKey,
    CfgNoUrl,
    CfgNoToken,
    CfgSyntax,
    NetFail,
    TlsFail,
    FileFail,
    EntryBad,
    HttpBad,
    Unknown,
}

struct BgetErr {
    code: i32,
    mode: BgetErrKind,
    attc: Option<String>,
    pass: Option<Box<dyn std::error::Error>>,
}

impl Default for BgetErr {
    fn default() -> Self {
        Self {
            code: 1,
            mode: BgetErrKind::Unknown,
            attc: None,
            pass: None,
        }
    }
}

impl fmt::Display for BgetErr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let sp1 = match self.code {
            1 => "failure",
            2 => "usage",
            3 => "invalid config",
            _ => panic!("bad error code"),
        };
        use BgetErrKind::*;
        let sp2 = match self.mode {
            WrongArg => USAGE,
            CfgNoHome => "config not found; HOME not defined",
            CfgNotFound => "config not found at",
            CfgBadKey => "unrecognized key",
            CfgNoUrl => "no URL provided",
            CfgNoToken => "no token provided",
            CfgSyntax => "syntax error",
            NetFail => "network connection error",
            TlsFail => "TLS connection error",
            FileFail => "file output error",
            EntryBad => "unexpected token from Nightscout",
            HttpBad => "HTTP parse failure",

            Unknown => "fatal",
        };
        let sp3 = match self.attc {
            Some(ref s) => String::from(": ") + s,
            None => String::new(),
        };

        write!(f, "{}: {}{}", sp1, sp2, sp3)
    }
}

// EXIT CODES
// 0 : success
// 1 : general failure
// 2 : called incorrectly
// 3 : invalid config

// FLAGS
// -c : path to config file
// -o : read only once
// -h : help

fn main() {
    let mut args = std::env::args();
    args.next();

    let (arg_path, only_once) = {
        let (mut cxp, mut csn, mut osn) = (false, false, false);
        let mut tpath = None;

        for a in args.into_iter() {
            match a.as_str() {
                "-c" if !csn & !cxp => cxp = true,
                "-o" if !osn & !cxp => osn = true,
                "-h" if !cxp => {
                    println!("{HELP}");
                    std::process::exit(0);
                }
                path if cxp && path.as_bytes()[0] != b'-' => {
                    tpath = Some(path.into());
                    cxp = false;
                    csn = true;
                }
                _ => fail(errc!(2 WrongArg)),
            }
        }

        if cxp {
            fail(errc!(2 WrongArg));
        }

        (tpath, osn)
    };

    let cfg_path = match arg_path {
        Some(cfp) => cfp,
        None => match std::env::var("HOME") {
            Ok(s) => PathBuf::from(s),
            Err(e) => fail(errc!(1 CfgNoHome ,p e)),
        }
        .join(CFG_REL_PATH),
    };

    let cfg_content = match std::fs::read_to_string(&cfg_path) {
        Ok(s) => s,
        Err(e) => fail(errc!(1 CfgNotFound ,s cfg_path.to_string_lossy() ,p e)),
    };

    let top_config = match parse_config(cfg_content) {
        Ok(c) => c,
        Err(e) => fail(e),
    };

    let request = format!(
        "GET /api/v1/entries/?count=2&token={} HTTP/1.1\r\n\r\n",
        &top_config.ns_token
    )
    .into_bytes();

    let mut late_int = LATE_INTERVAL;

    loop {
        let entries = match get_entries(&top_config, &request) {
            Ok(v) => v,
            Err(e) => fail(e),
        };

        let (dlast, checkin) = gen_int(&top_config, &mut late_int, &entries);
        let r_output = gen_msg(&top_config, &entries, dlast);

        println!("{r_output}");
        println!("{checkin}s");

        if let Err(e) = write_out(&top_config, r_output.as_bytes()) {
            fail(e)
        }

        if only_once {
            break;
        }

        process_sleep(checkin as _);
    }

    fn fail(err: BgetErr) -> ! {
        println!("{}", err);

        match err.pass {
            Some(be) => eprintln!("-> {}", be),
            None => (),
        }

        std::process::exit(err.code);
    }
}

fn write_out(tcfg: &Cfg, output: &[u8]) -> Result<(), BgetErr> {
    let mut target = match std::fs::File::create(&tcfg.tgt_file) {
        Ok(f) => f,
        Err(e) => return Err(errc!(1 FileFail ,p e)),
    };

    if let Err(e) = target.write_all(output) {
        return Err(errc!(1 FileFail ,p e));
    }

    Ok(())
}

fn parse_config(text: String) -> Result<Cfg, BgetErr> {
    let (mut turl, mut ttkn, mut tprt, mut ttfl, mut tmcw, mut tmra) =
        (None, None, None, None, None, None);

    for mut ent in text.lines().filter_map(|l| {
        if l.is_empty() || l.starts_with('#') {
            None
        } else {
            Some(l.split_ascii_whitespace())
        }
    }) {
        match ent.next() {
            Some(h) => match h {
                "NightscoutURL" => turl = ent.next(),
                "NightscoutToken" => ttkn = ent.next(),
                "NightscoutPort" => tprt = ent.next(),
                "TargetFile" => ttfl = ent.next(),
                "MaxCheckWait" => tmcw = ent.next(),
                "MaxReadingAge" => tmra = ent.next(),
                _ => return Err(errc!(3 CfgBadKey)),
            },
            None => unreachable!(),
        }
    }

    Ok(Cfg {
        ns_url: match turl {
            Some(url) => String::from(url),
            None => return Err(errc!(3 CfgNoUrl)),
        },
        ns_token: match ttkn {
            Some(tkn) => String::from(tkn),
            None => return Err(errc!(3 CfgNoToken)),
        },
        ns_port: match tprt {
            Some(prt) => match prt.parse::<u16>() {
                Ok(n) => n,
                Err(e) => return Err(errc!(3 CfgSyntax ,p e)),
            },
            None => DEF_NS_PORT,
        },
        tgt_file: PathBuf::from(match ttfl {
            Some(tfl) => tfl,
            None => DEF_TGT_FILE,
        }),
        max_wait: match tmcw {
            Some(mcw) => match mcw.parse::<u64>() {
                Ok(n) => n,
                Err(e) => return Err(errc!(3 CfgSyntax ,p e)),
            },
            None => DEF_MAX_WAIT,
        },
        max_age: match tmra {
            Some(mra) => match mra.parse::<u64>() {
                Ok(n) => n,
                Err(e) => return Err(errc!(3 CfgSyntax ,p e)),
            },
            None => DEF_MAX_AGE,
        },
    })
}

fn get_entries(tcfg: &Cfg, request: &[u8]) -> Result<Vec<Entry>, BgetErr> {
    let tls_conn_builder = match native_tls::TlsConnector::new() {
        Ok(tcb) => tcb,
        Err(e) => return Err(errc!(1 TlsFail ,p e)),
    };

    let tcp_conn = match TcpStream::connect((tcfg.ns_url.as_str(), tcfg.ns_port)) {
        Ok(tpc) => tpc,
        Err(e) => return Err(errc!(1 NetFail ,p e)),
    };

    let mut api_conn = match tls_conn_builder.connect(&tcfg.ns_url, &tcp_conn) {
        Ok(out) => out,
        Err(HandshakeError::WouldBlock(_)) => unreachable!(),
        Err(HandshakeError::Failure(e)) => return Err(errc!(1 TlsFail ,p e)),
    };

    if let Err(e) = api_conn.write_all(request) {
        return Err(errc!(1 NetFail ,p e));
    }

    if let Err(e) = api_conn.flush() {
        return Err(errc!(1 NetFail ,p e));
    }

    let msg = match read_http_msg(&mut api_conn) {
        Ok(v) => v,
        Err(s) => return Err(errc!(1 HttpBad ,s s)),
    };

    api_conn.shutdown().unwrap_or(());
    tcp_conn.shutdown(std::net::Shutdown::Both).unwrap_or(());

    parse_nightscout_entries(msg)
}

fn gen_msg(tcfg: &Cfg, entries: &Vec<Entry>, dlast: u64) -> String {
    let bg_cur = entries[0].bg;
    let bg_dlt = bg_cur as i16 - entries[1].bg as i16;
    let bg_chg = bg_dlt.abs();

    let dlt_sym = if bg_dlt >= 0 { '+' } else { '−' };
    let arr_sym = match entries[0].arr {
        Arrow::DoubleDown => '⇊',
        Arrow::SingleDown => '↓',
        Arrow::FortyFiveDown => '↘',
        Arrow::Flat => '→',
        Arrow::FortyFiveUp => '↗',
        Arrow::SingleUp => '↑',
        Arrow::DoubleUp => '⇈',
    };

    if dlast < tcfg.max_age {
        format!("{bg_cur} {arr_sym} {dlt_sym}{bg_chg}")
    } else {
        format!("-- NR --")
    }
}

fn gen_int(tcfg: &Cfg, lint: &mut u64, entries: &Vec<Entry>) -> (u64, u64) {
    let rd_last = entries[0].secs;
    let rd_gap = rd_last - entries[1].secs;

    let curtime = get_time_secs() as u64;
    let expect = rd_last + rd_gap + WAIT_EXTRA;

    (
        curtime - rd_last,
        if expect <= curtime {
            *lint *= LATE_BACKOFF;
            *lint
        } else {
            *lint = LATE_INTERVAL;
            (expect - curtime).min(tcfg.max_wait)
        },
    )
}

fn process_sleep(sec: i64) {
    // syscall: clock_nanosleep

    #[repr(C)]
    struct Timespec {
        sec: i64,
        nsec: i64,
    }

    let clock_nanosleep = 230u64;
    let clockid = 7u64; // CLOCK_BOOTTIME
    let flags = 0i32;

    let spec = Timespec { sec, nsec: 0 };
    let t: *const Timespec = &spec;
    let remain = std::ptr::null_mut::<Timespec>();

    let out: i32;

    unsafe {
        std::arch::asm!("syscall",
                        in("rax") clock_nanosleep,
                        in("rdi") clockid,
                        in("rsi") flags,
                        in("rdx") t,
                        in("r10") remain,
                        lateout("rax") out,
                        out("rcx") _,
                        out("r11") _,
                        options(nostack, preserves_flags)
        );
    }

    assert_eq!(out, 0);
}

fn get_time_secs() -> i64 {
    // syscall: time

    let time = 201u64;
    let time_tloc = std::ptr::null::<i64>();

    let time_out: i64;

    unsafe {
        std::arch::asm!("syscall",
                        in("rax") time,
                        in("rdi") time_tloc,
                        lateout("rax") time_out,
                        out("rcx") _,
                        out("r11") _,
                        options(nostack, preserves_flags)
        );
    }

    assert!(time_out >= 0);

    time_out
}

fn parse_nightscout_entries(msg: Vec<u8>) -> Result<Vec<Entry>, BgetErr> {
    enum ParseState {
        Outer,
        Time,
        Glucose,
        Dir,
    }

    fn dir_text_to_arrow(dir: &Vec<u8>) -> Result<Arrow, BgetErr> {
        match ARROW_STRS.iter().enumerate().find_map(|(i, e)| {
            if dir == *e {
                (i as u8).try_into().ok()
            } else {
                None
            }
        }) {
            Some(arr) => Ok(arr),
            None => Err(errc!(1 EntryBad ,s String::from_utf8_lossy(dir))),
        }
    }

    let mut out = vec![];

    let mut cs = ParseState::Outer;
    let mut ct = 0u64;
    let mut cg = 0u16;
    let mut aacc = vec![];

    for b in msg.into_iter().chain(std::iter::once(b'\n')) {
        use ParseState::*;
        match cs {
            Outer => match b {
                b'\n' => {
                    // reset
                    out.push(Entry {
                        secs: ct,
                        bg: cg,
                        arr: dir_text_to_arrow(&aacc)?,
                    });
                    ct = 0;
                    cg = 0;
                    aacc.clear();
                }
                b'\t' => cs = Time,
                _ => (),
            },
            Time => match b {
                b'\t' => {
                    ct /= 1000;
                    cs = Glucose;
                }
                _ if b.is_ascii_digit() => {
                    ct *= 10;
                    ct += b as u64 & 0xF;
                }
                _ => return Err(errc!(1 EntryBad ,s format!("{b} in Time"))),
            },
            Glucose => match b {
                b'\t' => cs = Dir,
                _ if b.is_ascii_digit() => {
                    cg *= 10;
                    cg += b as u16 & 0xF;
                }
                _ => return Err(errc!(1 EntryBad ,s format!("{b} in Glucose"))),
            },
            Dir => match b {
                b'\t' => cs = Outer,
                b'"' => (),
                _ if b.is_ascii_alphabetic() => {
                    aacc.push(b);
                }
                _ => return Err(errc!(1 EntryBad ,s format!("{b} in Dir"))),
            },
        }
    }

    Ok(out)
}

/// Parses a full HTTP message from an input TLS connection over TCP,
/// returning its body.
///
/// The header must either provide a content length or specify chunked
/// transfer encoding.
fn read_http_msg(stream: &mut TlsStream<&TcpStream>) -> Result<Vec<u8>, String> {
    let hd_len = b"Content-Length:";
    let hd_enc = b"Transfer-Encoding:";
    let va_enc = b"chunked";

    // buffer for reads direct from stream
    let mut buf = [0u8; 1024];

    // accumulator to collect unaltered message
    let mut acc: Vec<u8> = Vec::new();

    // current position in accumulator
    let mut cursor: usize = 0;

    // current position in a constant string
    let mut parcur: usize = 1;

    // current parsing phase
    enum Phase {
        // HTTP header
        Head,
        // content length
        LenH,
        // transfer encoding
        EncH,
        // encoding type (must be chunked)
        EncT,
        // content length
        MsgL,
        // chunk length
        SegL,
        // single message body
        BdyO,
        // individual chunk
        BdyC,
    }

    // message content type
    enum MsgTy {
        // unable to discern
        None,
        // single body
        Once,
        // chunked body
        Cnkd,
    }

    let mut phase = Phase::Head;
    let mut msgty = MsgTy::None;

    // length & cursor for segment reads
    let mut seglen = 0u32;
    let mut segrd = 0u32;

    // carriage return & line feed flags
    let mut cr = false;
    let mut lf = false;

    // message body alone
    let mut body: Vec<u8> = Vec::new();

    // repeat until message parse complete
    loop {
        // read available bytes
        match stream.read(&mut buf) {
            Ok(n) => acc.extend_from_slice(&buf[0..n]),

            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => (),
            Err(err) => return Err(format!("{err:?}")),
        }

        // parse read bytes
        while cursor < acc.len() {
            // each iteration parses a single byte
            let chr = acc[cursor];

            match phase {
                Phase::Head => match chr {
                    // find header end: "\r\n\r\n"
                    b'\r' => cr = true,
                    b'\n' => {
                        if cr && !lf {
                            cr = false;
                            lf = true;
                        } else if cr && lf {
                            match msgty {
                                MsgTy::None => {
                                    return Err(String::from("header parse: no len nor enc"))
                                }
                                MsgTy::Once => phase = Phase::BdyO,
                                MsgTy::Cnkd => phase = Phase::SegL,
                            }
                        }
                    }
                    c => {
                        cr = false;
                        lf = false;

                        // seek the start of an appropriate header
                        if c == hd_len[0] {
                            phase = Phase::LenH
                        } else if c == hd_enc[0] {
                            phase = Phase::EncH
                        }
                    }
                },
                Phase::LenH => {
                    // read header and set message type appropriately
                    if parcur >= hd_len.len() {
                        parcur = 1;
                        msgty = MsgTy::Once;
                        phase = Phase::MsgL;
                    } else if chr == hd_len[parcur] {
                        parcur += 1;
                    } else {
                        parcur = 1;
                        phase = Phase::Head;
                    }
                }
                Phase::EncH => {
                    // read header and set message type appropriately
                    if parcur >= hd_enc.len() {
                        parcur = 0;
                        msgty = MsgTy::Cnkd;
                        phase = Phase::EncT;
                    } else if chr == hd_enc[parcur] {
                        parcur += 1;
                    } else {
                        parcur = 1;
                        phase = Phase::Head;
                    }
                }
                Phase::EncT => {
                    // ensure chunked transfer encoding
                    if parcur >= va_enc.len() {
                        parcur = 1;
                        phase = Phase::Head;
                    } else if chr == va_enc[parcur] {
                        parcur += 1;
                    } else {
                        return Err(String::from("header parse: not chunked encoding"));
                    }
                }
                Phase::MsgL => match chr {
                    b'\r' => {
                        cr = true;
                        phase = Phase::Head;
                    }
                    // parse decimal message length
                    b if b.is_ascii_digit() => {
                        seglen *= 10;
                        seglen += chr as u32 & 0xF;
                    }
                    _ => return Err(String::from("header parse: invalid length")),
                },
                Phase::SegL => match chr {
                    b'\r' => cr = true,
                    b'\n' => {
                        if !cr {
                            return Err(String::from("segment parse: misplaced line feed"));
                        }
                        phase = Phase::BdyC;
                    }
                    // parse hexadecimal chunk length
                    b if b.is_ascii_hexdigit() => {
                        seglen *= 16;
                        match b {
                            b'0'..=b'9' => seglen += b as u32 - 48,
                            b'A'..=b'F' => seglen += b as u32 - 55,
                            b'a'..=b'f' => seglen += b as u32 - 87,
                            _ => unreachable!(),
                        }
                    }
                    _ => return Err(String::from("segment parse: invalid length")),
                },
                Phase::BdyO => {
                    if segrd < seglen {
                        body.push(chr);
                        segrd += 1;
                    }
                    if segrd == seglen {
                        return Ok(body);
                    }
                }
                Phase::BdyC => {
                    // alternate between reading chunks & lengths
                    if segrd <= seglen {
                        body.push(chr);
                        segrd += 1;
                    } else {
                        match chr {
                            b'\r' => cr = true,
                            b'\n' => {
                                if !cr {
                                    return Err(String::from("segment parse: misplaced line feed"));
                                }
                                if seglen == 0 {
                                    return Ok(body);
                                }
                                seglen = 0;
                                segrd = 0;
                                phase = Phase::SegL;
                            }
                            _ => return Err(String::from("segment parse: incorrect length")),
                        }
                    }
                }
            }
            cursor += 1;
        }
    }
}
