use std::io::prelude::*;
use std::net::TcpStream;
use std::path::PathBuf;

use native_tls::{HandshakeError, TlsStream};

const DEF_NS_PORT: u16 = 443;
const DEF_TGT_FILE: &'static str = "/tmp/bget-latest";
const DEF_MAX_WAIT: u64 = 330;
const DEF_MAX_AGE: u64 = 1800;

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

const WARG: &'static str = "usage: bget [-h] [-o] [-c <path to config>]";

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

#[derive(Debug)]
struct Entry {
    secs: u64,
    bg: u16,
    arr: Arrow,
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

fn term(code: i32, out: &str) -> ! {
    println!("{}", out);
    std::process::exit(code);
}

fn main() {
    let mut args = std::env::args();
    args.next();

    let (arg_path, only_once) = {
        let (mut cxp, mut csn, mut osn) = (false, false, false);
        let mut tpath = None;

        loop {
            match args.next() {
                Some(st) => match st.as_str() {
                    "-c" if !csn & !cxp => cxp = true,
                    "-o" if !osn & !cxp => osn = true,
                    "-h" if !cxp => term(0, HELP),
                    path if cxp && path.as_bytes()[0] != b'-' => {
                        tpath = Some(path.into());
                        cxp = false;
                        csn = true;
                    }
                    _ => term(2, WARG),
                },
                None => {
                    if cxp {
                        term(2, WARG);
                    } else {
                        break;
                    }
                }
            }
        }

        (tpath, osn)
    };

    // TODO: deduplicate failure and invalid config code

    let cfg_path = match arg_path {
        Some(cfp) => cfp,
        None => {
            let hp = match std::env::var("HOME") {
                Ok(s) => PathBuf::from(s),
                Err(e) => {
                    println!("failure: default config not found; HOME not set");
                    eprintln!("err: {:?}", e);
                    std::process::exit(1);
                }
            };
            hp.join(CFG_REL_PATH)
        }
    };

    let cfg_content = match std::fs::read_to_string(&cfg_path) {
        Ok(s) => s,
        Err(e) => {
            println!("failure: config not found at {:?}", cfg_path);
            eprintln!("err: {:?}", e);
            std::process::exit(1);
        }
    };

    let top_config = {
        let (mut turl, mut ttkn, mut tprt, mut ttfl, mut tmcw, mut tmra) =
            (None, None, None, None, None, None);

        for mut ent in cfg_content.lines().filter_map(|l| {
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
                    _ => {
                        println!("invalid config: unrecognized key");
                        std::process::exit(3);
                    }
                },
                None => unreachable!(),
            }
        }

        Cfg {
            ns_url: match turl {
                Some(url) => String::from(url),
                None => {
                    println!("invalid config: no URL provided");
                    std::process::exit(3);
                }
            },
            ns_token: match ttkn {
                Some(tkn) => String::from(tkn),
                None => {
                    println!("invalid config: no token provided");
                    std::process::exit(3);
                }
            },
            ns_port: match tprt {
                Some(prt) => match prt.parse::<u16>() {
                    Ok(n) => n,
                    Err(e) => {
                        println!("invalid config: syntax error");
                        eprintln!("err: {:?}", e);
                        std::process::exit(3);
                    }
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
                    Err(e) => {
                        println!("invalid config: syntax error");
                        eprintln!("err: {:?}", e);
                        std::process::exit(3);
                    }
                },
                None => DEF_MAX_WAIT,
            },
            max_age: match tmra {
                Some(mra) => match mra.parse::<u64>() {
                    Ok(n) => n,
                    Err(e) => {
                        println!("invalid config: syntax error");
                        eprintln!("err: {:?}", e);
                        std::process::exit(3);
                    }
                },
                None => DEF_MAX_AGE,
            },
        }
    };

    // println!("{:?}", top_config);

    let api_tls_conn = native_tls::TlsConnector::new().unwrap();

    let api_tcp_conn =
        TcpStream::connect((top_config.ns_url.as_str(), top_config.ns_port)).unwrap();

    api_tcp_conn.set_nonblocking(true).unwrap();

    let mut api_conn = match api_tls_conn.connect(&top_config.ns_url, api_tcp_conn) {
        Ok(out) => out,
        Err(HandshakeError::WouldBlock(mut stream)) => loop {
            match stream.handshake() {
                Ok(out) => break out,
                Err(HandshakeError::WouldBlock(nstream)) => stream = nstream,
                Err(HandshakeError::Failure(_)) => panic!(),
            }
        },
        Err(HandshakeError::Failure(_)) => panic!(),
    };

    let request = format!(
        "GET /api/v1/entries/?count=2&token={} HTTP/1.1\r\n\r\n",
        &top_config.ns_token
    );

    api_conn.write_all(request.as_bytes()).unwrap();
    api_conn.flush().unwrap();

    let msg = read_http_msg(&mut api_conn);

    let entries = parse_nightscout_entries(msg);

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

    let rd_last = entries[0].secs;
    let rd_gap = rd_last - entries[1].secs;

    let curtime = get_time_secs() as u64;
    let checkin = ((rd_last + rd_gap + 5) - curtime).min(top_config.max_wait);

    let dlast = curtime - rd_last;

    // println!("{entries:?}");

    if dlast < top_config.max_age {
        println!("{bg_cur} {arr_sym} {dlt_sym}{bg_chg}");
    } else {
        println!("-- NR --");
    }

    println!("{checkin}s");
}

// TODO: add timed recurring checks & write to file
type Fd = u32;

// fn start_timer() -> Fd {

// }

// fn set_timer(tgt: Fd) {

// }

fn get_time_secs() -> i64 {
    unsafe {
        let time = 201u64;
        let time_tloc = std::ptr::null::<i64>();

        let time_out: i64;

        std::arch::asm!("syscall",
                        in("rax") time,
                        in("rdi") time_tloc,
                        lateout("rax") time_out,
                        out("rcx") _,
                        out("r11") _,
        );

        time_out
    }
}

fn parse_nightscout_entries(msg: Vec<u8>) -> Vec<Entry> {
    enum ParseState {
        Outer,
        Time,
        Glucose,
        Dir,
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
                        arr: ARROW_STRS
                            .iter()
                            .enumerate()
                            .find_map(|(i, e)| {
                                if &aacc == *e {
                                    Some(unsafe { std::mem::transmute::<u8, Arrow>(i as u8) })
                                } else {
                                    None
                                }
                            })
                            .unwrap(),
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
                _ => panic!(),
            },
            Glucose => match b {
                b'\t' => cs = Dir,
                _ if b.is_ascii_digit() => {
                    cg *= 10;
                    cg += b as u16 & 0xF;
                }
                _ => panic!(),
            },
            Dir => match b {
                b'\t' => cs = Outer,
                b'"' => (),
                _ if b.is_ascii_alphabetic() => {
                    aacc.push(b);
                }
                _ => panic!(),
            },
        }
    }

    out
}

/// Parses a full HTTP message from an input TLS connection over TCP,
/// returning its body.
///
/// The header must either provide a content length or specify chunked
/// transfer encoding.
fn read_http_msg(stream: &mut TlsStream<TcpStream>) -> Vec<u8> {
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
    #[derive(Debug)]
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
            Ok(n) => {
                // println!("LAST READ:\n{}", String::from_utf8_lossy(&buf[0..n]));
                acc.extend_from_slice(&buf[0..n]);
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => (),
            Err(err) => panic!("{:?}", err),
        }

        // parse read bytes
        while cursor < acc.len() {
            // each iteration parses a single byte
            let chr = acc[cursor];

            // let dbgchr: char = chr.into();
            // println!("Phs: {:?} ; Chr: {}", phase, dbgchr);

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
                                MsgTy::None => panic!("header parse fail: no len nor enc"),
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
                        panic!("header parse fail: not chunked encoding");
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
                    _ => panic!("header parse fail: invalid length"),
                },
                Phase::SegL => match chr {
                    b'\r' => cr = true,
                    b'\n' => {
                        if !cr {
                            panic!("segment parse fail: misplaced line feed");
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
                    _ => panic!("segment parse fail: invalid length"),
                },
                Phase::BdyO => {
                    if segrd < seglen {
                        body.push(chr);
                        segrd += 1;
                    }
                    if segrd == seglen {
                        return body;
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
                                    panic!("segment parse fail: misplaced line feed");
                                }
                                if seglen == 0 {
                                    return body;
                                }
                                seglen = 0;
                                segrd = 0;
                                phase = Phase::SegL;
                            }
                            _ => panic!("segment parse fail: incorrect length"),
                        }
                    }
                }
            }
            cursor += 1;
        }
    }
}
