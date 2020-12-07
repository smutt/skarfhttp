/*
Copyright (c) 2020, Andrew McConachie <andrew@depht.com>
All rights reserved.
 */

//////////////
// INCLUDES //
//////////////
#[macro_use] extern crate log;
use clap::{Arg, App, ArgGroup};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use pcap::{Capture, Device};
use etherparse::PacketHeaders;
use etherparse::IpHeader::*;
use etherparse::TransportHeader::*;
use json;

///////////////
// CONSTANTS //
///////////////
const SUPPORTED_HTTP_REQUESTS: [&str; 2] = ["POST", "GET"]; // Supported HTTP requests
const SUPPORTED_HTTP_RESPONSES: [&str; 2] = ["200", "404"]; // Supported HTTP responses
const INVALID_DELIMITER_CHARS: [&str; 10] = ["\"", "\\", "'", "`", "{", "}", "(", ")", "[", "]"]; // Disallowed characters in output delimiter
const MAX_DELIMITER_LEN: usize = 3; // Maximum number of characters allowed in output delimiter

/////////////
// STRUCTS //
/////////////
#[derive(Debug, Clone)] // TODO
struct CacheEntry {
    ts: SystemTime, // Last touched timestamp
    seq: Option<u32>, // TCP sequence number for reassembly
    data: Option<Vec<u8>>, // TCP fragment for reassembly
    stale: bool, // Entry can be deleted at next cleanup
}

///////////////
// FUNCTIONS //
///////////////

///////////////////////
// GENERAL FUNCTIONS //
///////////////////////

// Die gracefully
fn euthanize() {
    info!("Ctrl-C exiting");
    // TODO
    std::process::exit(0);
}

// Derives a cache key from unique pairing of values
fn derive_cache_key(src_ip: &String, dst_ip: &String, src_port: &u16, dst_port: &u16) -> String {
    let delim = "_".to_string();
    let mut key = src_ip.clone();
    key.push_str(&delim);
    key.push_str(&dst_ip);
    key.push_str(&delim);
    key.push_str(&src_port.to_string());
    key.push_str(&delim);
    key.push_str(&dst_port.to_string());
    key
}

/////////////////////////
// Argument Validators //
/////////////////////////

// Check if capture device exists and can be put into promisc mode
fn val_iface(iface: String) -> Result<(), String> {
    match Device::list().unwrap().iter().find(|x| x.name == iface) {
        Some(_) => { },
        _ => return Err(String::from("Invalid capture interface. Make sure you are root.")),
    }
    match Capture::from_device(iface.as_str()).unwrap().promisc(true).rfmon(false).open() {
        Ok(_) => { },
        _ => return Err(String::from("Unable to open capture interface in promisc mode. Make sure you are root.")),
    }
    Ok(())
}

// Check if val is valid number between umin and umax
fn val_range(val: &String, umin: u32, umax: u32) -> Result<(), String> {
    if !val.is_ascii() {
        return Err(String::from("not ascii"));
    }
    for cc in val.chars() {
        if !cc.is_numeric() {
            return Err(String::from("not number"));
        }
    }
    let num = val.chars().fold(0, |acc, c| c.to_digit(10).unwrap_or(0) + acc);
    if num > umax || num < umin {
        return Err(String::from("out of range"));
    }
    Ok(())
}

// Check if chop is between 1 and 1500
fn val_chop(chop: String) -> Result<(), String> {
    return val_range(&chop, 1, 1500);
}

// Port must be a number between 1 and 65535
fn val_port(port: String) -> Result<(), String> {
    return val_range(&port, 1, 65535);
}

fn val_delim(delim: String) -> Result<(), String> {
    if !delim.is_ascii() {
        return Err(String::from("invalid delimiter"));
    }
    if delim.len() > MAX_DELIMITER_LEN {
        return Err(String::from("too many characters in delimiter"));
    }
    if INVALID_DELIMITER_CHARS.iter().any(|&x| delim.contains(x)) {
        return Err(String::from("invalid character in delimiter"));
    }
    Ok(())
}

fn val_requests(request: String) -> Result<(), String> {
    if !SUPPORTED_HTTP_REQUESTS.contains(&request.as_str()) {
        return Err(String::from("unsupported request method"));
    }
    Ok(())
}

fn val_responses(response: String) -> Result<(), String> {
    if !SUPPORTED_HTTP_RESPONSES.contains(&response.as_str()) {
        return Err(String::from("unsupported response code"));
    }
    Ok(())
}

///////////////////////
// DISPLAY FUNCTIONS //
///////////////////////

// Returns display formatted string for ipv4 address
fn ipv4_display(ip: &[u8;4]) -> String {
    return ip.iter().map(|x| format!(".{}", x)).collect::<String>().split_off(1);
}

// Prints pretty hex representation of passed slice
fn hex_print(data: &[u8]) {
    let mut pos:usize = 0;
    let mut row:usize = 0;
    let mut out:String = "0000 ".to_string();
    let mut decoded:String = "".to_string();

    for byte in data {
        if pos != 0 && pos % 16 == 0 {
            println!("{} {}", out, decoded);
            row = row + 1;
            out = format!("{:0>4X} ", row);
            decoded = "".to_string();
        }else if pos != 0 && pos % 8 == 0 {
            out.push_str(" ");
        }

        out.push_str(&format!(" {:0>2X}", &byte));
        if byte.is_ascii_alphanumeric() || byte.is_ascii_punctuation() {
            decoded.push_str(&String::from_utf8(vec![*byte]).expect("Error converting 8-bit value to ASCII"));
        }else if byte.is_ascii_whitespace() {
            decoded.push_str(" ");
        }else{
            decoded.push_str(".");
        }
        pos = pos + 1;
    }
    println!("{} {}", format!("{:<54}", &out), decoded);
}

////////////////////
// HTTP FUNCTIONS //
////////////////////
// Init the packet parsing
// Handles TCP reconstruction and cache entries
fn init_pkt_parse(cache: &Arc<RwLock<HashMap<String, CacheEntry>>>, cli_opts: &clap::ArgMatches,
                  ipv4_hdr: &etherparse::Ipv4Header, tcp_hdr: &etherparse::TcpHeader, payload: &[u8]) {

    let key = derive_cache_key(&ipv4_display(&ipv4_hdr.source),
                               &ipv4_display(&ipv4_hdr.destination),
                               &tcp_hdr.source_port,
                               &tcp_hdr.destination_port);

    let mut data: Vec<u8> = Vec::new();
    if cache.read().contains_key(&key) && !cache.read().get(&key).unwrap().stale {
        debug!("We've seen you before!");
        if let Some(entry) = cache.write().get_mut(&key) {
            if entry.stale {
                debug!("Entry marked not stale now stale");
                return;
            }
            if entry.seq.unwrap() != tcp_hdr.sequence_number {
                debug!("Out-0f-order TCP packets detected, message lost");
                return;
            }
            data = entry.data.clone().unwrap();
        }
        data.extend_from_slice(&payload);
    } else {
        data = payload.clone().to_vec();
    }

    let mut output: String = String::from(""); // output buffer for printing

    let mut http_headers = [httparse::EMPTY_HEADER; 16];
    if cli_opts.is_present("requests") {
        let mut req_found = false;
        for req in cli_opts.values_of("requests").unwrap() { // Does beginning of payload represent a valid request?
            if req.len() >= payload.len() {
                warn!("Invalid request: Payload truncated");
                return;
            }
            match String::from_utf8(payload[0..req.len()].to_vec()) {
                Err(_) => return,
                Ok(s) => {
                    if s == req {
                        debug!("HTTP request found");
                        req_found = true;
                    }
                }
            }
        }
        if !req_found { return; }

        let mut req = httparse::Request::new(&mut http_headers);
        match req.parse(&data) {
            Err(err) => {
                warn!("Error parsing HTTP request {:?}", err);
                return
            },
            Ok(status) => {
                if status.is_complete() {
                    if let Some(entry) = cache.write().get_mut(&key) {
                        entry.stale = true;
                        entry.ts = SystemTime::now();
                    }
                    //debug!("Parsed HTTP {:#?}", req);

                    // Check if we care about this method type
                    if !cli_opts.values_of("requests").unwrap().
                        into_iter().any(|x| x == req.method.unwrap()) { return }

                    // Deal with headers
                    let mut req_content_type: String = String::from("");
                    let mut req_content_len: usize = 0;
                    for req_head in req.headers.iter() {
                        if req_head.name.to_lowercase() == "content-type" {
                            match String::from_utf8(req_head.value.to_vec()) {
                                Err(err) => error!("Error converting 8-bit value to ASCII {:?}", err),
                                Ok(val) => {
                                    if val.to_lowercase().contains("json") {
                                        req_content_type = val.clone();
                                    }
                                }
                            }
                        }
                        if req_head.name.to_lowercase() == "content-length" {
                            match String::from_utf8(req_head.value.to_vec()) {
                                Err(err) => error!("Error converting 8-bit value to ASCII {:?}", err),
                                Ok(val) => {
                                    match val.parse::<usize>() {
                                        Err(err) => error!("Bad HTTP content-length {:?}", err),
                                        Ok(length) => {
                                            if length < payload.len() {
                                                req_content_len = length.clone();
                                            }else{
                                                warn!("Invalid http content-length, ignoring request");
                                                return;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Capture headers
                        if cli_opts.is_present("headers") {
                            for cli_head in cli_opts.values_of("headers").unwrap() {
                                if req_head.name.to_lowercase() == cli_head.to_lowercase() {
                                    match String::from_utf8(req_head.value.to_vec()) {
                                        Err(err) => error!("Error converting http header to ASCII {:?}", err),
                                        Ok(val) => {
                                            if cli_opts.is_present("line") {
                                                output.push_str(&val);
                                                output.push_str(&cli_opts.value_of("delim").unwrap());
                                            }else{
                                                //debug!("head_{:?}: {:?}", cli_head, val);
                                                output.push_str(&format!("head_{}: {}\n", req_head.name, val));
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    // capture JSON tags
                    if cli_opts.is_present("json") && req_content_type.contains("json") && req_content_len != 0 {
                        let content = payload[payload.len() - req_content_len..].to_vec();
                        match String::from_utf8(content) {
                            Err(_) => error!("Error converting 8-bit http content to ASCII"),
                            Ok(ascii) => {
                                match json::parse(&ascii) {
                                    Err(err) => error!("JSON parsing error {:?}", err),
                                    Ok(json) => {
                                        //debug!("{:#?}", json);
                                        for cli_json in cli_opts.values_of("json").unwrap() {
                                            if json.has_key(&cli_json) {
                                                let json_val: String;
                                                if json[cli_json].is_string() {
                                                    //debug!("json_{:?}: {:?}", cli_json, json[cli_json].as_str().unwrap().to_string());
                                                    json_val = json[cli_json].as_str().unwrap().to_string();
                                                }else if json[cli_json].is_boolean() {
                                                    if json[cli_json].as_bool().unwrap() {
                                                        json_val = "true".to_string();
                                                    }else{
                                                        json_val = "false".to_string();
                                                    }
                                                }else if json[cli_json].is_number() {
                                                    json_val = json[cli_json].to_string();
                                                }else{
                                                    continue;
                                                }
                                                if cli_opts.is_present("line") {
                                                    output.push_str(&json_val);
                                                    output.push_str(&cli_opts.value_of("delim").unwrap());
                                                }else{
                                                    output.push_str(&format!("json_{}: {}\n", cli_json, json_val));
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                }else{ // if status.is_complete()
                    if cache.read().contains_key(&key) {
                        debug!("Updating existing cache entry: {:?}", key);
                        if let Some(entry) = cache.write().get_mut(&key) {
                            entry.ts = SystemTime::now();
                            entry.seq =  Some(tcp_hdr.sequence_number + payload.len() as u32);
                            entry.data = Some(data.to_vec());
                            entry.stale = false;
                        }else{
                            panic!("Failed to update cache");
                        }
                    }else{
                        debug!("Creating new cache entry: {:?}", key);
                        cache.write().insert(key, CacheEntry {
                            ts: SystemTime::now(),
                            seq: Some(tcp_hdr.sequence_number + payload.len() as u32),
                            data: Some(data.to_vec()),
                            stale: false,
                        });
                    }
                }
            }
        }
    }else{ // Assume cli_opts.is_present("responses")
        let mut resp = httparse::Response::new(&mut http_headers);
        match resp.parse(&data) {
            Err(err) => {
                warn!("Error parsing HTTP response {:?}", err);
                return;
            },
            Ok(status) => {
                if status.is_complete() { // do more here
                    debug!("Successful parse");
                    if let Some(entry) = cache.write().get_mut(&key) {
                        entry.stale = true;
                        entry.ts = SystemTime::now();
                    }
                    // TODO: handle responses here
                }else{
                    if cache.read().contains_key(&key) {
                        debug!("Updating existing cache entry: {:?}", key);
                        if let Some(entry) = cache.write().get_mut(&key) {
                            entry.ts = SystemTime::now();
                            entry.seq =  Some(tcp_hdr.sequence_number + payload.len() as u32);
                            entry.data = Some(data.to_vec());
                            entry.stale = false;
                        }else{
                            panic!("Failed to update cache");
                        }
                    }else{
                        debug!("Creating new cache entry: {:?}", key);
                        cache.write().insert(key, CacheEntry {
                            ts: SystemTime::now(),
                            seq: Some(tcp_hdr.sequence_number + payload.len() as u32),
                            data: Some(data.to_vec()),
                            stale: false,
                        });
                    }
                }
            }
        }
    }

    // finalize output and print
    if cli_opts.is_present("line") {
        output = output.trim_end_matches(cli_opts.value_of("delim").unwrap()).to_string();
        if cli_opts.is_present("timestamp") {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(ts) => output.insert_str(0, &format!("{}{}", ts.as_secs(), cli_opts.value_of("delim").unwrap())),
                Err(err) => {
                    error!("Error generating timestamp from system time {:?}", err);
                    output.insert_str(0, cli_opts.value_of("delim").unwrap());
                }
            }
        }
    }else{
        if cli_opts.is_present("timestamp") {
            match SystemTime::now().duration_since(UNIX_EPOCH) {
                Ok(ts) => output.insert_str(0, &format!("ts: {}: \n", ts.as_secs())),
                Err(err) => {
                    error!("Error generating timestamp from system time {:?}", err);
                    output.insert_str(0, "ts: \n");
                }
            }
        }
    }
    println!("{}", output);
}

/////////////////////////////
// BEGIN PROGRAM EXECUTION //
/////////////////////////////
fn main() {
    env_logger::builder().default_format_timestamp(false).init();
    debug!("Start");

    let cli_opts = App::new("skarfhttp")
        .version("0.1")
        .author("Andrew McConachie <andrew@depht.com>")
        .about("Skarf some HTTP")
        .arg(Arg::with_name("chop")
             .help("Chop BYTES from beginning of every packet")
             .short("C")
             .long("chop")
             .value_name("bytes")
             .takes_value(true)
             .validator(val_chop)
             .required(false))
        .arg(Arg::with_name("iface")
             .help("pcap interface to listen on, typically a network interface")
             .short("i")
             .long("iface")
             .value_name("interface")
             .takes_value(true)
             .validator(val_iface)
             .required(true))
        .arg(Arg::with_name("port")
             .help("TCP port for bpf")
             .short("p")
             .long("port")
             .value_name("port")
             .takes_value(true)
             .validator(val_port)
             .default_value("80")
             .required(false))
        .arg(Arg::with_name("headers")
             .help("Lowercase list of HTTP headers to print e.g. user-agent,cookie")
             .short("h")
             .long("headers")
             .takes_value(true)
             .use_delimiter(true)
             .required(false))
        .arg(Arg::with_name("json")
             .help("When content-type includes string 'json', print [boolean|number|string] values of these json keys")
             .short("j")
             .long("json")
             .value_name("keys")
             .takes_value(true)
             .require_delimiter(true)
             .requires("requests")
             .required(false))
        .arg(Arg::with_name("line")
             .help("print all output on one delimited line")
             .short("l")
             .long("line-output")
             .takes_value(false)
             .required(false))
        .arg(Arg::with_name("delim")
             .help("Use custom delimiter in single line output")
             .short("d")
             .long("delimiter")
             .value_name("delimiter")
             .takes_value(true)
             .validator(val_delim)
             .default_value(",")
             .requires("line")
             .required(false))
        .arg(Arg::with_name("timestamp")
             .help("prepend 64-bit UNIX timestemp to output")
             .short("t")
             .long("timestamp")
             .takes_value(false)
             .required(false))
        .arg(Arg::with_name("requests")
             .help("List of request methods to match e.g. GET,POST")
             .short("q")
             .long("requests")
             .takes_value(true)
             .validator(val_requests)
             .require_delimiter(true))
        .arg(Arg::with_name("responses")
             .help("List of response statuses to match e.g. 200,404")
             .short("s")
             .long("responses")
             .takes_value(true)
             .validator(val_responses)
             .require_delimiter(true))
        .group(ArgGroup::with_name("direction")
               .args(&["requests", "responses"])
               .required(true))
        .get_matches();

    if cli_opts.is_present("requests") {
        debug!("Skarfing HTTP requests {:?}", cli_opts.values_of("requests").unwrap().
               into_iter().map(|s| format!("{:},", s)).collect::<String>().trim_end_matches(","));
    }else{
        debug!("Skarfing HTTP responses {:?}", cli_opts.values_of("responses").unwrap().
               into_iter().map(|s| format!("{:},", s)).collect::<String>().trim_end_matches(","));
    }

    ctrlc::set_handler(move || {
        euthanize();
    }).expect("Error setting Ctrl-C handler");

    let mut threads = vec![]; // Our threads

    // Setup our cache
    let cache = Arc::new(RwLock::new(HashMap::<String, CacheEntry>::new()));

    let listen_thr = thread::Builder::new().name("listen_thr".to_string()).spawn(move || {
        let bpf = format!("tcp port {}", cli_opts.value_of("port").unwrap());
        debug!("filter {:?}", bpf);

        let mut capture = Capture::from_device(cli_opts.value_of("iface").unwrap()).unwrap()
            .promisc(true)
            .rfmon(false)
            //.timeout(10)
            //.snaplen(65535)
            .open().unwrap();
        match capture.filter(&bpf){
            Ok(_) => (),
            Err(err) => error!("BPF error {}", err.to_string()),
        }

        debug!("{:?} opened in promiscious mode", cli_opts.value_of("iface").unwrap());
        loop {
            match capture.next() {
                Err(err) => {
                    error!("capture error {:?}", err);
                    break;
                },
                Ok(raw_pkt) => {
                    /* pcap/Etherparse strips the Ethernet FCS before it hands the packet to us.
                    So a 60 byte packet was 64 bytes on the wire.
                    Etherparse interprets any Ethernet padding as TCP data. I consider this a bug.
                    Therefore, we ignore any packet 60 bytes or less to prevent us from storing erroneous TCP payloads.
                    The chances of us actually needing that small of a packet are close to zero. */
                    if raw_pkt.len() <= 60 {
                        continue;
                    }

                    //debug!("Everything");
                    //hex_print(&raw_pkt.data);
                    let mut packet = raw_pkt.clone();
                    if cli_opts.is_present("chop") {
                        let num = cli_opts.value_of("chop").unwrap().chars().fold(0, |acc, c| c.to_digit(10).unwrap_or(0) + acc);
                        if (num as usize) > raw_pkt.data.len() {
                            warn!("chop is larger than captured packet");
                            continue
                        } else {
                            match raw_pkt.data.get(num as usize..) {
                                Some(new_data) => packet.data = new_data,
                                _ => {
                                    warn!("Error chopping packet");
                                    continue;
                                }
                            }
                        }
                    }

                    match PacketHeaders::from_ethernet_slice(&packet) {
                        Err(err) => {
                            debug!("Failed to decode pkt as ethernet {:?}", err);
                            match PacketHeaders::from_ip_slice(&packet) {
                                Err(err) => debug!("Failed to decode pkt as IP {:?}", err),
                                Ok(pkt) => match pkt.ip.unwrap() {
                                    Version6(_) => warn!("IPv6 packet captured, but IPv4 expected"),
                                    Version4(ipv4) => {
                                        //debug!("Everything: {:?}", pkt);
                                        match pkt.transport.unwrap() {
                                            Udp(_) => warn!("UDP transport captured when TCP expected"),
                                            Tcp(tcp) => {
                                                if pkt.payload.len() > 0 {
                                                    debug!("Calling init_pkt_parse");
                                                    init_pkt_parse(&cache, &cli_opts, &ipv4, &tcp, &pkt.payload);
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Ok(pkt) => {
                            match pkt.ip.unwrap() {
                                Version6(_) => warn!("IPv6 packet captured, but IPv4 expected"),
                                Version4(ipv4) => {
                                    match pkt.transport.unwrap() {
                                        Udp(_) => warn!("UDP transport captured when TCP expected"),
                                        Tcp(tcp) => {
                                            if pkt.payload.len() > 0 {
                                                debug!("Calling init_pkt_parse");
                                                init_pkt_parse(&cache, &cli_opts, &ipv4, &tcp, &pkt.payload);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }).unwrap();
    threads.push(listen_thr);

    for thr in threads {
        thr.join().expect("Couldn't join the thread");
    }

    debug!("Finish");
}
