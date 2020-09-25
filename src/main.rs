/*
Copyright (c) 2020, Andrew McConachie <andrew@depht.com>
All rights reserved.
 */

//////////////
// INCLUDES //
//////////////
#[macro_use] extern crate log;
extern crate clap;
use clap::{Arg, App};
use std::thread;
use std::time::{SystemTime};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use pcap::{Capture, Device};
use etherparse::PacketHeaders;
use etherparse::IpHeader::*;
use etherparse::TransportHeader::*;
//use ipaddress::ipv4;

///////////////
// CONSTANTS //
///////////////

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

/////////////////////////
// Argument Validators //
/////////////////////////

// Check if capture device exists and can be put into promisc mode
fn val_iface(iface: String) -> Result<(), String> {
    match Device::list().unwrap().iter().find(|x| x.name == iface) {
        Some(_) => { },
        _ => return Err(String::from("Invalid capture interface")),
    }
    match Capture::from_device(iface.as_str()).unwrap().promisc(true).rfmon(false).open() {
        Ok(_) => debug!("test success, {:?} opened in promisc mode", iface),
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



///////////////////////
// GENERAL FUNCTIONS //
///////////////////////

// Die gracefully
fn euthanize() {
    info!("Ctrl-C exiting");
    // TODO
    std::process::exit(0);
}
/*
// End execution quickly with message to stdout
fn cease(s: &str) {
    println!("{}", s);
    std::process::exit(0);
}

// Derives a cache key from unique pairing of values
fn derive_cache_key(src_ip: &ipaddress::IPAddress, dst_ip: &ipaddress::IPAddress, src_port: &u16, dst_port: &u16) -> String {
    let delim = "_".to_string();
    let mut key = src_ip.to_s();
    key.push_str(&delim);
    key.push_str(&dst_ip.to_s());
    key.push_str(&delim);
    key.push_str(&src_port.to_string());
    key.push_str(&delim);
    key.push_str(&dst_port.to_string());
    key
}

// Returns display formatted string for ipv4 address
fn ipv4_display(ip: &[u8;4]) -> String {
    return ip.iter().map(|x| format!(".{}", x)).collect::<String>().split_off(1);
}
*/
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
             .value_name("BYTES")
             .takes_value(true)
             .validator(val_chop)
             .required(false))
        .arg(Arg::with_name("dns")
             .help("extract DNS names from URLs")
             .short("d")
             .long("dns")
             .takes_value(false)
             .multiple(false))
        .arg(Arg::with_name("interface")
             .help("pcap interface to listen on, typically a network interface")
             .short("i")
             .long("iface")
             .value_name("IFACE")
             .takes_value(true)
             .validator(val_iface)
             .required(true))
        .arg(Arg::with_name("port")
             .help("TCP port for bpf filter")
             .short("p")
             .long("port")
             .value_name("PORT")
             .takes_value(true)
             .validator(val_port)
             .default_value("80"))
        .arg(Arg::with_name("headers")
             .help("List of HTTP headers to print e.g. server,date")
             .short("h")
             .long("headers")
             .takes_value(true)
             .use_delimiter(true))
        .arg(Arg::with_name("json")
             .help("When content type includes string 'json', print this json key from body")
             .short("j")
             .long("json")
             .value_name("KEY")
             .takes_value(true)
             .required(false)
             .multiple(false))
        .arg(Arg::with_name("requests")
             .help("List of request methods to match e.g. GET,POST")
             .short("q")
             .long("requests")
             .takes_value(true)
             .use_delimiter(true))
        .arg(Arg::with_name("responses")
             .help("List of response statuses to match e.g. 200,404")
             .short("s")
             .long("responses")
             .takes_value(true)
             .use_delimiter(true))
        .get_matches();

    ctrlc::set_handler(move || {
        euthanize();
    }).expect("Error setting Ctrl-C handler");

    let mut threads = vec![]; // Our threads

    // Setup our caches
    let _cache = Arc::new(RwLock::new(HashMap::<String, CacheEntry>::new()));

    let listen_thr = thread::Builder::new().name("listen_thr".to_string()).spawn(move || {
        let bpf = format!("tcp port {}", cli_opts.value_of("port").unwrap());

        let mut capture = Capture::from_device(cli_opts.value_of("iface").unwrap()).unwrap()
            .promisc(true)
            .rfmon(false)
            .open().unwrap();
        match capture.filter(&bpf){
            Ok(_) => (),
            Err(err) => error!("BPF error {}", err.to_string()),
        }

        while let Ok(mut packet) = capture.next() {
            /* pcap/Etherparse strips the Ethernet FCS before it hands the packet to us.
            So a 60 byte packet was 64 bytes on the wire.
            Etherparse interprets any Ethernet padding as TCP data. I consider this a bug.
            Therefore, we ignore any packet 60 bytes or less to prevent us from storing erroneous TCP payloads.
            The chances of us actually needing that small of a packet are close to zero. */
            if packet.len() <= 60 {
                continue;
            }

            if cli_opts.is_present("chop") {
                let num = cli_opts.value_of("chop").unwrap().chars().fold(0, |acc, c| c.to_digit(10).unwrap_or(0) + acc);
                if (num as usize) < packet.data.len() {
                    let new_data = packet.data.get(num as usize..);
                    if new_data == None {
                        warn!("Error chopping packet");
                        continue
                    } else {
                        packet.data = new_data.unwrap();
                    }
                } else {
                    warn!("chop is larger than captured packet");
                    continue
                }
            }

            match PacketHeaders::from_ethernet_slice(&packet) {
                Err(err) => {
                    debug!("Failed to decode pkt as ethernet {:?}", err);
                    match PacketHeaders::from_ip_slice(&packet) {
                        Err(err) => debug!("Failed to decode pkt as IP {:?}", err),
                        Ok(ip) => match ip.ip.unwrap() {
                            Version6(_) => warn!("IPv6 packet captured, but IPv4 expected"),
                            Version4(_) => {
                                //debug!("Everything: {:?}", pkt);
                                match ip.transport.unwrap() {
                                    Udp(_) => warn!("UDP transport captured when TCP expected"),
                                    Tcp(_tcp) => {
                                        info!("WIN!");
                                    }
                                }
                            }
                        }
                    }
                }
                Ok(pkt) => {
                    //debug!("Everything: {:?}", pkt);
                    match pkt.ip.unwrap() {
                        Version6(_) => warn!("IPv6 packet captured, but IPv4 expected"),
                        Version4(_ipv4) => {
                            match pkt.transport.unwrap() {
                                Udp(_) => warn!("UDP transport captured when TCP expected"),
                                Tcp(_tcp) => {
                                    info!("WIN!");
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
        thr.join().unwrap();
    }

    debug!("Finish");
}
