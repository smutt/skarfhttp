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
//use std::{iter, time, thread};
use std::time::{SystemTime};
use std::sync::Arc;
use parking_lot::RwLock;
use std::collections::HashMap;
use pcap::{Capture, Device};
//use etherparse::PacketHeaders;
//use etherparse::IpHeader::*;
//use etherparse::TransportHeader::*;
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

fn val_iface(iface: String) -> Result<(), String> {
    // Check if capture device exists
    match Device::list().unwrap().iter().find(|x| x.name == iface) {
        Some(_) => { },
        _ => return Err(String::from("Invalid capture interface")),
    }
    // Check if we can capture promiscuously, will fail if not root
/*    match Capture::from_device(&iface).unwrap().promisc(true).rfmon(false).open() {
        Ok(_) => debug!("test success, {:?} opened in promisc mode", iface),
        _ => return Err(String::from("Unable to open capture interface in promisc mode. Make sure you are root.")),
    }*/
    Ok(())
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

    //    let mut threads = vec![]; // Our threads

    // Setup our caches
    let cache = Arc::new(RwLock::new(HashMap::<String, CacheEntry>::new()));

    /*
    let listen_thr = thread::Builder::new().name("server_4".to_string()).spawn(move || {
        let bpf = format!("tcp port {}", &cli_opts.port);

        let mut capture = Capture::from_device(Opt::from_args().iface.as_str()).unwrap()
            .promisc(true)
            .rfmon(false)
            .open().unwrap();
        match capture.filter(bpf_server_4){
            Ok(_) => (),
            Err(err) => error!("BPF error {}", err.to_string()),
        }

        while let Ok(packet) = capture.next() {
            debug!("Investigating server_cache_v4 staleness {:?}", server_cache_v4.read().len());
            let mut stale = Vec::new();
            for (key,entry) in server_cache_v4.read().iter() {
                if entry.stale {
                    if entry.ts < SystemTime::now() - Duration::new(CACHE_MIN_STALENESS, 0) {
                        stale.push(key.clone());
                        debug!("Found stale server_cache_v4 entry {:?}", key);
                    }
                }
            }
            for key in stale.iter() {
                server_cache_v4.write().remove(key);
                debug!("Deleted stale server_cache_v4 entry {:?}", key);
            }
            drop(stale);

            /* pcap/Etherparse strips the Ethernet FCS before it hands the packet to us.
            So a 60 byte packet was 64 bytes on the wire.
            Etherparse interprets any Ethernet padding as TCP data. I consider this a bug.
            Therefore, we ignore any packet 60 bytes or less to prevent us from storing erroneous TCP payloads.
            The chances of us actually needing that small of a packet are close to zero. */
            if packet.len() <= 60 {
                continue;
            }

            let pkt = PacketHeaders::from_ethernet_slice(&packet).expect("Failed to decode packet in server_4_thr");
            //debug!("Everything: {:?}", pkt);

            match pkt.ip.unwrap() {
                Version6(_) => {
                    warn!("IPv6 packet captured, but IPv4 expected");
                    continue;
                }
                Version4(ipv4) => {
                    match pkt.transport.unwrap() {
                        Udp(_) => warn!("UDP transport captured when TCP expected"),
                        Tcp(tcp) => {
                            //debug!("resp_tcp_seq: {:?}", tcp.sequence_number);
                            //debug!("payload_len: {:?}", pkt.payload.len());
                            parse_server_hello(&acl_cache_v4_srv, &client_cache_v4_srv, &server_cache_v4,
                                               ipv4::new(ipv4_display(&ipv4.source)).unwrap(),
                                               ipv4::new(ipv4_display(&ipv4.destination)).unwrap(),
                                               tcp, pkt.payload);
                        }
                    }
                }
            }
        }
    }).unwrap();
    threads.push(listen_4_thr);


    for thr in threads {
        thr.join().unwrap();
    }
     */
    debug!("Finish");
}
