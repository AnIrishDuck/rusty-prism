extern crate libc;
extern crate rustc_serialize;
extern crate bounded_spsc_queue;

use std::env;
use std::str;
use std::hash::{Hash, Hasher, SipHasher};
use std::thread;
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::sync::{Arc, RwLock};

use bounded_spsc_queue::{Producer,Consumer};
use rustc_serialize::json;
use rustc_serialize::json::{Json, ToJson};

mod util;
mod pcap;
mod ether;
mod ip;

use pcap::Packet;

fn hash_u32(i: u32) -> u64 {
    let mut hasher = SipHasher::new();
    i.hash(&mut hasher);
    return hasher.finish();
}

fn to_str<'a>(s: &'a String) -> &'a str {
    str::from_utf8(s.as_bytes()).unwrap()
}

#[derive(RustcDecodable, RustcEncodable, Clone, Copy, PartialEq)]
struct Stats {
    capacity: usize,
    rx_frames: u64
}

type Status = Vec<(String, Stats)>;

const QUEUE_SIZE : usize = 256 * 1024;

struct Writer {
    path: String,
    thread: thread::JoinHandle<()>,
    queue: Producer<Packet>
}

fn main() {
    let mut args = env::args();
    args.next(); // shift off program name
    let input = pcap::read(to_str(&args.next().unwrap()));

    let fin = Arc::new(RwLock::new(false));

    let writers: Vec<_> = args.map(|path| {
        let (producer, consumer) = bounded_spsc_queue::make::<Packet>(QUEUE_SIZE);

        let datalink = input.datalink();
        let snaplen = input.snaplen();

        let readFin = fin.clone();
        let writerPath = path.clone();

        let thread = thread::spawn(move || {
            let f = pcap::write(to_str(&path), datalink, snaplen);

            let try_write = || {
                match consumer.try_pop() {
                    Some(pkt) => { f.write(&pkt); true }
                    None      => false
                }
            };

            while !*readFin.read().unwrap() {
                if !try_write() {
                    thread::sleep_ms(1);
                }
            }

            // flush backlog
            while try_write() { }
        });

        Writer { thread: thread, queue: producer, path: writerPath }
    }).collect();

    let (tx_status, rx_status) = bounded_spsc_queue::make::<Status>(1);
    let mut status = BTreeMap::from_iter(writers.iter().map(|w| {
        (w.path.clone(), Stats { capacity: w.queue.free_space(), rx_frames: 0 })
    }));

    let status_fin = fin.clone();
    let status_thread = thread::spawn(move || {
        status_main(rx_status, status_fin);
    });

    let mut count = 0;
    for pkt in input {
        let hash = {
            let inner = ether::read_inner_packet(&pkt.bytes);
            let ip = ip::V4Packet::new(inner);

            hash_u32(ip.src()) ^ hash_u32(ip.dst())
        };

        let ix: usize = (hash % (writers.len() as u64)) as usize;
        let ref writer = writers[ix];

        writer.queue.push(pkt);

        {
            let mut stats = status.get_mut(&writer.path).unwrap();
            stats.rx_frames += 1;
            count += 1;
        }

        if count & 0xFF == 0 {
            let i = status.iter().map(|(path, stats)| {
                (path.clone(), *stats)
            });
            let current_status: Vec<(String, Stats)> = i.collect();

            tx_status.push(current_status);
        }
    }

    {
        let mut ended = fin.write().unwrap();
        *ended = true;
    }

    for writer in writers {
        writer.thread.join();
    }
    status_thread.join();
}

fn status_main(rx: Consumer<Status>, fin: Arc<RwLock<bool>>) {
    let write_status = |status: Status| {
        let iter = status.iter().map(|pair| {
            let (ref path, ref stats) = *pair;
            (path.clone(), *stats)
        });
        let status: BTreeMap<String, Stats> = BTreeMap::from_iter(iter);

        println!("status {}", json::encode(&status).unwrap());
    };

    while !*fin.read().unwrap() {
        match rx.try_pop() {
            Some(status) => {
                write_status(status);
            },
            None => {
                thread::sleep_ms(1000);
            }
        }
    }
}
