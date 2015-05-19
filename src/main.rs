extern crate libc;
extern crate rustc_serialize;
extern crate bounded_spsc_queue;

use std::env;
use std::str;
use std::hash::{Hash, Hasher, SipHasher};
use std::thread;
use std::sync::{Arc, RwLock};

use bounded_spsc_queue::{Producer,Consumer};
use rustc_serialize::json;

mod util;
mod pcap;
mod ether;
mod ip;

use pcap::Packet;

// Automatically generate `RustcDecodable` and `RustcEncodable` trait
// implementations
#[derive(RustcDecodable, RustcEncodable)]
pub struct TestStruct  {
    data_int: u8,
    data_str: String,
    data_vector: Vec<u8>,
}

fn hash_u32(i: u32) -> u64 {
    let mut hasher = SipHasher::new();
    i.hash(&mut hasher);
    return hasher.finish();
}

fn to_str<'a>(s: &'a String) -> &'a str {
    str::from_utf8(s.as_bytes()).unwrap()
}

const QUEUE_SIZE : usize = 256 * 1024;

struct Writer {
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
        let readFin = fin.clone();

        let datalink = input.datalink();
        let snaplen = input.snaplen();

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

        Writer { thread: thread, queue: producer }
    }).collect();

    let mut count = 0;
    for pkt in input {
        let hash = {
            let inner = ether::read_inner_packet(&pkt.bytes);
            let ip = ip::V4Packet::new(inner);

            hash_u32(ip.src()) ^ hash_u32(ip.dst())
        };

        let ix: usize = (hash % (writers.len() as u64)) as usize;

        count += 1;
        writers[ix].queue.push(pkt);
    }

    {
        let mut ended = fin.write().unwrap();
        *ended = true;
    }

    for writer in writers {
        writer.thread.join();
    }

    let object = TestStruct {
        data_int: 1,
        data_str: "homura".to_string(),
        data_vector: vec![2,3,4,5],
    };

    // Serialize using `json::encode`
    let encoded = json::encode(&object).unwrap();

    println!("encoded {}", encoded);
}
