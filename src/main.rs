extern crate libc;
extern crate rustc_serialize;
extern crate bounded_spsc_queue;

use std::env;
use std::str;
use std::hash::{Hash, Hasher, SipHasher};
use std::thread;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Write;
use std::iter::FromIterator;
use std::sync::{Arc, RwLock};
use std::sync::atomic::{AtomicUsize, Ordering};

use bounded_spsc_queue::Producer;
use rustc_serialize::json::{Json, ToJson};

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

struct Stats {
    capacity: AtomicUsize,
    rx_frames: AtomicUsize
}

impl ToJson for Stats {
    fn to_json(&self) -> Json {
        let items = vec![("capacity", &self.capacity),
                         ("rx_frames", &self.rx_frames)];

        Json::Object(BTreeMap::from_iter(items.iter().map(|&(s, aus)| {
            (s.to_string(), aus.load(Ordering::Relaxed).to_json())
        })))
    }
}

type Status = Vec<Stats>;

const QUEUE_SIZE : usize = 256 * 1024;

struct Writer {
    thread: thread::JoinHandle<()>,
    queue: Producer<Packet>
}

fn main() {
    let mut args = env::args();
    args.next(); // shift off program name

    let status_path = args.next().unwrap();
    let input_path = args.next().unwrap();
    let paths: Vec<_> = args.collect();

    split(status_path, input_path, paths);
}

/// Program entry point. Takes parsed cli arguments and runs the main threads.
#[allow(unused_variables)]
pub fn split(status_path: String, input_path: String, paths: Vec<String>) {
    let input = pcap::read(to_str(&input_path));

    let fin = Arc::new(RwLock::new(false));

    let writers: Vec<_> = paths.iter().map(|path| {
        create_writer(path.clone(), fin.clone(), &input)
    }).collect();

    let local_status: Arc<Vec<_>> = Arc::new(writers.iter().map(|w| {
        Stats { capacity: AtomicUsize::new(QUEUE_SIZE),
                rx_frames: AtomicUsize::new(0) }
    }).collect());

    let status = create_status(status_path, local_status.clone(), paths,
                               fin.clone());

    for pkt in input {
        let hash = {
            let inner = ether::read_inner_packet(&pkt.bytes);
            let ip = ip::V4Packet::new(inner);

            hash_u32(ip.src()) ^ hash_u32(ip.dst())
        };

        let ix: usize = (hash % (writers.len() as u64)) as usize;
        let ref writer = writers[ix];
        writer.queue.push(pkt);

        let ref stats = local_status[ix];
        stats.rx_frames.fetch_add(1, Ordering::Relaxed);
        stats.capacity.store(writer.queue.free_space(), Ordering::Relaxed);
    }

    {
        let mut ended = fin.write().unwrap();
        *ended = true;
    }

    for writer in writers {
        writer.thread.join().unwrap();
    }
    status.join().unwrap();
}

/// Creates the thread that periodically writes stats to a JSON file.
fn create_status(path: String, status: Arc<Status>, names: Vec<String>,
                 fin: Arc<RwLock<bool>>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let write_status = || {
            let iter = names.iter().zip(status.iter()).map(|pair| {
                let (ref path, stats) = pair;
                ((*path).clone(), stats.to_json())
            });
            let status: BTreeMap<String, Json> = BTreeMap::from_iter(iter);
            let json = status.to_json();

            let mut file = File::create(&path).unwrap();
            write!(file, "{}\n", &json.pretty()).unwrap();
        };

        while !*fin.read().unwrap() {
            write_status();
            thread::sleep_ms(100);
        }
        write_status();
    })
}

/// Creates an individual pcap writer thread.
fn create_writer(path: String, fin: Arc<RwLock<bool>>,
                 input: &pcap::PcapFileReader) -> Writer {
    let (producer, consumer) = bounded_spsc_queue::make::<Packet>(QUEUE_SIZE);

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

        while !*fin.read().unwrap() {
            if !try_write() {
                thread::sleep_ms(1);
            }
        }

        // flush backlog
        while try_write() { }

        f.close();
    });

    Writer { thread: thread, queue: producer }
}

#[cfg(test)]
mod tests {
    extern crate tempdir;

    use super::*;
    use self::tempdir::TempDir;

    use pcap;

    fn pcap_count(path: &str) -> usize {
        let input = pcap::read(path);
        input.count()
    }

    #[test]
    fn keeps_single_flow_together() {
        let tmp = TempDir::new("rusty-prism").unwrap();
        let tmp_path = tmp.path();

        let original = "data/one-flow.pcap";
        let one_path = tmp_path.join("1.pcap");
        let two_path = tmp_path.join("2.pcap");

        let one = one_path.to_str().unwrap();
        let two = two_path.to_str().unwrap();

        split("stats.json".to_string(),
              original.to_string(),
              vec![one.to_string(), two.to_string()]);

        assert!(pcap_count(one) == 0 || pcap_count(two) == 0);
        assert_eq!(pcap_count(one) + pcap_count(two), pcap_count(original));
    }

    #[test]
    fn splits_many_flows() {
        let tmp = TempDir::new("rusty-prism").unwrap();
        let tmp_path = tmp.path();

        let original = "data/many-flows.pcap";
        let one_path = tmp_path.join("1.pcap");
        let two_path = tmp_path.join("2.pcap");

        let one = one_path.to_str().unwrap();
        let two = two_path.to_str().unwrap();


        split("stats.json".to_string(),
              original.to_string(),
              vec![one.to_string(), two.to_string()]);

        assert!(pcap_count(one) != 0);
        assert!(pcap_count(two) != 0);
        assert_eq!(pcap_count(one) + pcap_count(two), pcap_count(original));
    }
}
