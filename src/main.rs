extern crate libc;
extern crate rustc_serialize;

use std::hash::{Hash, Hasher, SipHasher};

use rustc_serialize::json;

mod util;
mod pcap;
mod ether;
mod ip;

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

fn main() {
    let pcap = pcap::PcapFile::open("/data/many-flow.pcap");

    for pkt in pcap.take(16) {
        let inner = ether::read_inner_packet(&pkt.bytes);
        let ip = ip::V4Packet::new(inner);

        let hash = hash_u32(ip.src()) ^ hash_u32(ip.dst());

        println!("# {}.{} 0x{:X} (0x{:X} -> 0x{:X})",
                 pkt.header.ts.tv_sec, pkt.header.ts.tv_usec,
                 hash, ip.src(), ip.dst());
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
