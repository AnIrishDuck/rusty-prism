extern crate libc;
extern crate rustc_serialize;

mod pcap;

use std::ptr;
use rustc_serialize::json;

// Automatically generate `RustcDecodable` and `RustcEncodable` trait
// implementations
#[derive(RustcDecodable, RustcEncodable)]
pub struct TestStruct  {
    data_int: u8,
    data_str: String,
    data_vector: Vec<u8>,
}

fn main() {
    let pcap = pcap::PcapFile::open("/data/many-flow.pcap");

    for pkt in pcap {
        println!("# {}.{}", pkt.header.ts.tv_sec, pkt.header.ts.tv_usec);
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
