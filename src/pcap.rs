use libc::c_int;
use std::mem;
use std::ptr;
use std::str;
use std::ffi::CString;
use std::io::Read;

#[repr(C)]
pub struct timeval {
    pub tv_sec: i64,
    pub tv_usec: i64
}

#[repr(C)]
pub struct PacketHeader {
    pub ts: timeval,        /* time stamp */
    pub caplen: u32,        /* length of portion present */
    pub len: u32,           /* length this packet (off wire) */
}

pub type PcapCallback = extern fn(*mut u8, *const PacketHeader, *const u8);

// Used for libpcap types that are intentially opaque.
// stackoverflow.com/q/26699631/#comment41993111_26699631
type OpaquePointer = *const u8;

#[link(name = "pcap")]
extern {
    fn pcap_datalink(p: OpaquePointer) -> c_int;
    fn pcap_snapshot(p: OpaquePointer) -> c_int;
    fn pcap_open_dead(linktype: c_int, snaplen: c_int) -> OpaquePointer;
    fn pcap_dump_open(p: OpaquePointer, path: *const i8) -> OpaquePointer;
    fn pcap_dump(p: OpaquePointer,
                 hdr: *const PacketHeader,
                 pkt: *const u8) -> OpaquePointer;
    fn pcap_dump_close(p: OpaquePointer);

    fn pcap_open_offline(path: *const i8, err: *mut u8) -> OpaquePointer;
    fn pcap_loop(pcap: OpaquePointer, count: c_int,
                 cb: PcapCallback,
                 udata: *mut u8) -> c_int;
}

struct UserData {
    packet: Packet,
    filled: bool
}

extern fn cb(udata: *mut u8, hdr: *const PacketHeader, bytes: *const u8) {
    unsafe {
        let data: &mut UserData = mem::transmute(udata);

        data.filled = true;
        let target: &mut Packet = &mut data.packet;
        ptr::copy(bytes, target.bytes.as_mut_ptr(), 1500);
        ptr::copy(hdr, &mut target.header, 1);
    }
}

pub struct Packet {
    pub header: PacketHeader,
    pub bytes: [u8; 1500]
}

pub struct PcapFileReader {
    pcap: *const u8,
}

pub struct PcapFileWriter {
    pcap: *const u8,
}

pub fn read(path: &str) -> PcapFileReader {
    unsafe {
        let mut err: [u8; 256] = [0; 256];
        let c_path = CString::new(path).unwrap();
        let pcap = pcap_open_offline(c_path.as_ptr(), err.as_mut_ptr());
        if !pcap.is_null() {
            PcapFileReader {
                pcap: pcap,
            }
        }
        else {
            panic!("error in pcap_open_offline: {}", str::from_utf8(&err).unwrap());
        }
    }
}

pub fn write(path: &str, datalink: i32, snaplen: i32) -> PcapFileWriter {
    unsafe {
        let c_path = CString::new(path).unwrap();

        let inst = pcap_open_dead(datalink, snaplen);
        let pcap = pcap_dump_open(inst, c_path.as_ptr());

        if !pcap.is_null() {
            PcapFileWriter { pcap: pcap }
        }
        else {
            panic!("error in pcap_dump_open");
        }
    }
}

impl PcapFileReader {
    pub fn snaplen(&self) -> i32 { unsafe { pcap_snapshot(self.pcap) } }
    pub fn datalink(&self) -> i32 { unsafe { pcap_datalink(self.pcap) } }
}

impl Iterator for PcapFileReader {
    type Item = Packet;

    fn next(&mut self) -> Option<Packet> {
        unsafe {
            let data = UserData {
                packet: Packet {
                    bytes: [0; 1500],
                    header: PacketHeader {
                        ts: timeval {
                            tv_sec: 0,
                            tv_usec: 0
                        },
                        caplen: 0,
                        len: 0,
                    }
                },
                filled: false
            };
            let ptr: *mut u8 = mem::transmute(&data);
            pcap_loop(self.pcap, 1, cb, ptr);
            let pkt = data.packet;
            if data.filled { Some(pkt) } else { None }
        }
    }
}

impl PcapFileWriter {
    pub fn write(&self, pkt: &Packet) {
        unsafe {
            pcap_dump(self.pcap, &pkt.header, pkt.bytes.as_ptr());
        }
    }

    pub fn close(&self) {
        unsafe {
            pcap_dump_close(self.pcap);
        }
    }
}
