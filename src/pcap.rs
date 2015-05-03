use std::ptr;
use std::mem;
use libc::c_int;

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

#[link(name = "pcap")]
extern {
    fn pcap_open_offline(path: *const u8, err: *mut u8) -> *const u8;
    fn pcap_loop(pcap: *const u8, count: c_int,
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

pub struct PcapFile {
    pcap: *const u8,
}

impl PcapFile {
    pub fn open(path: &str) -> PcapFile {
        unsafe {
            let mut err: [u8; 256] = [0; 256];
            PcapFile {
                pcap: pcap_open_offline(path.as_ptr(), err.as_mut_ptr()),
            }
        }
    }
}

impl Iterator for PcapFile {
    type Item = Packet;

    fn next(&mut self) -> Option<Packet> {
        unsafe {
            let mut data = UserData {
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
            let count = pcap_loop(self.pcap, 1, cb, ptr);
            let pkt = data.packet;
            if data.filled { Some(pkt) } else { None }
        }
    }
}
