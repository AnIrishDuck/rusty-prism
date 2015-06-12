use util;
use std::mem;

#[repr(C)]
#[packed]
struct iphdr {
    ihl_version: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32
}

#[allow(dead_code)]
pub struct V4Packet<'a> {
    header: &'a iphdr,
    payload: &'a [u8]
}

impl<'a> V4Packet<'a> {
    pub fn new(raw: &'a [u8]) -> V4Packet<'a> {
        let header: *const u8 = raw.as_ptr();

        // XXX - fix to take into account options length.
        return V4Packet {
            header: unsafe { &*(header as *const iphdr) },
            payload: &raw[mem::size_of::<iphdr>() ..]
        };
    }

    pub fn src(&self) -> u32 { return util::ntohl(self.header.saddr) }
    pub fn dst(&self) -> u32 { return util::ntohl(self.header.daddr) }
}
