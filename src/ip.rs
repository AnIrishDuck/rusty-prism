/// IP parsing routines. This is mostly a direct port of linux/ip.h

extern crate num;

use std::mem;

use self::num::traits::PrimInt;

#[repr(C)]
#[repr(packed)]
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

    /// Returns the source address of this IPv4 packet.
    pub fn src(&self) -> u32 { return u32::from_be(self.header.saddr) }

    /// Returns the destination address of this IPv6 packet.
    pub fn dst(&self) -> u32 { return u32::from_be(self.header.daddr) }
}
