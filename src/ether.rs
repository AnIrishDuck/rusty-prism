use util;
use std::mem;

const ETH_ALEN : usize  = 6;
const ETH_P_8021Q : u16 = 0x8100;

type MacAddr = [u8; ETH_ALEN];

#[repr(C)]
#[packed]
struct vlan_ethhdr {
    h_dest       : MacAddr,
    h_source     : MacAddr,
    h_vlan_proto : u16,
    h_vlan_TCI   : u16,
    h_vlan_encapsulated_proto : u16
}

#[repr(C)]
#[packed]
struct ethhdr {
    h_dest : MacAddr,
    h_source : MacAddr,
    h_proto : u16
}

pub fn read_inner_packet(outer : &[u8]) -> &[u8] {
    let header: *const u8 = outer.as_ptr();
    let header: &ethhdr = unsafe { &*(header as *const ethhdr) };

    let proto = util::ntohs(header.h_proto);

    if proto == ETH_P_8021Q {
        return &outer[mem::size_of::<vlan_ethhdr>() ..];
    }
    else {
        return &outer[mem::size_of::<ethhdr>() ..];
    }
}
