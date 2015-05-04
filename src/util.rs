pub fn ntohs(n: u16) -> u16 {
    return (n & 0xFF) << 8 + (n >> 8)
}

pub fn ntohl(n: u32) -> u32 {
    //return n;
    let a = (n & 0x000000FF) << 24;
    let b = (n & 0x0000FF00) << 8;
    let c = (n & 0x00FF0000) >> 8;
    let d = (n & 0xFF000000) >> 24;

    return a + b + c + d;
}
