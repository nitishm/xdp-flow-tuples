#![no_std]
#![no_main]

use core::ptr;
use probes::pktcapture::*;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut FLOW_TUPLES: PerfMap<FlowTuples> = PerfMap::with_max_entries(1024);

#[xdp("pktcapture")]
fn flow_capture(ctx: XdpContext) -> XdpResult {
    let mut flow = FlowTuples::default();
    let (ip, data) = match (ctx.ip(), ctx.data()) {
        // use ptr::read_unaligned if the alignment of the pointer is unsure
        (Ok(ip), Ok(data)) => (unsafe { ptr::read_unaligned(ip) }, data),
        _ => return Ok(XdpAction::Pass),
    };

    flow.src_ip = ip.saddr;
    flow.dest_ip = ip.daddr;

    let tcphdr = match ctx.transport() {
        Ok(Transport::TCP(tcphdr)) => unsafe { ptr::read_unaligned(tcphdr) },
        _ => return Ok(XdpAction::Pass),
    };

    if u16::from_be(tcphdr.dest) != 8080_u16 {
        return Ok(XdpAction::Pass);
    }

    unsafe {
        FLOW_TUPLES.insert(
            &ctx,
            &MapData::with_payload(flow, data.offset() as u32, data.len() as u32),
        );
    }

    return Ok(XdpAction::Pass);
}
