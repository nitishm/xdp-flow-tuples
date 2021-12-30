#![no_std]
#![no_main]

use probes::pktcapture::*;
use redbpf_probes::xdp::prelude::*;

program!(0xFFFFFFFE, "GPL");

#[map]
static mut FLOW_TUPLES: PerfMap<FlowTuples> = PerfMap::with_max_entries(1024);

#[xdp]
fn flow_capture(ctx: XdpContext) -> XdpResult {
    let mut flow = FlowTuples::default();
		let (ip, data) = match (ctx.ip(), ctx.data()) {
			(Ok(ip), Ok(data)) => (unsafe { *ip }, data),
			_ => return Ok(XdpAction::Pass),
		};

		flow.src_ip = ip.saddr;
		flow.src_ip = ip.daddr;
	
		unsafe {
			FLOW_TUPLES.insert(
				&ctx, 
				&MapData::with_payload(flow, data.offset() as u32,data.len() as u32),
			);
		}
		
		return Ok(XdpAction::Pass);
}
