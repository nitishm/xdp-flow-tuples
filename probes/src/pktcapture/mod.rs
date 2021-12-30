#[repr(C)]
#[derive(Debug, Clone)]
pub struct FlowTuples {
	pub src_ip: u32, 
	pub dest_ip: u32 
}

impl Default for FlowTuples {
    fn default() -> FlowTuples {
			FlowTuples {
				src_ip: 0,
				dest_ip: 0
			}
    }
}
