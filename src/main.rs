use futures::stream::StreamExt;
use tracing::Level;
use tracing_subscriber::FmtSubscriber;

use redbpf::load::Loader;
use redbpf::xdp::{self, MapData};

use probes::pktcapture::FlowTuples;

fn probe_code() -> &'static [u8] {
    include_bytes!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/target/bpf/programs/pktcapture/pktcapture.elf"
    ))
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::WARN)
        .finish();
    tracing::subscriber::set_global_default(subscriber).unwrap();

    let mut loaded = Loader::load(probe_code()).expect("error on Loader::load");

    loaded
        .xdp_mut("pktcapture")
        .expect("error on Loaded::xdp_mut")
        .attach_xdp("eth0", xdp::Flags::default())
        .expect("error on XDP probe::attach_xdp");

    while let Some((map_name, events)) = loaded.events.next().await {
        if map_name == "FLOW_TUPLES" {
            for event in events {
                let event = unsafe { &*(event.as_ptr() as *const MapData<FlowTuples>) };
                let info = event.data(); 
                println!("SRC {} DST {}", info.src_ip, info.dest_ip);
            }
        }
    }
}
