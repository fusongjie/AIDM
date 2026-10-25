//! Explicit interoperability check of metadata -> private resource directory ->
//! SN directory. This does not request file data or claim transport parity.
use aidm_engine::ed2k::{private_index, private_nat, private_peer};
use std::{
    net::Ipv4Addr,
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

#[test]
#[ignore = "explicit public directory interoperability check; no ISO data"]
fn original_link_resolves_private_peer_super_nodes_without_sdk() {
    let uri = "ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
    let aidm_core::ed2k::Link::File(link) = aidm_core::ed2k::parse_link(uri).unwrap() else {
        panic!("file")
    };
    let identity = private_index::peer_id(&[19; 16]);
    let start = Instant::now();
    let meta = private_index::query(&link, uri, &identity)
        .unwrap()
        .unwrap();
    let metadata_ms = start.elapsed().as_millis();
    let network = private_peer::NetworkInfo {
        internal_ip: Ipv4Addr::UNSPECIFIED,
        nat_type: 0,
        upnp_ip: Ipv4Addr::UNSPECIFIED,
        upnp_port: 0,
        address_is_translated_or_unknown: true,
    };
    let directory = private_peer::query(&link, uri, &meta, &identity, &network).unwrap();
    let directory_ms = start.elapsed().as_millis();
    assert!(!directory.peers.is_empty());
    let targets: Vec<_> = directory.peers.iter().take(3).map(|p| p.peer_id).collect();
    let cancelled = AtomicBool::new(false);
    let mut sn_count = 0;
    let replies =
        private_nat::query_super_nodes(&targets, Duration::from_secs(3), &cancelled, |lookup| {
            if lookup.response.status == 1 && !lookup.response.super_nodes.is_empty() {
                sn_count += lookup.response.super_nodes.len();
                cancelled.store(true, Ordering::Relaxed);
            }
        })
        .unwrap();
    assert!(replies > 0 && sn_count > 0);
    println!("independent_private_lookup metadata_ms={metadata_ms} directory_ms={directory_ms} first_sn_ms={} peers={} sn_replies={replies} super_nodes={sn_count} file_bytes=0", start.elapsed().as_millis(), directory.peers.len());
}
