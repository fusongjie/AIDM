//! Opt-in reference-free real private transfer and complete ed2k-piece check.
use aidm_core::ed2k::hash;
use aidm_engine::ed2k::{private_connection, private_index, private_peer, private_session};
use std::{
    net::Ipv4Addr,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
#[ignore = "explicit real ISO transfer; downloads and validates one 9.728MB piece"]
fn own_engine_private_channel_downloads_a_complete_verified_iso_piece() {
    let uri="ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
    let aidm_core::ed2k::Link::File(link) = aidm_core::ed2k::parse_link(uri).unwrap() else {
        panic!("file")
    };
    let identity = private_index::peer_id(&[0x51; 16]);
    let started = Instant::now();
    let meta = private_index::query(&link, uri, &identity)
        .unwrap()
        .unwrap();
    let network = private_peer::NetworkInfo {
        internal_ip: Ipv4Addr::UNSPECIFIED,
        nat_type: 0,
        upnp_ip: Ipv4Addr::UNSPECIFIED,
        upnp_port: 0,
        address_is_translated_or_unknown: true,
    };
    let directory = private_peer::query(&link, uri, &meta, &identity, &network).unwrap();
    let cancelled = AtomicBool::new(false);
    let connection = private_connection::connect(
        &identity,
        &directory.peers,
        Duration::from_secs(5),
        &cancelled,
    )
    .unwrap();
    let connected_ms = started.elapsed().as_millis();
    let session = private_session::Session::new(connection, &link, &meta).unwrap();
    let mut first = None;
    let mut received = 0;
    let data = private_session::download_range(
        session,
        0,
        9_728_000,
        Duration::from_secs(30),
        &cancelled,
        |_, bytes| {
            first.get_or_insert(started.elapsed().as_millis());
            received += bytes.len();
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(data.len(), 9_728_000);
    assert_eq!(received, data.len());
    assert_eq!(hash::md4(&data), meta.part_hashes[0]);
    let prefix = ring::digest::digest(&ring::digest::SHA256, &data[..65536]);
    let prefix: String = prefix.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(
        prefix,
        "ace8a9fd072227270e07430ff7f8ebb666f46d930ed2c434dc5335972c9f4983"
    );
    println!("independent_rust_private_transfer connected_ms={connected_ms} first_file_ms={} finished_ms={} validated_file_bytes={received} verified_ed2k_pieces=1 prefix_sha256={prefix}",first.unwrap(),started.elapsed().as_millis());
}
