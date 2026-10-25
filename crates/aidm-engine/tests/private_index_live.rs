//! 显式运行的公网元数据验收，不创建任务、不请求 ISO 数据。
#[test]
#[ignore = "explicit live SHub interoperability check"]
fn original_iso_native_query_returns_a_valid_hashset_without_reference_sdk() {
    let uri = "ed2k://|file|cn_windows_10_enterprise_ltsc_2019_x64_dvd_9c09ff24.iso|4478906368|E7C526499308841A4A6D116C857DB669|/";
    let aidm_core::ed2k::Link::File(link) = aidm_core::ed2k::parse_link(uri).unwrap() else {
        panic!("file")
    };
    let now = std::time::Instant::now();
    let meta = aidm_engine::ed2k::private_index::query(
        &link,
        uri,
        &aidm_engine::ed2k::private_index::peer_id(&[19; 16]),
    )
    .unwrap()
    .unwrap();
    assert_eq!(meta.part_hashes.len(), 461);
    println!(
        "independent_native_index_ms={} validated_hashes={}",
        now.elapsed().as_millis(),
        meta.part_hashes.len()
    );
}
