//! 设置读取热路径的开销量化。
//!
//! 这不是"跑分"，而是回答一个具体问题：**调度每拍读设置要花多少时间、碰几次库**。
//! 对照组是改造前的写法（每次按键名查一次 SQL）。用 `--nocapture` 看数字：
//!
//! ```text
//! cargo test -p aidm-core --offline --test settings_perf -- --nocapture
//! ```

use std::path::Path;
use std::time::Instant;

use aidm_core::settings;

fn mem() -> rusqlite::Connection {
    aidm_core::open_db(Path::new(":memory:")).unwrap()
}

fn bench(label: &str, iters: u32, mut f: impl FnMut()) -> f64 {
    // 预热一次，避免首轮包含懒初始化
    f();
    let t = Instant::now();
    for _ in 0..iters {
        f();
    }
    let per = t.elapsed().as_secs_f64() * 1e6 / f64::from(iters);
    println!("  {label:<44} {per:>9.2} µs/次");
    per
}

#[test]
fn settings_hot_path_cost() {
    let conn = mem();
    settings::ensure_defaults(&conn).unwrap();
    let keys: Vec<&str> = aidm_core::setting_spec::specs()
        .iter()
        .filter(|s| !s.readonly && !s.secret)
        .map(|s| s.key)
        .collect();

    println!("\n== 设置读取开销（每项 2000 次平均）==");

    // 1) 冷路径：一次装载 + 全量解析成快照（启动/设置变更后才做）
    let load = bench(
        "Snapshot::load（装载+解析全部派生量）",
        200,
        || {
            let _ = settings::Snapshot::load(&conn).unwrap();
        },
    );

    // 2) 热路径：从已有快照按键取值（内存）
    let snap = settings::Snapshot::load(&conn).unwrap();
    let raw = bench("Snapshot::raw(key)（内存查表）", 20_000, || {
        let _ = snap.raw("conn.global_conn_cap");
    });

    // 3) 热路径：类型化字段（引擎真正用的形式）
    let field = bench(
        "快照字段读取（snap.limit_kbps 等）",
        20_000,
        || {
            let _ = std::hint::black_box(snap.limit_kbps);
            let _ = std::hint::black_box(snap.verify_sha256);
            let _ = std::hint::black_box(snap.recv_buf_kb);
        },
    );

    // 4) 版本戳查询：判断"要不要重载"的那一次主键查询
    let rev = bench("settings::revision（一条主键查询）", 5_000, || {
        let _ = settings::revision(&conn);
    });

    // 5) 对照组：改造前"每次按键名查一次 SQL"
    let old = bench(
        "60 × settings::get（改造前的每拍做法）",
        500,
        || {
            for k in &keys {
                let _ = settings::get(&conn, k).unwrap();
            }
        },
    );

    // 6) 冷路径：设置页全量读取
    let map = bench("public_map（设置页全量，冷路径）", 500, || {
        let _ = settings::public_map(&conn).unwrap();
    });

    // 7) schema 视图（UI 打开设置页时拉一次）
    let schema = bench("schema_json（UI 声明表）", 500, || {
        let _ = settings::schema_json();
    });
    assert!(schema > 0.0, "schema_json 应有可测开销");

    println!("\n== 结论 ==");
    println!(
        "  每拍调度读设置：朴素实现 {:.1} µs → 版本戳未变时 {:.1} µs，提速 {:.0}×",
        old,
        rev,
        old / rev.max(0.001)
    );
    println!(
        "  键数 {}；一次解析 {:.1} µs，之后每键取值 {:.3} µs（内存）",
        keys.len(),
        load,
        raw
    );
    println!(
        "  设置页一次全量读 {:.1} µs（含 {} 条主键查询）",
        map,
        keys.len()
    );

    // 回归护栏：给一个宽松上限，防止以后无意间把热路径做成每拍查库
    assert!(
        rev < 2_000.0,
        "版本戳查询过慢（{rev:.1} µs），热路径应只做一条主键查询"
    );
    assert!(
        raw < 50.0,
        "快照内存取值过慢（{raw:.2} µs），不应再碰数据库"
    );
    assert!(field < 50.0, "快照字段读取过慢（{field:.2} µs）");
    assert!(load < 20_000.0, "快照装载过慢（{load:.1} µs），启动会卡");
}
