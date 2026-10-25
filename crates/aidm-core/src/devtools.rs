//! 开发工具的资源地址：把**包坐标**变成可以直接下载的 HTTPS 直链。
//!
//! ## 为什么需要它
//!
//! `npm` / `cargo` 这类工具的产物最终都是 registry 上的一个普通文件，AIDM 本来就能下。
//! 缺的不是"下载能力"，而是**从用户手上那种坐标到地址的换算**：用户手里通常写着
//! `lodash@4.17.21` 或 `serde@1.0.0`，而不是那条又长又记不住的 URL。
//!
//! ## 只做能确定性构造的那些
//!
//! - **npm / pnpm**：`registry.npmjs.org/{name}/-/{basename}-{version}.tgz`
//! - **cargo**：`static.crates.io/crates/{name}/{name}-{version}.crate`
//!
//! 这两个是**纯字符串构造**，不查任何接口，所以离线可用、也不会因为 registry 抖动
//! 而失败。**PyPI 不在这里**：它的文件路径含哈希目录（`packages/ab/cd/<hash>/…`），
//! 只能通过 `pypi.org/pypi/{name}/{version}/json` 查出来 —— 那需要一次真实的网络
//! 请求，属于"取回"而不是"换算"，见文末的未做说明。
//!
//! ## 刻意不做的事
//!
//! 不校验包是否存在（那要联网），**也不猜版本**：没写版本就明确回绝，而不是去取
//! `latest` —— "我以为你要的是最新版"是下载器最不该替用户做的决定。

/// 解析失败的原因。都是稳定机器码，可直接透出到 IPC。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevToolError {
    /// 认不出这是哪个工具的坐标。
    UnknownTool,
    /// 认得出工具，但缺版本（**不猜 latest**）。
    MissingVersion,
    /// 包名形状不合法。
    BadName,
}

impl DevToolError {
    pub fn code(self) -> &'static str {
        match self {
            DevToolError::UnknownTool => "devtool_unknown",
            DevToolError::MissingVersion => "devtool_missing_version",
            DevToolError::BadName => "devtool_bad_name",
        }
    }
}

/// 支持的工具。`curl` 不是"工具坐标"——它就是任意 URL，所以不在这里。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DevTool {
    Npm,
    Cargo,
}

impl DevTool {
    pub fn as_str(self) -> &'static str {
        match self {
            DevTool::Npm => "npm",
            DevTool::Cargo => "cargo",
        }
    }

    fn from_prefix(p: &str) -> Option<Self> {
        match p {
            // pnpm 用的就是 npm registry，产物完全相同，所以归为同一个工具，
            // 只是前缀也接受 `pnpm:`。
            "npm" | "pnpm" => Some(DevTool::Npm),
            "cargo" | "crates" => Some(DevTool::Cargo),
            _ => None,
        }
    }
}

/// 换算结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    pub tool: DevTool,
    pub name: String,
    pub version: String,
    /// 可直接下载的 HTTPS 直链。
    pub url: String,
    /// 建议的文件名（`lodash-4.17.21.tgz`）。有它就不必让下游再从 URL 猜。
    pub file_name: String,
}

/// 从包坐标构造下载地址。
///
/// **必须带工具前缀**（大小写不敏感）：`npm:` / `pnpm:` / `cargo:` / `crates:`。
///
/// 为什么不像直觉那样"没前缀就当 npm"：`user@host`（SCP 风格的粘贴）与
/// `lodash@4.17.21` 形状完全一样，前者会被静默拼成一条 npm registry 地址 ——
/// 用户以为在下自己的东西，实际去向第三方 registry 要一个包。**这种失败模式比
/// "多打四个字符"糟得多**，所以宁可要求前缀。
///
/// 接受的写法：
/// - `npm:lodash@4.17.21` / `pnpm:lodash@4.17.21`
/// - `cargo:serde@1.0.0` / `crates:serde@1.0.0`
/// - npm 的 scope 包：`npm:@babel/core@7.24.0`
///
/// **不接受的是**：没有前缀、没有版本（不猜 `latest`）、认不出的前缀、空包名。
pub fn resolve(spec: &str) -> Result<Resolved, DevToolError> {
    let raw = spec.trim();
    if raw.is_empty() {
        return Err(DevToolError::UnknownTool);
    }

    // 前缀是必须的 —— 见上面的理由。
    let (tool, body) = match raw.split_once(':') {
        Some((p, rest)) => match DevTool::from_prefix(&p.trim().to_ascii_lowercase()) {
            Some(t) => (t, rest.trim()),
            None => return Err(DevToolError::UnknownTool),
        },
        None => return Err(DevToolError::UnknownTool),
    };

    // 版本分隔符在 npm 是 `@`、在 crates 也是 `@`。注意 scope 包的首字符就是 `@`，
    // 所以要从**第二个字符之后**找最后一个 `@`。
    let (name, version) = split_name_version(body)?;
    if name.is_empty() {
        return Err(DevToolError::BadName);
    }
    if version.is_empty() {
        return Err(DevToolError::MissingVersion);
    }

    let url = match tool {
        DevTool::Npm => {
            // scope 包（`@scope/name`）的文件名只取最后一段：`@babel/core` → `core`。
            let basename = name.rsplit('/').next().unwrap_or(&name);
            format!("https://registry.npmjs.org/{name}/-/{basename}-{version}.tgz")
        }
        DevTool::Cargo => format!("https://static.crates.io/crates/{name}/{name}-{version}.crate"),
    };
    let file_name = match tool {
        DevTool::Npm => {
            let basename = name.rsplit('/').next().unwrap_or(&name);
            format!("{basename}-{version}.tgz")
        }
        DevTool::Cargo => format!("{name}-{version}.crate"),
    };

    Ok(Resolved {
        tool,
        name,
        version,
        url,
        file_name,
    })
}

/// 拆出 `(包名, 版本)`。`@scope/name@1.2.3` 里的第一个 `@` 属于包名。
fn split_name_version(body: &str) -> Result<(String, String), DevToolError> {
    let body = body.trim();
    if body.is_empty() {
        return Err(DevToolError::BadName);
    }
    // scope 包以 `@` 开头：跳过它再找版本分隔符。
    let search_from = usize::from(body.starts_with('@'));
    match body[search_from..].rfind('@') {
        Some(rel) => {
            let at = search_from + rel;
            Ok((
                body[..at].trim().to_string(),
                body[at + 1..].trim().to_string(),
            ))
        }
        // 没有 `@`：要么是纯包名（缺版本），要么是 `name==1.2.3`（pip 风格）——
        // 后者不属于本模块的工具，但对 npm/cargo 来说同样是"认不出"。
        None => {
            if let Some((n, v)) = body.split_once("==") {
                // pip 风格写得再像，也不该被当成 npm/cargo 处理：registry 完全不同。
                let _ = (n, v);
                Err(DevToolError::UnknownTool)
            } else {
                Err(DevToolError::MissingVersion)
            }
        }
    }
}

/// 该地址是不是"已知的开发工具 registry 直链"。
///
/// 用途是**只读的标注**（在任务属性里显示"这是 crates.io 的包"），不改变下载行为 ——
/// 这些地址本来就走普通 HTTP 路径，不需要特殊处理。
pub fn registry_of(url: &str) -> Option<&'static str> {
    let u = url.trim().to_ascii_lowercase();
    if u.starts_with("https://registry.npmjs.org/") || u.starts_with("http://registry.npmjs.org/") {
        Some("npm")
    } else if u.starts_with("https://static.crates.io/") {
        Some("crates.io")
    // 两个主机都算 pypi：`files.pythonhosted.org` 是文件 CDN，`pypi.org` 是元数据/直链，
    // 对"这是 PyPI 的东西"这个判断而言是同一件事（合并成一个条件，避免重复分支）。
    } else if u.starts_with("https://files.pythonhosted.org/") || u.starts_with("https://pypi.org/")
    {
        Some("pypi")
    } else {
        None
    }
}

// ————————————————— PyPI —————————————————
//
// PyPI 与 npm/cargo 有一个本质区别：**文件地址无法构造**。它的下载路径含哈希目录
// （`packages/ab/cd/<hash>/<file>`），哈希是上传时算的，只有查过接口才知道。
// 所以这里分成两步：先给出**接口地址**，取回 JSON 后再从中挑一个文件。

/// PyPI 坐标的查询计划。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipLookup {
    pub name: String,
    pub version: String,
    /// `https://pypi.org/pypi/{name}/{version}/json`
    pub api_url: String,
}

/// `pip:requests==2.31.0` → 元数据接口地址。
///
/// 只接受 `==` 这个**精确版本**写法（PyPI 的 JSON 接口需要确切版本）。用 `>=`、
/// `~=` 这类范围说明符的输入一律回绝 —— 替用户挑一个满足约束的版本，是包管理器的
/// 活，不是下载器的。
///
/// `api_base` 留空则用官方 `https://pypi.org/pypi`。可覆盖的理由有两个：镜像
/// （国内直连官方源很慢），以及**可测试性** —— 硬编码地址让端到端测试没法指向
/// 本地 stub，只能靠联网跑，那样的测试是不可复现的。
pub fn resolve_pip_with(spec: &str, api_base: &str) -> Result<PipLookup, DevToolError> {
    let raw = spec.trim();
    let body = raw
        .split_once(':')
        .filter(|(p, _)| p.trim().eq_ignore_ascii_case("pip"))
        .map(|(_, rest)| rest.trim())
        .ok_or(DevToolError::UnknownTool)?;
    let (name, version) = body.split_once("==").ok_or(DevToolError::MissingVersion)?;
    let (name, version) = (name.trim(), version.trim());
    if name.is_empty() {
        return Err(DevToolError::BadName);
    }
    if version.is_empty() {
        return Err(DevToolError::MissingVersion);
    }
    let name = name.to_ascii_lowercase();
    let base = api_base.trim().trim_end_matches('/');
    let base = if base.is_empty() {
        "https://pypi.org/pypi"
    } else {
        base
    };
    Ok(PipLookup {
        api_url: format!("{base}/{name}/{version}/json"),
        name,
        version: version.to_string(),
    })
}

/// [`resolve_pip_with`] 的官方源版本。
pub fn resolve_pip(spec: &str) -> Result<PipLookup, DevToolError> {
    resolve_pip_with(spec, "")
}

/// 从 PyPI 的 JSON 里挑一个文件下载地址，返回 `(url, filename)`。
///
/// 选择顺序（**这是本函数唯一有判断的地方，所以写清楚**）：
/// 1. **wheel 优先于 sdist**：wheel 是构建好的产物，sdist 还要本地编译；
/// 2. wheel 之间优先**平台无关**的（`py3-none-any` / `py2.py3-none-any`）——
///    它在任何机器上都能装，而某个平台的 wheel 换台机器就没用了；
/// 3. 都没有就退回 sdist；再没有就 `None`（不猜）。
///
/// JSON 形状不合法时返回 `None`，由调用方报错 —— 这里不 panic。
pub fn pick_pypi_file(json: &str) -> Option<(String, String)> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    let files = v.get("urls")?.as_array()?;

    let mut best_wheel: Option<(String, String, bool)> = None; // (url, name, is_pure)
    let mut any_sdist: Option<(String, String)> = None;
    for f in files {
        let (Some(url), Some(name)) = (
            f.get("url").and_then(|x| x.as_str()),
            f.get("filename").and_then(|x| x.as_str()),
        ) else {
            continue;
        };
        let packagetype = f.get("packagetype").and_then(|x| x.as_str()).unwrap_or("");
        if packagetype == "bdist_wheel" || name.ends_with(".whl") {
            // `py3-none-any`：纯 Python、平台无关。
            let lname = name.to_ascii_lowercase();
            let is_pure = lname.contains("-none-any.whl");
            let better = match &best_wheel {
                None => true,
                // 已经拿到纯 wheel 就不换；否则换成纯的。
                Some((_, _, had_pure)) => is_pure && !*had_pure,
            };
            if better {
                best_wheel = Some((url.to_string(), name.to_string(), is_pure));
            }
        } else if any_sdist.is_none() {
            any_sdist = Some((url.to_string(), name.to_string()));
        }
    }
    best_wheel.map(|(u, n, _)| (u, n)).or(any_sdist)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_scoped_and_unscoped() {
        let r = resolve("npm:lodash@4.17.21").unwrap();
        assert_eq!(r.tool, DevTool::Npm);
        assert_eq!(
            r.url,
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        );
        assert_eq!(r.file_name, "lodash-4.17.21.tgz");

        // scope 包：包名保留 `@scope/`，文件名只取最后一段。
        let s = resolve("npm:@babel/core@7.24.0").unwrap();
        assert_eq!(s.name, "@babel/core");
        assert_eq!(
            s.url,
            "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz"
        );
        assert_eq!(s.file_name, "core-7.24.0.tgz");
    }

    /// 无前缀一律回绝 —— `user@host` 与 `lodash@4.17.21` 形状相同，
    /// 静默当 npm 会把前者送进第三方 registry。这是**刻意的取舍**。
    #[test]
    fn prefix_is_required_so_scp_style_is_never_mistaken_for_npm() {
        assert_eq!(
            resolve("lodash@4.17.21").unwrap_err(),
            DevToolError::UnknownTool,
            "没有前缀就不该被换算"
        );
        assert_eq!(
            resolve("user@host").unwrap_err(),
            DevToolError::UnknownTool,
            "scp 风格绝不能变成 npm 下载"
        );
        // pnpm 前缀是 npm registry 的别名（产物完全相同）。
        assert_eq!(
            resolve("pnpm:lodash@4.17.21").unwrap(),
            resolve("npm:lodash@4.17.21").unwrap()
        );
    }

    #[test]
    fn cargo_crate_url() {
        let r = resolve("cargo:serde@1.0.0").unwrap();
        assert_eq!(r.tool, DevTool::Cargo);
        assert_eq!(
            r.url,
            "https://static.crates.io/crates/serde/serde-1.0.0.crate"
        );
        assert_eq!(r.file_name, "serde-1.0.0.crate");
        // `crates:` 是同一件事的另一种写法。
        assert_eq!(resolve("crates:serde@1.0.0").unwrap(), r);
    }

    /// **不猜版本**：没写版本就明确回绝。
    ///
    /// 去取 `latest` 是下载器最不该替用户做的决定 —— 用户以为下的 1.2.3，
    /// 拿到的却是别的东西，而且下完才发现。
    #[test]
    fn missing_version_is_refused_not_defaulted_to_latest() {
        assert_eq!(
            resolve("npm:lodash").unwrap_err(),
            DevToolError::MissingVersion
        );
        assert_eq!(
            resolve("cargo:serde").unwrap_err(),
            DevToolError::MissingVersion
        );
        assert_eq!(
            resolve("npm:lodash@").unwrap_err(),
            DevToolError::MissingVersion
        );
        // scope 包无版本：同样回绝，且不能被当成"包名是 @babel"。
        assert_eq!(
            resolve("npm:@babel/core").unwrap_err(),
            DevToolError::MissingVersion
        );
    }

    /// pip 风格**不该被当成 npm/cargo**：registry 完全不同，硬套会拼出一个 404 的地址。
    #[test]
    fn pip_style_is_not_silently_treated_as_npm() {
        assert_eq!(
            resolve("requests==2.31.0").unwrap_err(),
            DevToolError::UnknownTool
        );
        assert_eq!(
            resolve("pip:requests==2.31.0").unwrap_err(),
            DevToolError::UnknownTool
        );
    }

    #[test]
    fn unknown_prefix_and_empty_input_are_refused() {
        assert_eq!(resolve("").unwrap_err(), DevToolError::UnknownTool);
        assert_eq!(resolve("   ").unwrap_err(), DevToolError::UnknownTool);
        assert_eq!(
            resolve("https://example.com/a.tgz").unwrap_err(),
            DevToolError::UnknownTool,
            "真 URL 不该走坐标换算"
        );
        assert_eq!(
            resolve("gem:rails@7.0.0").unwrap_err(),
            DevToolError::UnknownTool
        );
    }

    /// 大小写与前缀两侧的空白都要容忍：粘贴来的坐标常带这些。
    #[test]
    fn case_and_whitespace_are_tolerated() {
        let r = resolve("  NPM:lodash@4.17.21  ").unwrap();
        assert_eq!(
            r.url,
            "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
        );
        // 版本号里的预发布标记要原样保留（`-alpha.1` 是版本的一部分）。
        let pre = resolve("npm:foo@1.0.0-alpha.1").unwrap();
        assert_eq!(
            pre.url,
            "https://registry.npmjs.org/foo/-/foo-1.0.0-alpha.1.tgz"
        );
    }

    #[test]
    fn registry_of_labels_known_hosts() {
        assert_eq!(
            registry_of("https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"),
            Some("npm")
        );
        assert_eq!(
            registry_of("https://static.crates.io/crates/serde/serde-1.0.0.crate"),
            Some("crates.io")
        );
        assert_eq!(
            registry_of("https://files.pythonhosted.org/packages/ab/cd/x.whl"),
            Some("pypi")
        );
        // 普通地址不标注。
        assert_eq!(registry_of("https://mirrors.example/a.iso"), None);
    }

    // ————————————————— PyPI —————————————————

    /// PyPI 只能给出**接口地址** —— 文件路径含哈希目录，构造不出来。
    #[test]
    fn pip_yields_a_lookup_url_not_a_file_url() {
        let l = resolve_pip("pip:requests==2.31.0").unwrap();
        assert_eq!(l.name, "requests");
        assert_eq!(l.version, "2.31.0");
        assert_eq!(l.api_url, "https://pypi.org/pypi/requests/2.31.0/json");
        // 包名在 URL 里按小写（PyPI 的规范名是小写）。
        assert_eq!(
            resolve_pip("pip:Django==4.2").unwrap().api_url,
            "https://pypi.org/pypi/django/4.2/json"
        );
    }

    /// **范围说明符一律回绝**：替用户挑一个满足约束的版本是包管理器的活。
    #[test]
    fn pip_range_specifiers_are_refused() {
        for spec in [
            "pip:requests",
            "pip:requests>=2.0",
            "pip:requests~=2.31",
            "pip:requests==",
        ] {
            let err = resolve_pip(spec).unwrap_err();
            assert!(
                matches!(err, DevToolError::MissingVersion | DevToolError::BadName),
                "{spec} 应当被回绝，实际 {err:?}"
            );
        }
        // 不是 pip 前缀。
        assert_eq!(
            resolve_pip("npm:lodash@1.0.0").unwrap_err(),
            DevToolError::UnknownTool
        );
    }

    /// 选文件的三条规则：wheel 优先于 sdist；wheel 之间优先平台无关；都没有才退 sdist。
    #[test]
    fn pypi_file_choice_prefers_pure_wheel_then_any_wheel_then_sdist() {
        // 三个候选都有：应当选纯 wheel。
        let json = r#"{"urls":[
            {"filename":"requests-2.31.0.tar.gz","url":"https://f/sdist.tar.gz","packagetype":"sdist"},
            {"filename":"requests-2.31.0-cp311-cp311-win_amd64.whl","url":"https://f/plat.whl","packagetype":"bdist_wheel"},
            {"filename":"requests-2.31.0-py3-none-any.whl","url":"https://f/pure.whl","packagetype":"bdist_wheel"}
        ]}"#;
        assert_eq!(
            pick_pypi_file(json),
            Some((
                "https://f/pure.whl".into(),
                "requests-2.31.0-py3-none-any.whl".into()
            ))
        );

        // 只有平台相关 wheel 与 sdist：选 wheel（构建好的产物）。
        let json2 = r#"{"urls":[
            {"filename":"x-1.0.tar.gz","url":"https://f/sdist.tar.gz","packagetype":"sdist"},
            {"filename":"x-1.0-cp311-cp311-win_amd64.whl","url":"https://f/plat.whl","packagetype":"bdist_wheel"}
        ]}"#;
        assert_eq!(
            pick_pypi_file(json2).map(|(u, _)| u),
            Some("https://f/plat.whl".into())
        );

        // 只有 sdist：退回它。
        let json3 = r#"{"urls":[{"filename":"y-1.0.tar.gz","url":"https://f/s.tar.gz","packagetype":"sdist"}]}"#;
        assert_eq!(
            pick_pypi_file(json3).map(|(u, _)| u),
            Some("https://f/s.tar.gz".into())
        );

        // 一个都没有 / JSON 不合法：返回 None，**不猜**。
        assert_eq!(pick_pypi_file(r#"{"urls":[]}"#), None);
        assert_eq!(pick_pypi_file("not json"), None);
        assert_eq!(pick_pypi_file("{}"), None);
    }
}
