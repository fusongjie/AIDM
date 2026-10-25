//! HTTP 认证挑战解析与 Digest 应答（RFC 7616 / RFC 7235）。
//!
//! 只实现 `qop=auth`（及无 qop 的 RFC 2069 兼容形式）；`auth-int` 需要对整个
//! 请求体做摘要，GET 下载用不上，遇到“只给 auth-int”的挑战直接视为不支持。
//! 解析 fail-closed：缺 `realm`/`nonce`、算法未知、参数重复或引号不闭合的
//! 挑战都丢弃，不猜默认值。

use sha2::{Digest as _, Sha256};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigestAlgorithm {
    Md5,
    Md5Sess,
    Sha256,
    Sha256Sess,
}

impl DigestAlgorithm {
    fn parse(raw: &str) -> Option<Self> {
        match raw.to_ascii_uppercase().as_str() {
            "MD5" => Some(Self::Md5),
            "MD5-SESS" => Some(Self::Md5Sess),
            "SHA-256" => Some(Self::Sha256),
            "SHA-256-SESS" => Some(Self::Sha256Sess),
            _ => None,
        }
    }

    fn token(self) -> &'static str {
        match self {
            Self::Md5 => "MD5",
            Self::Md5Sess => "MD5-sess",
            Self::Sha256 => "SHA-256",
            Self::Sha256Sess => "SHA-256-sess",
        }
    }

    fn is_sess(self) -> bool {
        matches!(self, Self::Md5Sess | Self::Sha256Sess)
    }

    /// 多个 Digest 挑战并存时优先选更强的摘要。
    fn strength(self) -> u8 {
        match self {
            Self::Md5 | Self::Md5Sess => 1,
            Self::Sha256 | Self::Sha256Sess => 2,
        }
    }

    fn hash_hex(self, data: &str) -> String {
        match self {
            Self::Md5 | Self::Md5Sess => format!("{:x}", md5::compute(data.as_bytes())),
            Self::Sha256 | Self::Sha256Sess => hex(&Sha256::digest(data.as_bytes())),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigestChallenge {
    pub realm: String,
    pub nonce: String,
    pub opaque: Option<String>,
    pub algorithm: DigestAlgorithm,
    /// 服务端给了 `qop` 且其中含 `auth`；`false` 表示挑战里没有 `qop`（RFC 2069 形式）。
    pub qop_auth: bool,
    pub userhash: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Challenge {
    Basic {
        realm: Option<String>,
    },
    Digest(DigestChallenge),
    /// 能识别出 scheme 但参数不可用（例如只给 `auth-int` 的 Digest），或未知 scheme。
    Unsupported {
        scheme: String,
    },
}

/// 解析一个或多个 `WWW-Authenticate` 头值（同一头里也可以有逗号分隔的多个挑战）。
pub fn parse_challenges<S: AsRef<str>>(values: &[S]) -> Vec<Challenge> {
    let mut out = Vec::new();
    for v in values {
        match split_challenges(v.as_ref()) {
            Some(list) => out.extend(list.into_iter().map(build_challenge)),
            None => out.push(Challenge::Unsupported {
                scheme: String::new(),
            }),
        }
    }
    out
}

/// 在多个挑战里选最强的可用 Digest。
pub fn best_digest(challenges: &[Challenge]) -> Option<&DigestChallenge> {
    challenges
        .iter()
        .filter_map(|c| match c {
            Challenge::Digest(d) => Some(d),
            _ => None,
        })
        .max_by_key(|d| d.algorithm.strength())
}

pub fn offers_basic(challenges: &[Challenge]) -> bool {
    challenges
        .iter()
        .any(|c| matches!(c, Challenge::Basic { .. }))
}

/// 生成 `Authorization: Digest ...` 的值（不含头名）。
///
/// `uri` 必须与请求行里的 request-target 逐字节一致（路径 + 查询串）。
/// 用户名含引号、反斜杠、控制字符或非 ASCII 时返回 `None`：RFC 7616 的
/// `username*` 扩展形式各服务器支持参差，宁可不发也不发一个必然失败的应答。
pub fn digest_authorization(
    ch: &DigestChallenge,
    username: &str,
    password: &str,
    method: &str,
    uri: &str,
    cnonce: &str,
    nc: u32,
) -> Option<String> {
    let plain_user = |s: &str| {
        s.bytes()
            .all(|b| (0x20..0x7f).contains(&b) && b != b'"' && b != b'\\')
    };
    if !ch.userhash && !plain_user(username) {
        return None;
    }
    if !plain_user(uri) || !plain_user(cnonce) || cnonce.is_empty() {
        return None;
    }
    let alg = ch.algorithm;
    let nc_hex = format!("{nc:08x}");
    let mut ha1 = alg.hash_hex(&format!("{username}:{}:{password}", ch.realm));
    if alg.is_sess() {
        ha1 = alg.hash_hex(&format!("{ha1}:{}:{cnonce}", ch.nonce));
    }
    let ha2 = alg.hash_hex(&format!("{method}:{uri}"));
    let response = if ch.qop_auth {
        alg.hash_hex(&format!("{ha1}:{}:{nc_hex}:{cnonce}:auth:{ha2}", ch.nonce))
    } else {
        alg.hash_hex(&format!("{ha1}:{}:{ha2}", ch.nonce))
    };
    let shown_user = if ch.userhash {
        alg.hash_hex(&format!("{username}:{}", ch.realm))
    } else {
        username.to_string()
    };
    let mut h = format!(
        "Digest username=\"{shown_user}\", realm=\"{}\", uri=\"{uri}\", algorithm={}, nonce=\"{}\"",
        quote_escape(&ch.realm),
        alg.token(),
        quote_escape(&ch.nonce),
    );
    if ch.qop_auth {
        h.push_str(&format!(", nc={nc_hex}, cnonce=\"{cnonce}\", qop=auth"));
    }
    h.push_str(&format!(", response=\"{response}\""));
    if let Some(o) = &ch.opaque {
        h.push_str(&format!(", opaque=\"{}\"", quote_escape(o)));
    }
    if ch.userhash {
        h.push_str(", userhash=true");
    }
    Some(h)
}

/// 32 个十六进制字符的随机 cnonce。
pub fn random_cnonce() -> String {
    use ring::rand::SecureRandom;
    let mut b = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut b)
        .expect("system RNG unavailable");
    hex(&b)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn quote_escape(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

type RawChallenge = (String, Vec<(String, String)>);

fn build_challenge((scheme, params): RawChallenge) -> Challenge {
    let lower = scheme.to_ascii_lowercase();
    let get = |k: &str| {
        params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(k))
            .map(|(_, v)| v.clone())
    };
    let mut seen = std::collections::HashSet::new();
    let duplicated = params
        .iter()
        .any(|(n, _)| !seen.insert(n.to_ascii_lowercase()));
    match lower.as_str() {
        "basic" if !duplicated => Challenge::Basic {
            realm: get("realm"),
        },
        "digest" if !duplicated => {
            let unsupported = || Challenge::Unsupported {
                scheme: scheme.clone(),
            };
            let (Some(realm), Some(nonce)) = (get("realm"), get("nonce")) else {
                return unsupported();
            };
            let algorithm = match get("algorithm") {
                None => DigestAlgorithm::Md5,
                Some(a) => match DigestAlgorithm::parse(&a) {
                    Some(a) => a,
                    None => return unsupported(),
                },
            };
            let qop_auth = match get("qop") {
                None => false,
                Some(q) => {
                    if !q.split(',').any(|t| t.trim().eq_ignore_ascii_case("auth")) {
                        return unsupported();
                    }
                    true
                }
            };
            // `-sess` 依赖 cnonce，而 cnonce 只在带 qop 时发送；无 qop 的 sess 无法定义。
            if algorithm.is_sess() && !qop_auth {
                return unsupported();
            }
            let userhash = get("userhash").is_some_and(|v| v.eq_ignore_ascii_case("true"));
            Challenge::Digest(DigestChallenge {
                realm,
                nonce,
                opaque: get("opaque"),
                algorithm,
                qop_auth,
                userhash,
            })
        }
        _ => Challenge::Unsupported { scheme },
    }
}

/// 把头值切成 `(scheme, params)` 列表。语法错误（引号不闭合、`=` 后无值等）返回 `None`。
fn split_challenges(s: &str) -> Option<Vec<RawChallenge>> {
    let b = s.as_bytes();
    let mut i = 0;
    let mut out: Vec<RawChallenge> = Vec::new();
    let skip_ws = |i: &mut usize| {
        while *i < b.len() && (b[*i] == b' ' || b[*i] == b'\t') {
            *i += 1;
        }
    };
    let is_tchar = |c: u8| c.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&c);
    loop {
        skip_ws(&mut i);
        while i < b.len() && b[i] == b',' {
            i += 1;
            skip_ws(&mut i);
        }
        if i >= b.len() {
            break;
        }
        let start = i;
        while i < b.len() && is_tchar(b[i]) {
            i += 1;
        }
        if start == i {
            return None;
        }
        let token = &s[start..i];
        skip_ws(&mut i);
        if i < b.len() && b[i] == b'=' {
            // 参数：属于最近的一个挑战
            i += 1;
            skip_ws(&mut i);
            let value = if i < b.len() && b[i] == b'"' {
                i += 1;
                let mut v = String::new();
                loop {
                    let c = *b.get(i)?;
                    i += 1;
                    match c {
                        b'"' => break,
                        b'\\' => {
                            v.push(*b.get(i)? as char);
                            i += 1;
                        }
                        _ => v.push(c as char),
                    }
                }
                v
            } else {
                let vs = i;
                while i < b.len() && is_tchar(b[i]) {
                    i += 1;
                }
                if vs == i {
                    // token68（如 `Basic abc==`）不会出现在挑战参数里
                    return None;
                }
                s[vs..i].to_string()
            };
            out.last_mut()?.1.push((token.to_string(), value));
        } else {
            out.push((token.to_string(), Vec::new()));
        }
        skip_ws(&mut i);
        if i < b.len() && b[i] != b',' && !is_tchar(b[i]) {
            return None;
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RFC7616_NONCE: &str = "7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v";
    const RFC7616_OPAQUE: &str = "FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS";
    const RFC7616_CNONCE: &str = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";

    fn rfc7616(alg: DigestAlgorithm) -> DigestChallenge {
        DigestChallenge {
            realm: "http-auth@example.org".into(),
            nonce: RFC7616_NONCE.into(),
            opaque: Some(RFC7616_OPAQUE.into()),
            algorithm: alg,
            qop_auth: true,
            userhash: false,
        }
    }

    fn response_of(h: &str) -> &str {
        let at = h.find("response=\"").unwrap() + "response=\"".len();
        &h[at..at + h[at..].find('"').unwrap()]
    }

    /// RFC 7616 §3.9.1 的 MD5 与 SHA-256 示例。
    #[test]
    fn rfc7616_examples() {
        let md5 = digest_authorization(
            &rfc7616(DigestAlgorithm::Md5),
            "Mufasa",
            "Circle of Life",
            "GET",
            "/dir/index.html",
            RFC7616_CNONCE,
            1,
        )
        .unwrap();
        assert_eq!(response_of(&md5), "8ca523f5e9506fed4657c9700eebdbec");
        let sha = digest_authorization(
            &rfc7616(DigestAlgorithm::Sha256),
            "Mufasa",
            "Circle of Life",
            "GET",
            "/dir/index.html",
            RFC7616_CNONCE,
            1,
        )
        .unwrap();
        assert_eq!(
            response_of(&sha),
            "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"
        );
        assert!(sha.contains("algorithm=SHA-256"));
        assert!(sha.contains("nc=00000001"));
        assert!(sha.contains(&format!("opaque=\"{RFC7616_OPAQUE}\"")));
    }

    /// RFC 2617 §3.5 的经典示例（MD5 + qop=auth）。
    #[test]
    fn rfc2617_example() {
        let ch = DigestChallenge {
            realm: "testrealm@host.com".into(),
            nonce: "dcd98b7102dd2f0e8b11d0f600bfb0c093".into(),
            opaque: Some("5ccc069c403ebaf9f0171e9517f40e41".into()),
            algorithm: DigestAlgorithm::Md5,
            qop_auth: true,
            userhash: false,
        };
        let h = digest_authorization(
            &ch,
            "Mufasa",
            "Circle Of Life",
            "GET",
            "/dir/index.html",
            "0a4f113b",
            1,
        )
        .unwrap();
        assert_eq!(response_of(&h), "6629fae49393a05397450978507c4ef1");
    }

    #[test]
    fn parses_multiple_challenges_and_prefers_sha256() {
        let v = [
            "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=MD5, nonce=\"n1\", opaque=\"o\"",
            "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=SHA-256, nonce=\"n2\", opaque=\"o\", Basic realm=\"x\"",
        ];
        let cs = parse_challenges(&v);
        assert_eq!(cs.len(), 3);
        assert!(offers_basic(&cs));
        let d = best_digest(&cs).unwrap();
        assert_eq!(d.algorithm, DigestAlgorithm::Sha256);
        assert_eq!(d.nonce, "n2");
        assert!(d.qop_auth);
    }

    #[test]
    fn rejects_unusable_challenges() {
        let cs = parse_challenges(&[
            "Digest realm=\"r\", qop=\"auth-int\", nonce=\"n\"",
            "Digest realm=\"r\", algorithm=SHA-512-256, nonce=\"n\"",
            "Digest realm=\"r\"",
            "Digest realm=\"r\", nonce=\"a\", nonce=\"b\"",
            "Digest realm=\"r\", algorithm=MD5-sess, nonce=\"n\"",
            "Negotiate",
        ]);
        assert_eq!(cs.len(), 6);
        assert!(cs
            .iter()
            .all(|c| matches!(c, Challenge::Unsupported { .. })));
        assert!(best_digest(&cs).is_none());
        assert!(!offers_basic(&cs));
        assert_eq!(
            parse_challenges(&["Digest realm=\"unterminated"]),
            vec![Challenge::Unsupported {
                scheme: String::new()
            }]
        );
    }

    #[test]
    fn rfc2069_form_has_no_qop_fields() {
        let cs = parse_challenges(&["Digest realm=\"r\", nonce=\"n\""]);
        let d = best_digest(&cs).unwrap();
        assert!(!d.qop_auth);
        let h = digest_authorization(d, "u", "p", "GET", "/f", "c", 1).unwrap();
        assert!(!h.contains("qop=") && !h.contains("nc=") && !h.contains("cnonce="));
        let ha1 = format!("{:x}", md5::compute("u:r:p"));
        let ha2 = format!("{:x}", md5::compute("GET:/f"));
        assert_eq!(
            response_of(&h),
            format!("{:x}", md5::compute(format!("{ha1}:n:{ha2}")))
        );
    }

    #[test]
    fn escapes_and_refuses_unsafe_inputs() {
        let cs = parse_challenges(&["Digest realm=\"a\\\"b\", nonce=\"n\", qop=auth"]);
        let d = best_digest(&cs).unwrap();
        assert_eq!(d.realm, "a\"b");
        let h = digest_authorization(d, "u", "p", "GET", "/", "c", 1).unwrap();
        assert!(h.contains("realm=\"a\\\"b\""));
        assert!(digest_authorization(d, "u\"x", "p", "GET", "/", "c", 1).is_none());
        assert!(digest_authorization(d, "用户", "p", "GET", "/", "c", 1).is_none());
        assert!(digest_authorization(d, "u", "p", "GET", "/", "", 1).is_none());
    }

    #[test]
    fn userhash_hides_username() {
        let mut ch = rfc7616(DigestAlgorithm::Sha256);
        ch.userhash = true;
        let h = digest_authorization(
            &ch,
            "Mufasa",
            "Circle of Life",
            "GET",
            "/",
            RFC7616_CNONCE,
            1,
        )
        .unwrap();
        assert!(!h.contains("Mufasa"));
        assert!(h.contains("userhash=true"));
    }

    #[test]
    fn cnonce_is_random_hex() {
        let a = random_cnonce();
        assert_eq!(a.len(), 32);
        assert!(a.bytes().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(a, random_cnonce());
    }
}
