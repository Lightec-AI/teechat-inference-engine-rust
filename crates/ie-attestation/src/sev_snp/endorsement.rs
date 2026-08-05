//! Self-contained AMD SNP endorsement loading (RB-02).

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ie_protocol::CpuTeeEndorsement;

fn nonempty_env(env: &HashMap<String, String>, key: &str) -> Option<String> {
    env.get(key)
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn pem_to_der_b64(pem: &str) -> Result<String, ()> {
    let body: String = pem
        .lines()
        .map(str::trim)
        .filter(|line| {
            !line.is_empty() && !line.starts_with("-----BEGIN ") && !line.starts_with("-----END ")
        })
        .collect();
    if body.is_empty() {
        return Err(());
    }
    let der = STANDARD.decode(body).map_err(|_| ())?;
    if der.is_empty() {
        return Err(());
    }
    Ok(STANDARD.encode(der))
}

fn read_pem_der_b64(path: &Path) -> Result<Option<String>, ()> {
    if !path.exists() {
        return Ok(None);
    }
    let pem = fs::read_to_string(path).map_err(|_| ())?;
    pem_to_der_b64(&pem).map(Some)
}

/// Load VCEK plus optional ASK/ARK/CRL collateral.
///
/// Explicit DER-base64 environment variables take precedence. Otherwise,
/// `TEECHAT_SNP_CERT_CACHE_DIR` is expected to contain `vcek.pem` and may
/// contain `ask.pem`, `ark.pem`, and `crl.pem`. As in the TypeScript
/// reference, malformed or unreadable cache material makes the endorsement
/// unavailable rather than returning a partial chain.
pub fn load_cpu_tee_endorsement_from_env(
    env: &HashMap<String, String>,
) -> Option<CpuTeeEndorsement> {
    if let Some(vcek_der_b64) = nonempty_env(env, "TEECHAT_SNP_VCEK_DER_B64") {
        return Some(CpuTeeEndorsement {
            vcek_der_b64,
            ask_der_b64: nonempty_env(env, "TEECHAT_SNP_ASK_DER_B64"),
            ark_der_b64: nonempty_env(env, "TEECHAT_SNP_ARK_DER_B64"),
            crl_der_b64: nonempty_env(env, "TEECHAT_SNP_CRL_DER_B64"),
        });
    }

    let cache_dir = nonempty_env(env, "TEECHAT_SNP_CERT_CACHE_DIR").map(PathBuf::from)?;
    let load = || -> Result<Option<CpuTeeEndorsement>, ()> {
        let Some(vcek_der_b64) = read_pem_der_b64(&cache_dir.join("vcek.pem"))? else {
            return Ok(None);
        };
        Ok(Some(CpuTeeEndorsement {
            vcek_der_b64,
            ask_der_b64: read_pem_der_b64(&cache_dir.join("ask.pem"))?,
            ark_der_b64: read_pem_der_b64(&cache_dir.join("ark.pem"))?,
            crl_der_b64: read_pem_der_b64(&cache_dir.join("crl.pem"))?,
        }))
    };
    load().ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_vcek_takes_precedence_and_keeps_optional_chain() {
        let env = HashMap::from([
            ("TEECHAT_SNP_VCEK_DER_B64".into(), " dnNlaw== ".into()),
            ("TEECHAT_SNP_ASK_DER_B64".into(), "YXNr".into()),
            ("TEECHAT_SNP_ARK_DER_B64".into(), "YXJr".into()),
        ]);
        let got = load_cpu_tee_endorsement_from_env(&env).expect("endorsement");
        assert_eq!(got.vcek_der_b64, "dnNlaw==");
        assert_eq!(got.ask_der_b64.as_deref(), Some("YXNr"));
        assert_eq!(got.ark_der_b64.as_deref(), Some("YXJr"));
        assert_eq!(got.crl_der_b64, None);
    }

    #[test]
    fn loads_and_normalizes_pem_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("vcek.pem"),
            "-----BEGIN CERTIFICATE-----\nZG\nVy\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(
            dir.path().join("crl.pem"),
            "-----BEGIN X509 CRL-----\nY3Js\n-----END X509 CRL-----\n",
        )
        .unwrap();
        let env = HashMap::from([(
            "TEECHAT_SNP_CERT_CACHE_DIR".into(),
            dir.path().display().to_string(),
        )]);
        let got = load_cpu_tee_endorsement_from_env(&env).expect("endorsement");
        assert_eq!(got.vcek_der_b64, STANDARD.encode(b"der"));
        assert_eq!(got.crl_der_b64.as_deref(), Some("Y3Js"));
    }

    #[test]
    fn malformed_optional_pem_rejects_the_whole_cache() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("vcek.pem"),
            "-----BEGIN CERTIFICATE-----\nZGVy\n-----END CERTIFICATE-----\n",
        )
        .unwrap();
        fs::write(dir.path().join("ask.pem"), "not base64!").unwrap();
        let env = HashMap::from([(
            "TEECHAT_SNP_CERT_CACHE_DIR".into(),
            dir.path().display().to_string(),
        )]);
        assert!(load_cpu_tee_endorsement_from_env(&env).is_none());
    }
}
