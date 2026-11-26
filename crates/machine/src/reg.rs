//! The few registry reads and writes repairs need. Keys are written as `HKCU\Software\...` or
//! `HKLM\...`. Writes are refused outside HKCU: Genra never asks for admin rights. On other
//! systems every call fails with "Windows only".

use anyhow::Result;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "data", rename_all = "snake_case")]
pub enum RegValue {
    Dword(u32),
    String(String),
    ExpandString(String),
}

impl RegValue {
    pub fn as_text(&self) -> String {
        match self {
            RegValue::Dword(n) => n.to_string(),
            RegValue::String(s) | RegValue::ExpandString(s) => s.clone(),
        }
    }
}

/// Splits `HKCU\Software\X` into ("HKCU", "Software\X"). Accepts the long hive names too.
pub fn split_hive(key: &str) -> Option<(&'static str, &str)> {
    let (hive, rest) = key.split_once('\\').unwrap_or((key, ""));
    let hive = match hive.to_ascii_uppercase().as_str() {
        "HKCU" | "HKEY_CURRENT_USER" => "HKCU",
        "HKLM" | "HKEY_LOCAL_MACHINE" => "HKLM",
        _ => return None,
    };
    Some((hive, rest))
}

#[cfg(windows)]
mod imp {
    use super::*;
    use anyhow::{bail, Context};
    use winreg::enums::*;
    use winreg::{RegKey, RegValue as Raw};

    fn root(key: &str) -> Result<(RegKey, String)> {
        let Some((hive, rest)) = split_hive(key) else { bail!("unknown registry hive in {key}") };
        let h = if hive == "HKCU" { HKEY_CURRENT_USER } else { HKEY_LOCAL_MACHINE };
        Ok((RegKey::predef(h), rest.to_string()))
    }

    fn writable(key: &str) -> Result<()> {
        if split_hive(key).map(|(h, _)| h) != Some("HKCU") {
            bail!("cần quyền quản trị: Genra only changes the current user's settings ({key})");
        }
        Ok(())
    }

    fn decode(raw: &Raw) -> Option<RegValue> {
        match raw.vtype {
            REG_DWORD => {
                let b: [u8; 4] = raw.bytes.get(..4)?.try_into().ok()?;
                Some(RegValue::Dword(u32::from_le_bytes(b)))
            }
            REG_SZ | REG_EXPAND_SZ => {
                let u: Vec<u16> = raw.bytes.as_chunks::<2>().0.iter().map(|c| u16::from_le_bytes(*c)).collect();
                let s = String::from_utf16_lossy(&u).trim_end_matches('\0').to_string();
                Some(if raw.vtype == REG_SZ { RegValue::String(s) } else { RegValue::ExpandString(s) })
            }
            _ => None,
        }
    }

    fn open(key: &str, access: u32) -> Result<Option<RegKey>> {
        let (r, sub) = root(key)?;
        match r.open_subkey_with_flags(&sub, access) {
            Ok(k) => Ok(Some(k)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context(format!("opening {key}"))),
        }
    }

    pub fn get(key: &str, name: &str) -> Result<Option<RegValue>> {
        let Some(k) = open(key, KEY_READ)? else { return Ok(None) };
        match k.get_raw_value(name) {
            Ok(raw) => Ok(decode(&raw)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(anyhow::Error::new(e).context(format!("reading {key}\\{name}"))),
        }
    }

    pub fn set(key: &str, name: &str, value: &RegValue) -> Result<()> {
        writable(key)?;
        let (r, sub) = root(key)?;
        let (k, _) = r.create_subkey(&sub).with_context(|| format!("opening {key}"))?;
        match value {
            RegValue::Dword(n) => k.set_value(name, n),
            RegValue::String(s) => k.set_value(name, s),
            RegValue::ExpandString(s) => {
                let mut bytes: Vec<u8> = s.encode_utf16().chain(std::iter::once(0)).flat_map(|u| u.to_le_bytes()).collect();
                bytes.shrink_to_fit();
                k.set_raw_value(name, &Raw { bytes: bytes.into(), vtype: REG_EXPAND_SZ })
            }
        }
        .with_context(|| format!("writing {key}\\{name}"))
    }

    pub fn delete_value(key: &str, name: &str) -> Result<()> {
        writable(key)?;
        let Some(k) = open(key, KEY_READ | KEY_SET_VALUE)? else { return Ok(()) };
        match k.delete_value(name) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(anyhow::Error::new(e).context(format!("removing {key}\\{name}"))),
        }
    }

    pub fn subkeys(key: &str) -> Result<Vec<String>> {
        let Some(k) = open(key, KEY_READ)? else { return Ok(Vec::new()) };
        Ok(k.enum_keys().filter_map(|r| r.ok()).collect())
    }

    pub fn values(key: &str) -> Result<Vec<(String, RegValue)>> {
        let Some(k) = open(key, KEY_READ)? else { return Ok(Vec::new()) };
        Ok(k.enum_values().filter_map(|r| r.ok()).filter_map(|(n, raw)| decode(&raw).map(|v| (n, v))).collect())
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    fn na<T>() -> Result<T> {
        anyhow::bail!("the registry exists on Windows only")
    }
    pub fn get(_: &str, _: &str) -> Result<Option<RegValue>> {
        na()
    }
    pub fn set(_: &str, _: &str, _: &RegValue) -> Result<()> {
        na()
    }
    pub fn delete_value(_: &str, _: &str) -> Result<()> {
        na()
    }
    pub fn subkeys(_: &str) -> Result<Vec<String>> {
        na()
    }
    pub fn values(_: &str) -> Result<Vec<(String, RegValue)>> {
        na()
    }
}

pub use imp::{delete_value, get, set, subkeys, values};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hives() {
        assert_eq!(split_hive("HKCU\\Software\\X"), Some(("HKCU", "Software\\X")));
        assert_eq!(split_hive("HKEY_LOCAL_MACHINE\\A"), Some(("HKLM", "A")));
        assert_eq!(split_hive("HKCR\\A"), None);
    }

    #[test]
    fn values_round_trip_as_json() {
        let v = RegValue::Dword(1);
        let s = serde_json::to_string(&v).unwrap();
        assert_eq!(s, r#"{"type":"dword","data":1}"#);
        assert_eq!(serde_json::from_str::<RegValue>(&s).unwrap(), v);
    }
}
