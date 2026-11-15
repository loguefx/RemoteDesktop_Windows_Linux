//! Terminal prompts used by `install` and `user` commands.

use std::io::Write;

use anyhow::{bail, Result};

pub fn line(prompt: &str) -> Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;
    let mut s = String::new();
    std::io::stdin().read_line(&mut s)?;
    Ok(s.trim().to_string())
}

/// Ask for a new password twice.
pub fn new_password() -> Result<String> {
    for _ in 0..3 {
        let a = rpassword::prompt_password(format!("Password (min {} chars): ", crate::db::MIN_PASSWORD_LEN))?;
        if let Err(e) = crate::db::validate_password(&a) {
            println!("{e}");
            continue;
        }
        let b = rpassword::prompt_password("Repeat password: ")?;
        if a == b {
            return Ok(a);
        }
        println!("Passwords do not match.");
    }
    bail!("no password set")
}

/// Ask whether to set a quick-login PIN. Empty answer = no PIN.
pub fn optional_pin() -> Result<Option<String>> {
    for _ in 0..3 {
        let a = rpassword::prompt_password("Optional quick-login PIN (4-12 digits, Enter to skip): ")?;
        if a.is_empty() {
            return Ok(None);
        }
        if let Err(e) = crate::db::validate_pin(&a) {
            println!("{e}");
            continue;
        }
        let b = rpassword::prompt_password("Repeat PIN: ")?;
        if a == b {
            return Ok(Some(a));
        }
        println!("PINs do not match.");
    }
    bail!("no PIN set")
}
