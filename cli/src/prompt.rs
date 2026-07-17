//! Interactive input helpers.
//!
//! Prompts print to stderr so stdout stays clean data output. The master
//! password is read with echo disabled on a terminal. When stdin is not a
//! terminal (scripts, tests), input is read line by line from stdin; the
//! password still never appears on any command line.

use anyhow::{Context, Result};
use password_manager_core::secrecy::SecretString;
use std::io::{self, BufRead, IsTerminal, Write};
use zeroize::Zeroize;

fn prompt_to_stderr(prompt: &str) -> Result<()> {
    eprint!("{prompt}");
    io::stderr().flush()?;
    Ok(())
}

fn read_stdin_line() -> Result<String> {
    let mut line = String::new();
    let n = io::stdin()
        .lock()
        .read_line(&mut line)
        .context("reading stdin")?;
    if n == 0 {
        anyhow::bail!("unexpected end of input");
    }
    Ok(line.trim_end_matches(['\r', '\n']).to_string())
}

/// Read a secret without echo. Never taken as a command line argument.
pub fn read_password(prompt: &str) -> Result<SecretString> {
    prompt_to_stderr(prompt)?;
    if io::stdin().is_terminal() {
        let pw = rpassword::read_password().context("reading password")?;
        Ok(into_secret(pw))
    } else {
        let mut line = String::new();
        let n = io::stdin()
            .lock()
            .read_line(&mut line)
            .context("reading password")?;
        if n == 0 {
            line.zeroize();
            anyhow::bail!("unexpected end of input");
        }
        let end = line.trim_end_matches(['\r', '\n']).len();
        line.truncate(end);
        Ok(into_secret(line))
    }
}

/// Move a secret string into a `SecretString` without leaving unzeroized
/// copies behind. `SecretString::from(String)` shrinks the buffer, and a
/// shrink reallocates whenever capacity exceeds length (which read buffers
/// almost always do), freeing the original bytes unzeroized. Copying into an
/// exact-size buffer first makes that shrink a no-op, and the source buffer
/// is zeroized here.
fn into_secret(mut source: String) -> SecretString {
    let mut exact = String::with_capacity(source.len());
    exact.push_str(&source);
    source.zeroize();
    SecretString::from(exact)
}

/// Read one line of non-secret input.
pub fn read_line(prompt: &str) -> Result<String> {
    prompt_to_stderr(prompt)?;
    read_stdin_line()
}

/// Read one line, returning `default` when the user just presses Enter.
/// Entering a single `-` clears the value.
pub fn read_line_with_default(label: &str, default: &str) -> Result<String> {
    let shown = if default.is_empty() { "" } else { default };
    let input = read_line(&format!("{label} [{shown}] (Enter keeps, - clears): "))?;
    Ok(match input.as_str() {
        "" => default.to_string(),
        "-" => String::new(),
        _ => input,
    })
}

/// Characters used for generated passwords.
const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz\
0123456789!@#$%^&*()-_=+[]{}:,.?";

/// Generate a random password from the OS RNG. Rejection sampling keeps the
/// character distribution uniform.
pub fn generate_password(len: usize) -> Result<String> {
    anyhow::ensure!(len > 0, "password length must be at least 1");
    let limit = 256 - (256 % CHARSET.len());
    let mut out = String::with_capacity(len);
    'outer: loop {
        let mut buf = [0u8; 64];
        password_manager_core::crypto::fill_random(&mut buf).context("generating password")?;
        for b in buf {
            if (b as usize) < limit {
                out.push(CHARSET[b as usize % CHARSET.len()] as char);
                if out.len() == len {
                    break 'outer;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_password_has_requested_length_and_charset() {
        let pw = generate_password(32).unwrap();
        assert_eq!(pw.len(), 32);
        assert!(pw.bytes().all(|b| CHARSET.contains(&b)));
    }

    #[test]
    fn generated_passwords_differ() {
        assert_ne!(
            generate_password(24).unwrap(),
            generate_password(24).unwrap()
        );
    }

    #[test]
    fn zero_length_rejected() {
        assert!(generate_password(0).is_err());
    }
}
