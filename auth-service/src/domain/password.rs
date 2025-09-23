use color_eyre::eyre::{Result, eyre};

#[derive(Clone, Debug, PartialEq)]
pub struct Password(String);

impl Password {
    pub fn parse(password: String) -> Result<Password> {
        if password.len() >= 8 {
            Ok(Password(password))
        } else {
            Err(eyre!(format!("{} is not a valid password", password)))
        }
    }
}

impl AsRef<str> for Password {
    fn as_ref(&self) -> &str {
        self.0.as_ref()
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    pub fn valid_password() {
        let valid_password = "long enough".to_owned();
        assert_eq!(
            Password::parse(valid_password.clone()),
            Ok(Password(valid_password))
        )
    }

    #[test]
    pub fn invalid_password() {
        let invalid_password = "2short".to_owned();
        assert_eq!(
            Password::parse(invalid_password.clone()),
            Err("2short is not a valid password".to_owned())
        )
    }
}
