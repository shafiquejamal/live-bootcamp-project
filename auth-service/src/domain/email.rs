use validator::validate_email;

#[derive(PartialEq, Debug, Clone, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(email: String) -> Result<Self, String> {
        if validate_email(&email) {
            Ok(Self(email))
        } else {
            Err(format!("{} is not a valid email address.", email))
        }
    }
}

impl AsRef<str> for Email {
    fn as_ref(&self) -> &str {
        return &self.0;
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    fn test_valid_email() {
        let valid_email_address = "super@duper.com".to_owned();
        assert_eq!(
            Email::parse(valid_email_address.clone()),
            Ok(Email(valid_email_address))
        )
    }

    #[test]
    fn test_invalid_email() {
        let invalid_email_address = "notanaddress.com".to_owned();
        assert_eq!(
            Email::parse(invalid_email_address),
            Err("notanaddress.com is not a valid email address.".to_owned())
        );
    }
}
