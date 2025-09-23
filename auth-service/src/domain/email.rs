use color_eyre::eyre::{Result, eyre};
use std::hash::Hash;
use validator::validate_email;

use secrecy::{ExposeSecret, Secret};
#[derive(Debug, Clone)]
pub struct Email(Secret<String>);

impl Email {
    pub fn parse(s: Secret<String>) -> Result<Self> {
        if validate_email(s.expose_secret()) {
            Ok(Self(s))
        } else {
            Err(eyre!(format!(
                "{} is not a valid email address.",
                s.expose_secret()
            )))
        }
    }
}
// New!
impl PartialEq for Email {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

// New!
impl Hash for Email {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.expose_secret().hash(state);
    }
}
impl Eq for Email {}

impl AsRef<Secret<String>> for Email {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::Email;

    use fake::Fake;
    use fake::faker::internet::en::SafeEmail;
    use secrecy::Secret;

    #[test]
    fn empty_string_is_rejected() {
        let email = Secret::new("".to_string());
        assert!(Email::parse(email).is_err());
    }
    #[test]
    fn email_missing_at_symbol_is_rejected() {
        let email = Secret::new("ursuladomain.com".to_string());
        assert!(Email::parse(email).is_err());
    }
    #[test]
    fn email_missing_subject_is_rejected() {
        let email = Secret::new("@domain.com".to_string());
        assert!(Email::parse(email).is_err());
    }

    #[derive(Debug, Clone)]
    struct ValidEmailFixture(pub String);

    impl quickcheck::Arbitrary for ValidEmailFixture {
        fn arbitrary<G: quickcheck::Gen>(g: &mut G) -> Self {
            let email = SafeEmail().fake_with_rng(g);
            Self(email)
        }
    }

    #[quickcheck_macros::quickcheck]
    fn valid_emails_are_parsed_successfully(valid_email: ValidEmailFixture) -> bool {
        Email::parse(Secret::new(valid_email.0)).is_ok()
    }
}
