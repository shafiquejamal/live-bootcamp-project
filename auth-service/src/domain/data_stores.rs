use super::{Email, Password, User};
use color_eyre::eyre::{Context, Report, Result, eyre};
use rand::Rng;
use secrecy::{ExposeSecret, Secret};
use thiserror::Error;

#[async_trait::async_trait]
pub trait UserStore {
    // TODO: Add the `add_user`, `get_user`, and `validate_user` methods.
    // Make sure all methods are async so we can use async user stores in the future
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError>;
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError>;
    async fn validate_user(&self, email: &Email, password: &Password)
    -> Result<(), UserStoreError>;
}

#[async_trait::async_trait]
pub trait BannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError>;
    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError>;
}

#[derive(Debug, Error)]
pub enum BannedTokenStoreError {
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

#[derive(Debug, Error)]
pub enum UserStoreError {
    #[error("User already exists")]
    UserAlreadyExists,
    #[error("User not found")]
    UserNotFound,
    #[error("Invalid credentials")]
    InvalidCredentials,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for UserStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::UserAlreadyExists, Self::UserAlreadyExists)
                | (Self::UserNotFound, Self::UserNotFound)
                | (Self::InvalidCredentials, Self::InvalidCredentials)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}
// This trait represents the interface all concrete 2FA code stores should implement
#[async_trait::async_trait]
pub trait TwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError>;
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError>;
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError>;
}

#[derive(Debug, Error)]
pub enum TwoFACodeStoreError {
    #[error("Login Attempt ID not found")]
    LoginAttemptIdNotFound,
    #[error("Unexpected error")]
    UnexpectedError(#[source] Report),
}

impl PartialEq for TwoFACodeStoreError {
    fn eq(&self, other: &Self) -> bool {
        matches!(
            (self, other),
            (Self::LoginAttemptIdNotFound, Self::LoginAttemptIdNotFound)
                | (Self::UnexpectedError(_), Self::UnexpectedError(_))
        )
    }
}

#[derive(Debug, Clone)]
pub struct LoginAttemptId(Secret<String>);

impl PartialEq for LoginAttemptId {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl LoginAttemptId {
    pub fn parse(id: String) -> Result<Self> {
        // Updated!
        let parsed_id = uuid::Uuid::parse_str(&id).wrap_err("Invalid login attempt id")?;
        Ok(Self(Secret::new(parsed_id.to_string())))
    }
}

impl Default for LoginAttemptId {
    fn default() -> Self {
        Self(Secret::new(uuid::Uuid::new_v4().to_string())) // Use the `uuid` crate to generate a random version 4 UUID
    }
}

impl AsRef<Secret<String>> for LoginAttemptId {
    fn as_ref(&self) -> &Secret<String> {
        &self.0
    }
}

#[derive(Clone, Debug)]
pub struct TwoFACode(Secret<String>);

impl PartialEq for TwoFACode {
    fn eq(&self, other: &Self) -> bool {
        self.0.expose_secret() == other.0.expose_secret()
    }
}

impl TwoFACode {
    pub fn parse(code: String) -> Result<Self> {
        // Ensure `code` is a valid 6-digit code
        // check length of String
        if code.len() != 6 {
            Err(eyre!("Invalid code".to_string()))
        } else {
            match code.parse::<u64>() {
                Ok(parsed_code) => {
                    if parsed_code >= 100000 && parsed_code <= 999_999 {
                        Ok(TwoFACode(Secret::new(code)))
                    } else {
                        Err(eyre!("Invalid code".to_string()))
                    }
                }
                Err(_) => Err(eyre!("Invalid code".to_string())),
            }
        }
        // check min and max
    }
}

impl Default for TwoFACode {
    fn default() -> Self {
        // Use the `rand` crate to generate a random 2FA code.
        // The code should be 6 digits (ex: 834629)
        Self(Secret::new(
            rand::thread_rng().gen_range(000_000..=999_999).to_string(),
        ))
    }
}

// TODO: Implement AsRef<str> for TwoFACode
impl AsRef<Secret<String>> for TwoFACode {
    fn as_ref(&self) -> &Secret<String> {
        return &self.0;
    }
}
