use std::sync::Arc;

use color_eyre::eyre::Context;
use redis::{Commands, Connection};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::domain::{
    Email,
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
};

pub struct RedisTwoFACodeStore {
    conn: Arc<RwLock<Connection>>,
}

impl RedisTwoFACodeStore {
    pub fn new(conn: Arc<RwLock<Connection>>) -> Self {
        Self { conn }
    }
}

#[async_trait::async_trait]
impl TwoFACodeStore for RedisTwoFACodeStore {
    #[tracing::instrument(name = "Adding 2FA code to Redis", skip_all)]
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        let key = get_key(&email);
        // 2. Create a TwoFATuple instance.
        let data = TwoFATuple(
            login_attempt_id.as_ref().to_owned(),
            code.as_ref().to_owned(),
        );
        // 3. Use serde_json::to_string to serialize the TwoFATuple instance into a JSON string.
        // Return TwoFACodeStoreError::UnexpectedError if serialization fails.
        let serialized = serde_json::to_string(&data)
            .wrap_err("failed to serialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        // 4. Call the set_ex command on the Redis connection to set a new key/value pair with an expiration time (TTL).
        // The value should be the serialized 2FA tuple.
        // The expiration time should be set to TEN_MINUTES_IN_SECONDS.
        // Return TwoFACodeStoreError::UnexpectedError if casting fails or the call to set_ex fails.
        let _: () = self
            .conn
            .write()
            .await
            .set_ex(&key, serialized, TEN_MINUTES_IN_SECONDS)
            .wrap_err("failed to set 2FA code in Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok(())
    }

    #[tracing::instrument(name = "Removing 2FA code from redis", skip_all)]
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        let key = get_key(email);
        // 2. Call the del command on the Redis connection to delete the 2FA code entry.
        let _: () = self
            .conn
            .write()
            .await
            .del(&key)
            .wrap_err("failed to delete 2FA code from Redis")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        // Return TwoFACodeStoreError::UnexpectedError if the operation fails.
        Ok(())
    }

    #[tracing::instrument(name = "Checking for 2FA code in Redis", skip_all)]
    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        // TODO:
        // 1. Create a new key using the get_key helper function.
        let key = get_key(email);
        // 2. Call the get command on the Redis connection to get the value stored for the key.
        let value_stored = self
            .conn
            .write()
            .await
            .get::<_, String>(&key)
            .map_err(|e| TwoFACodeStoreError::UnexpectedError(e.into()))?;
        // Return TwoFACodeStoreError::LoginAttemptIdNotFound if the operation fails.
        // If the operation succeeds, call serde_json::from_str to parse the JSON string into a TwoFATuple.
        // Then, parse the login attempt ID string and 2FA code string into a LoginAttemptId and TwoFACode type respectively.
        // Return TwoFACodeStoreError::UnexpectedError if parsing fails.
        let data: TwoFATuple = serde_json::from_str(&value_stored)
            .wrap_err("failed to deserialize 2FA tuple")
            .map_err(TwoFACodeStoreError::UnexpectedError)?;
        let login_attempt_id =
            LoginAttemptId::parse(data.0).map_err(TwoFACodeStoreError::UnexpectedError)?;
        let code = TwoFACode::parse(data.1).map_err(TwoFACodeStoreError::UnexpectedError)?;
        Ok((login_attempt_id, code))
    }
}

#[derive(Serialize, Deserialize)]
struct TwoFATuple(pub String, pub String);

const TEN_MINUTES_IN_SECONDS: u64 = 600;
const TWO_FA_CODE_PREFIX: &str = "two_fa_code:";

fn get_key(email: &Email) -> String {
    format!("{}{}", TWO_FA_CODE_PREFIX, email.as_ref())
}
