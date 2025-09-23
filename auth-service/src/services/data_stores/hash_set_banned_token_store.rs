use std::collections::HashSet;

use secrecy::{ExposeSecret, Secret};

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: Secret<String>) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token.expose_secret().to_owned());
        Ok(())
    }

    async fn contains_token(&self, token: &Secret<String>) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.get(token.expose_secret()).is_some())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashSetBannedTokenStore::default();
        let result = store.add_token(Secret::new("foo".to_owned())).await;
        assert!(result.is_ok());
        assert!(
            store
                .contains_token(&Secret::new("foo".to_owned()))
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn test_contains_token() {
        let mut store = HashSetBannedTokenStore::default();
        store.tokens.insert("bar".to_owned());

        assert!(
            store
                .contains_token(&Secret::new("bar".to_owned()))
                .await
                .unwrap()
        )
    }
}
