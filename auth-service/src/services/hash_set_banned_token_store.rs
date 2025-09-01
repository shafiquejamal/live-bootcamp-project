use std::collections::HashSet;

use crate::domain::{BannedTokenStore, BannedTokenStoreError};

#[derive(Default)]
pub struct HashSetBannedTokenStore {
    tokens: HashSet<String>,
}

#[async_trait::async_trait]
impl BannedTokenStore for HashSetBannedTokenStore {
    async fn add_token(&mut self, token: String) -> Result<(), BannedTokenStoreError> {
        self.tokens.insert(token);
        Ok(())
    }

    async fn contains_token(&self, token: &str) -> Result<bool, BannedTokenStoreError> {
        Ok(self.tokens.get(token).is_some())
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[tokio::test]
    async fn test_add_token() {
        let mut store = HashSetBannedTokenStore::default();
        let result = store.add_token("foo".to_owned()).await;
        assert_eq!(result, Ok(()));
        assert!(store.contains_token("foo").await.unwrap());
    }

    #[tokio::test]
    async fn test_contains_token() {
        let mut store = HashSetBannedTokenStore::default();
        store.tokens.insert("bar".to_owned());

        assert!(store.contains_token("bar").await.unwrap())
    }
}
