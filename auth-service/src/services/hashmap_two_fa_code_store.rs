use std::collections::HashMap;

use crate::domain::{
    data_stores::{LoginAttemptId, TwoFACode, TwoFACodeStore, TwoFACodeStoreError},
    email::Email,
};

#[derive(Default)]
pub struct HashmapTwoFACodeStore {
    codes: HashMap<Email, (LoginAttemptId, TwoFACode)>,
}

impl HashmapTwoFACodeStore {
    pub fn new() -> Self {
        Self {
            codes: HashMap::new(),
        }
    }

    pub fn new_with_codes(codes: HashMap<Email, (LoginAttemptId, TwoFACode)>) -> Self {
        Self { codes }
    }
}

// TODO: implement TwoFACodeStore for HashmapTwoFACodeStore
#[async_trait::async_trait]
impl TwoFACodeStore for HashmapTwoFACodeStore {
    async fn add_code(
        &mut self,
        email: Email,
        login_attempt_id: LoginAttemptId,
        code: TwoFACode,
    ) -> Result<(), TwoFACodeStoreError> {
        match self.codes.insert(email, (login_attempt_id, code)) {
            Some(_) => Ok(()),
            None => Ok(()),
        }
    }
    async fn remove_code(&mut self, email: &Email) -> Result<(), TwoFACodeStoreError> {
        match self.codes.remove(&email) {
            Some(_) => Ok(()),
            None => Err(TwoFACodeStoreError::UnexpectedError),
        }
    }

    async fn get_code(
        &self,
        email: &Email,
    ) -> Result<(LoginAttemptId, TwoFACode), TwoFACodeStoreError> {
        match self.codes.get(email) {
            Some(pair) => Ok(pair.clone()),
            None => Err(TwoFACodeStoreError::LoginAttemptIdNotFound),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::domain::{Email, LoginAttemptId, TwoFACode};

    #[tokio::test]
    async fn test_add_code_succeeds() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email::parse(String::from("a@b.com")).unwrap();
        let login_attempt_id =
            LoginAttemptId::parse(String::from("02ce228e-f1f4-40a5-bb1d-e1ab52391008")).unwrap();
        let code = TwoFACode::parse(String::from("345678")).unwrap();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let retrieved_code = store.get_code(&email).await;
        assert_eq!(retrieved_code, Ok((login_attempt_id, code)))
    }

    #[tokio::test]
    async fn test_remove_code_succeeds() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email::parse(String::from("a@b.com")).unwrap();
        let login_attempt_id =
            LoginAttemptId::parse(String::from("02ce228e-f1f4-40a5-bb1d-e1ab52391008")).unwrap();
        let code = TwoFACode::parse(String::from("345678")).unwrap();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let retrieved_code = store.get_code(&email).await;
        assert_eq!(retrieved_code, Ok((login_attempt_id, code)));
        let result = store.remove_code(&email).await;
        assert_eq!(result, Ok(()));
    }

    #[tokio::test]
    async fn test_remove_code_fails() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email::parse(String::from("a@b.com")).unwrap();
        let login_attempt_id =
            LoginAttemptId::parse(String::from("02ce228e-f1f4-40a5-bb1d-e1ab52391008")).unwrap();
        let code = TwoFACode::parse(String::from("345678")).unwrap();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let retrieved_code = store.get_code(&email).await;
        assert_eq!(retrieved_code, Ok((login_attempt_id, code)));
        let result = store.remove_code(&email).await;
        assert_eq!(result, Ok(()));
        let result = store.remove_code(&email).await;
        assert_eq!(result, Err(TwoFACodeStoreError::UnexpectedError));
    }

    #[tokio::test]
    async fn test_get_code_succeeds() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email::parse(String::from("a@b.com")).unwrap();
        let login_attempt_id =
            LoginAttemptId::parse(String::from("02ce228e-f1f4-40a5-bb1d-e1ab52391008")).unwrap();
        let code = TwoFACode::parse(String::from("345678")).unwrap();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let retrieved_code = store.get_code(&email).await;
        assert_eq!(retrieved_code, Ok((login_attempt_id, code)));
    }

    #[tokio::test]
    async fn test_get_code_fails() {
        let mut store = HashmapTwoFACodeStore::new();
        let email = Email::parse(String::from("a@b.com")).unwrap();
        let login_attempt_id =
            LoginAttemptId::parse(String::from("02ce228e-f1f4-40a5-bb1d-e1ab52391008")).unwrap();
        let code = TwoFACode::parse(String::from("345678")).unwrap();
        store
            .add_code(email.clone(), login_attempt_id.clone(), code.clone())
            .await
            .unwrap();
        let non_matching_email = Email::parse(String::from("foo@bar.com")).unwrap();
        let retrieved_code = store.get_code(&non_matching_email).await;
        assert_eq!(
            retrieved_code,
            Err(TwoFACodeStoreError::LoginAttemptIdNotFound)
        );
    }
}
