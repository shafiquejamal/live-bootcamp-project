use std::collections::HashMap;

use crate::domain::{Email, Password, UserStore, UserStoreError, user::User};

// TODO: Create a new struct called `HashmapUserStore` containing a `users` field
// which stores a `HashMap`` of email `String`s mapped to `User` objects.
// Derive the `Default` trait for `HashmapUserStore`.
#[derive(Default)]
pub struct HashmapUserStore {
    users: HashMap<Email, User>,
}

impl HashmapUserStore {
    pub fn new() -> Self {
        Self {
            users: HashMap::new(),
        }
    }
}

#[async_trait::async_trait]
impl UserStore for HashmapUserStore {
    async fn add_user(&mut self, user: User) -> Result<(), UserStoreError> {
        // Return `UserStoreError::UserAlreadyExists` if the user already exists,
        // otherwise insert the user into the hashmap and return `Ok(())`.
        if self.users.contains_key(&user.email) {
            return Err(UserStoreError::UserAlreadyExists);
        }

        self.users.insert(user.email.clone(), user);

        Ok(())
    }

    // TODO: Implement a public method called `get_user`, which takes an
    // immutable reference to self and an email string slice as arguments.
    // This function should return a `Result` type containing either a
    // `User` object or a `UserStoreError`.
    // Return `UserStoreError::UserNotFound` if the user can not be found.
    async fn get_user(&self, email: &Email) -> Result<User, UserStoreError> {
        self.users
            .get(email)
            .map(|user| Ok(user.clone()))
            .unwrap_or(Err(UserStoreError::UserNotFound))
    }

    // TODO: Implement a public method called `validate_user`, which takes an
    // immutable reference to self, an email string slice, and a password string slice
    // as arguments. `validate_user` should return a `Result` type containing either a
    // unit type `()` if the email/password passed in match an existing user, or a `UserStoreError`.
    // Return `UserStoreError::UserNotFound` if the user can not be found.
    // Return `UserStoreError::InvalidCredentials` if the password is incorrect.
    async fn validate_user(
        &self,
        email: &Email,
        password: &Password,
    ) -> Result<(), UserStoreError> {
        let user = &self.get_user(email).await?;
        if &user.password != password {
            return Err(UserStoreError::InvalidCredentials);
        }
        Ok(())
    }
}

// TODO: Add unit tests for your `HashmapUserStore` implementation
#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_add_user() {
        let mut user_store = HashmapUserStore::new();
        let user = User {
            email: Email::parse(String::from("a@test.com")).unwrap(),
            password: Password::parse(String::from("some-password-1")).unwrap(),
            requires_2fa: false,
        };
        let initial_insert_result = user_store.add_user(user.clone()).await;
        assert_eq!(initial_insert_result, Ok(()));
        let subsequent_insert_result = user_store.add_user(user).await;
        assert_eq!(
            subsequent_insert_result,
            Err(UserStoreError::UserAlreadyExists)
        )
    }

    #[tokio::test]
    async fn test_get_user() {
        let user = User {
            email: Email::parse(String::from("a@test.com")).unwrap(),
            password: Password::parse(String::from("some-password-1")).unwrap(),
            requires_2fa: false,
        };
        let mut users = HashMap::new();
        users.insert(user.email.clone(), user.clone());
        let user_store = HashmapUserStore { users };
        let no_matching_user_result = user_store
            .get_user(&Email::parse("b@test.com".to_owned()).unwrap())
            .await;
        assert_eq!(no_matching_user_result, Err(UserStoreError::UserNotFound));
        let user_exists_result = user_store.get_user(&user.email).await;
        assert_eq!(user_exists_result, Ok(user))
    }

    #[tokio::test]
    async fn test_validate_user() {
        let user = User {
            email: Email::parse(String::from("a@test.com")).unwrap(),
            password: Password::parse(String::from("some-password-1")).unwrap(),
            requires_2fa: false,
        };
        let mut users = HashMap::new();
        users.insert(user.email.clone(), user.clone());
        let user_store = HashmapUserStore { users };
        let result_invalid = user_store
            .validate_user(
                &user.email,
                &Password::parse("wrong-password".to_owned()).unwrap(),
            )
            .await;
        assert_eq!(result_invalid, Err(UserStoreError::InvalidCredentials));
        let result_user_does_not_exist = user_store
            .validate_user(
                &Email::parse("c@test.com".to_owned()).unwrap(),
                &Password::parse("some-password-1".to_owned()).unwrap(),
            )
            .await;
        assert_eq!(
            result_user_does_not_exist,
            Err(UserStoreError::UserNotFound)
        );
        let result_valid = user_store.validate_user(&user.email, &user.password).await;
        assert_eq!(result_valid, Ok(()))
    }
}
