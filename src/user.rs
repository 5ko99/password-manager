use serde::{Serialize, Deserialize};
use std::error::Error;

use crate::program::{LogicError, MINIMUM_PASSWORD_LENGTH};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub username: String, // must be max 16 characters long
    pub password: String,
}

impl User {
    pub fn new(username: String, password: String) -> User {
        if username.len() < MINIMUM_PASSWORD_LENGTH || password.len() < MINIMUM_PASSWORD_LENGTH {
            panic!("Username and password must be at least 4 characters long!");
        } else {
            User {
                username,
                password,
            }
        }
    }

    pub fn is_empty(&self) -> bool {
        self.username.is_empty() || self.password.is_empty()
    }

    pub fn change_password(&mut self, new_pass : &str) -> Result<(), Box<dyn Error>> {
        if new_pass.len() < MINIMUM_PASSWORD_LENGTH {
            return Err((LogicError::PasswordTooShort { err: MINIMUM_PASSWORD_LENGTH }).into());
        } else {
            self.password = new_pass.to_string();
        }
        Ok(())
    }
}