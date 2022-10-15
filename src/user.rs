use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub username: String, // must be max 16 characters long
    pub password: String,
}

impl User {
    pub fn new(username: String, password: String) -> User {
        if username.len() < 4 || password.len() < 4 {
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
}