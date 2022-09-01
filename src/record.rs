use std::ops::{Index, IndexMut};

use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    pub record_name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.record_name == other.record_name
    }
}

impl Index<usize> for Record {
    type Output = String;

    fn index<'a>(&'a self, _index: usize) -> &'a String {
        if let Some(value) = self.get(_index) {
            value
        } else {
            panic!("Index out of bounds");
        }
    }
}

impl IndexMut<usize> for Record {
    fn index_mut<'a>(&'a mut self, _index: usize) -> &'a mut String {
        if let Some(value) = self.get_mut(_index) {
            value
        } else {
            panic!("Index out of bounds");
        }
    }
}

impl Record {
    pub fn new(
        record_name: String,
        username: Option<String>,
        email: Option<String>,
        password: Option<String>,
    ) -> Record {
        let mut rec = Record {
            record_name: record_name.clone(),
            ..Default::default()
        };
        if username.is_some() {
            rec.username = username.clone();
        }
        if email.is_some() {
            rec.email = email.clone();
        }
        if password.is_some() {
            rec.password = password.clone();
        }
        rec
    }

    pub fn get<'a>(&'a self, _index: usize) -> Option<&'a String> {
        match _index {
            0 => Some(&self.record_name),
            1 => {
                if self.username.is_some() {
                    Some(&self.username.as_ref().unwrap())
                } else {
                    None
                }
            }
            2 => {
                if self.email.is_some() {
                    Some(&self.email.as_ref().unwrap())
                } else {
                    None
                }
            }
            3 => {
                if self.password.is_some() {
                    Some(&self.password.as_ref().unwrap())
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    pub fn get_mut<'a>(&'a mut self, _index: usize) -> Option<&'a mut String> {
        match _index {
            0 => Some(&mut self.record_name),
            1 => {
                if self.username.is_none() {
                    // If the username is None, we create a new String and assign it to the username
                    self.username = Some(String::new());
                    return self.username.as_mut();
                } else if let Some(username) = &mut self.username {
                    return Some(username);
                } else {
                    panic!("Unknown error!");
                }
            }
            2 => {
                if self.email.is_none() {
                    // If the email is None, we create a new String and assign it to the email
                    self.email = Some(String::new());
                    return self.email.as_mut();
                } else if let Some(email) = &mut self.email {
                    return Some(email);
                } else {
                    panic!("Unknown error!");
                }
            }
            3 => {
                if self.password.is_none() {
                    // If the password is None, we create a new String and assign it to the password
                    self.password = Some(String::new());
                    return self.password.as_mut();
                } else if let Some(password) = &mut self.password {
                    return Some(password);
                } else {
                    panic!("Unknown error!");
                }
            }
            _ => None,
        }
    }

    pub fn len() -> usize {
        4
    }

    pub fn clear(&mut self) {
        self.record_name = String::new();
        self.username = None;
        self.email = None;
        self.password = None;
    }
}
