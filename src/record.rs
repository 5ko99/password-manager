use std::ops::{Index, IndexMut};

use serde::{Deserialize, Serialize};

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct Record {
    pub name: String,
    pub username: String,
    pub email: String,
    pub password: String,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name
    }
}

impl Index<usize> for Record {
    type Output = String;

    fn index(&self, index: usize) -> &String {
        if let Some(value) = self.get(index) {
            value
        } else {
            panic!("Index out of bounds");
        }
    }
}

impl IndexMut<usize> for Record {
    fn index_mut(&mut self, index: usize) -> &mut String {
        if let Some(value) = self.get_mut(index) {
            value
        } else {
            panic!("Index out of bounds");
        }
    }
}

impl Record {
    pub fn new(name: &str, username: &str, email: &str, password: &str) -> Record {
        Record {
            name : name.to_string(),
            username : username.to_string(),
            email : email.to_string(),
            password : password.to_string(),
        }
    }

    pub fn get(&self, index: usize) -> Option<&String> {
        match index {
            0 => Some(&self.name),
            1 => Some(&self.username),
            2 => Some(&self.email),
            3 => Some(&self.password),
            _ => None,
        }
    }

    pub fn get_mut(&mut self, index: usize) -> Option<&mut String> {
        match index {
            0 => Some(&mut self.name),
            1 => Some(&mut self.username),
            2 => Some(&mut self.email),
            3 => Some(&mut self.password),
            _ => None,
        }
    }

    pub fn len() -> usize {
        4
    }

    pub fn clear(&mut self) {
        self.name.clear();
        self.username.clear();
        self.email.clear();
        self.password.clear();
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty()
            && self.username.is_empty()
            && self.email.is_empty()
            && self.password.is_empty()
    }
}
