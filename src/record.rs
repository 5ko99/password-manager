

#[derive(Default, Debug, Clone)]
pub struct Record {
    pub record_name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    deleted: bool,
}

impl PartialEq for Record {
    fn eq(&self, other: &Self) -> bool {
        self.record_name == other.record_name
    }
}

impl Record {
    pub fn new(record_name: String, username: Option<String>, email: Option<String>, password: Option<String>,) -> Record {
        let mut rec = Record {
            record_name: record_name.clone(),
            deleted: false,
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

    pub fn delete_record(&mut self) {
        self.deleted = true;
    }

    pub fn is_deleted(&self) -> bool {
        self.deleted
    }
}