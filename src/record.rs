use crate::directory::Directory;

#[derive(Default, Debug)]
pub struct Record {
    pub record_name: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub password: Option<String>,
    pub file_name: Option<String>,
    pub directory: Option<Box<Directory>>,
}