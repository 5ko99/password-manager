use crate::record::Record;
use crate::directory::Directory;

#[derive(Default, Debug)]
pub struct Program {
    records: Vec<Record>,
    should_quit: bool,
    directories: Vec<Directory>,
    //terminal: Terminal,
}

impl Program {
    pub fn new() -> Program {
        Program {
            ..Default::default()
        }
    }


}