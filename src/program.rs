use crate::record::Record;
use crate::directory::Directory;
use crate::terminal::Terminal;


pub struct Program {
    records: Vec<Record>,
    should_quit: bool,
    directories: Vec<Directory>,
    terminal: Terminal,
}

impl Program {
    pub fn Default() -> Program {
        Program {
            records: Vec::new(),
            should_quit: false,
            directories: Vec::new(),
            terminal: Terminal::default().expect("Initializing terminal failed."),
        }
    }

    


}