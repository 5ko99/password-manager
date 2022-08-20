use std::io::{stdout, self};

use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
use password_manager::program::{User, Program, self};
use tui::Terminal;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut program = program::Program::default();
    program.run()
}
