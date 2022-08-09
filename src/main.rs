use std::io::{stdout, self};

use crossterm::terminal::{enable_raw_mode, disable_raw_mode};
use password_manager::{program::{self, User}, security::{decrypt_data, encrypt_data}};
use tui::Terminal;
use password_manager::security;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // let mut program = program::Program::default();
    // program.run()

    let user : User = User {
        username: String::from("petkooooo"),
        password: String::from("1234"),
    };

    let block = String::from("Hello, I'm Petko!");
    let enc_block = encrypt_data(&block, &user);
    println!("{:?}", enc_block);
    let dec_block = decrypt_data(&enc_block, &user);
    println!("{}", dec_block);

    Ok(())
}
