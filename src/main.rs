

use aes::cipher::consts::{B0, B1};
use aes::cipher::typenum::{UTerm, UInt};
use argon2::{self, Config, Variant, Version, ThreadMode};
use aes::{Aes256, Aes128};
use aes::cipher::{
    BlockCipher, BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use tui::Frame;
use tui::backend::Backend;

use std::{io, thread, time::Duration};
use tui::{
    backend::CrosstermBackend,
    widgets::{Widget, Block, Borders},
    layout::{Layout, Constraint, Direction},
    Terminal
};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};



fn main() -> Result<(), io::Error> {
    let password = "password";
    let salt = b"randomsalt";
    let config = Config::default();
    // let hash = argon2::hash_encoded(password, salt, &config).unwrap();
    // println!("{}", hash.len());
    // let matches = argon2::verify_encoded(&hash, password).unwrap();
    // let salt2 = b"petko&emi";
    // let hash2 = argon2::hash_encoded(password, salt2, &config).unwrap();
    // print!("{}", hash2.len());
    // println!("{}", hash2);
    // let matches2 = argon2::verify_encoded(&hash2, password).unwrap();
    // println!("{}", matches2);
    // assert!(hash != hash2);
    // assert!(matches);

    let hash = md5::compute(password).0;

    let key  = GenericArray::from_slice(&hash);
    //&GenericArray<u8, UInt<UInt<UInt<UInt<UInt<UInt<UTerm, B1>, B0>, B0>, B0>, B0>,B0>>
    let mut block = GenericArray::from([42u8; 16]);
    let cipher = Aes128::new(key);

    let block_copy = block.clone();
    cipher.encrypt_block(&mut block);

    println!("{:?}", block);

    cipher.decrypt_block(&mut block);
    println!("{:?}", block);
    assert_eq!(block, block_copy);

    // setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    terminal.draw(|f| {
        let size = f.size();
        let block = Block::default()
            .title("Block")
            .borders(Borders::ALL);
        //f.render_widget(block, size);
        ui(f)
    })?;

    thread::sleep(Duration::from_millis(5000));

    // restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    Ok(())

}

fn ui<B: Backend>(f: &mut Frame<B>) {
    let chunks = Layout::default()
         .direction(Direction::Vertical)
         .margin(1)
         .constraints(
             [
                 Constraint::Percentage(10),
                 Constraint::Percentage(80),
                 Constraint::Percentage(10)
             ].as_ref()
         )
         .split(f.size());
     let block = Block::default()
          .title("Block")
          .borders(Borders::ALL);
     f.render_widget(block, chunks[0]);
     let block = Block::default()
          .title("Block 2")
          .borders(Borders::ALL);
     f.render_widget(block, chunks[1]);
 }