use std::error::Error;
use std::io::{self, Stdout};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use std::{fs, thread};

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use serde::{Deserialize, Serialize};
use sha256::digest;
use snafu::Snafu;
use tui::backend::CrosstermBackend;
use tui::layout::{Alignment, Constraint, Direction, Layout};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans};
use tui::widgets::{
    Block, BorderType, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, Tabs,
};
use tui::Terminal;

use crate::record::Record;

use aes::cipher::{block_padding::Pkcs7, BlockDecryptMut, BlockEncryptMut, KeyIvInit};

use pbkdf2::{
    password_hash::{PasswordHasher, SaltString},
    Pbkdf2,
};


type Aes128CbcEnc = cbc::Encryptor<aes::Aes128>;
type Aes128CbcDec = cbc::Decryptor<aes::Aes128>;

const PATH_TO_CONFIG: &str = "./data/.conf";

const MINIMUM_PASSWORD_LENGTH: usize = 4;

const MENU_TITLES: &'static [&str] = &["Main", "Add", "Help"];

#[derive(Debug, Snafu)]
enum LogicError {
    #[snafu(display("No logged user found!"))]
    NoLoggedUser,
    #[snafu(display("The element '{name}' is already in the list! Please choose another name."))]
    DuplicationError { name: String },
    #[snafu(display("The user '{name}' is already logged! Please logout first!"))]
    AlreadyLoggedUser { name: String },
    #[snafu(display("Always should be a selected record"))]
    NoSelectedRecord {},
}

pub struct Program {
    records: Vec<Record>,
    should_quit: bool,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active_menu_item: MenuItem,
    logged_user: Option<User>,
    show_password: bool,
    edit_mode: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct User {
    pub username: String, // must be max 16 characters long
    pub password: String,
}

impl User {
    pub fn new(username: String, password: String) -> User {
        User { username, password }
    }
}

enum ProgramEvent<I> {
    Input(I),
    Tick,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum MenuItem {
    Main,
    Add,
    Help,
}

impl From<MenuItem> for usize {
    fn from(input: MenuItem) -> usize {
        match input {
            MenuItem::Main => 0,
            MenuItem::Add => 1,
            MenuItem::Help => 2,
        }
    }
}

impl Program {
    pub fn default() -> Program {
        Program {
            records: Vec::new(),
            should_quit: false,
            terminal: Terminal::new(CrosstermBackend::new(io::stdout())).unwrap(),
            active_menu_item: MenuItem::Main,
            logged_user: None,
            show_password: false,
            edit_mode: false,
        }
    }

    fn get_register_info() -> Result<User, Box<dyn Error>> {
        let mut username = String::new();
        let mut master_key;
        let users = Program::load_config().expect("Critical error: failed to load config");

        loop {
            println!("Please enter your username: ");
            io::stdin().read_line(&mut username)?;
            username = username.trim().to_string();
            if Program::users_exist(&username, &users) {
                println!("Username already exists!");
                continue;
            } else if username.len() > 16 {
                println!("Username is too long!");
            } else {
                break;
            }
        }

        loop {
            master_key = rpassword::prompt_password("Please enter your master key: ").unwrap();
            master_key = master_key.trim().to_string();
            if master_key.len() >= MINIMUM_PASSWORD_LENGTH {
                break;
            } else {
                println!(
                    "Master key must be at least {} characters long!",
                    MINIMUM_PASSWORD_LENGTH
                );
            }
        }

        master_key = digest(master_key);

        let user = User {
            username: username.to_string(),
            password: master_key.to_string(),
        };

        Ok(user)
    }

    pub fn register_user(&self, user: User) -> Result<(), Box<dyn Error>> {
        if self.logged_user.is_some() {
            return Err(LogicError::AlreadyLoggedUser {
                name: user.username,
            }
            .into());
        }

        let mut users = Program::load_config().expect("Critical error: failed to load config");

        if Program::users_exist(&user.username, &users) {
            return Err(LogicError::DuplicationError {
                name: user.username,
            }
            .into());
        } else {
        }

        users.push(user);
        fs::write(PATH_TO_CONFIG, &serde_json::to_vec(&users)?)?;
        Ok(())
    }

    pub fn delete_user(&mut self, username: &str) -> Result<(), Box<dyn Error>> {
        if self.logged_user.is_none() && self.logged_user.as_ref().unwrap().username != username {
            // if the user is not logged in and the username is not the same as the one to be deleted throw error
            return Err(LogicError::NoLoggedUser.into());
        }

        let mut users = Program::load_config().expect("Critical error: failed to load config");
        users.retain(|u| u.username != username);
        fs::write(PATH_TO_CONFIG, &serde_json::to_vec(&users)?)?; // remove the user from the config file

        let path_to_data = format!("./data/{}.json", username);

        fs::remove_file(path_to_data).expect("Error while deleting user data!"); // remove the user's file

        self.should_quit = true; // quit the program at the next tick
        Ok(())
    }

    fn users_exist(username: &str, users: &Vec<User>) -> bool {
        users.iter().any(|u| u.username == username)
    }

    fn get_login_info() -> (String, String, String) {
        let mut username = String::new();
        println!("Please enter your username: ");
        io::stdin()
            .read_line(&mut username)
            .expect("Failed to read username");
        let username = username.trim();

        let master_key = rpassword::prompt_password("Please enter your master key: ").unwrap();
        let master_key = master_key.trim();
        let master_key_hash = digest(master_key);

        (
            username.to_string(),
            master_key.to_string(),
            master_key_hash,
        )
    }

    pub fn login(
        &mut self,
        username: String,
        master_key: String,
        master_key_hash: String,
    ) -> Result<(), Box<dyn Error>> {
        if let Some(logged_user) = &self.logged_user {
            return Err(Box::new(LogicError::AlreadyLoggedUser {
                name: logged_user.username.clone(),
            }));
        }

        let users = Program::load_config().expect("Critical error: failed to load config");
        let user = users
            .iter()
            .find(|u| u.username == username && u.password == master_key_hash);
        if user.is_none() {
            return Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Username not found or wrong password!",
            )));
        } else {
            let user = User {
                username: username,
                password: master_key,
            };
            self.logged_user = Some(user); // Login successful.
            Ok(())
        }
    }

    pub fn logout(&mut self) -> Result<(), Box<dyn Error>> {
        self.save_data()?;
        self.logged_user = None;
        self.records = Vec::new();
        Ok(())
    }

    fn load_config() -> Result<Vec<User>, Box<dyn Error>> {
        let config = fs::read_to_string(PATH_TO_CONFIG)?;
        if config.is_empty() {
            return Ok(Vec::new());
        }
        let parsed: Vec<User> = serde_json::from_str(&config)?;
        Ok(parsed)
    }

    fn load_and_decrypt_data(&mut self) -> Result<(), Box<dyn Error>> {
        if let Some(logged_user) = &self.logged_user {
            let path_to_data = format!("./data/{}.json", logged_user.username);
            let encrypted_data = fs::read(&path_to_data);
            let encrypted_data = match encrypted_data {
                Ok(data) => data,
                Err(error) => match error.kind() {
                    io::ErrorKind::NotFound => {
                        fs::write(path_to_data, b"")?;
                        Vec::new()
                    }
                    _ => {
                        return Err(Box::new(error));
                    }
                },
            };

            let data = self.decrypt_data(&encrypted_data);

            let data: Result<Vec<Record>, serde_json::Error> = serde_json::from_str(&data);

            // if there is an error, just return an empty vector
            let data = match data {
                Ok(data) => data,
                Err(_) => Vec::new(),
            };

            for record in data {
                self.records.push(record);
            }
        } else {
            return Err(Box::new(LogicError::NoLoggedUser));
        }

        Ok(())
    }

    pub fn add_record(&mut self, record: Record) -> Result<&Record, Box<dyn Error>> {
        if self.logged_user.is_some() {
            if self.records.contains(&record) {
                return Err(Box::new(LogicError::DuplicationError {
                    name: record.record_name,
                }));
            } else {
                self.records.push(record);
                return Ok(&self
                    .records
                    .last()
                    .expect("Critical error: failed to get last record"));
            }
        } else {
            return Err(Box::new(LogicError::NoLoggedUser));
        }
    }

    pub fn delete_record(&mut self, record_name: &str) -> Result<(), Box<dyn Error>> {
        if self.logged_user.is_some() {
            self.records.retain(|r| r.record_name != record_name);
            Ok(())
        } else {
            return Err(Box::new(LogicError::NoLoggedUser));
        }
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            println!("Enter l to login, or r to register.");
            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let input = input.trim();
            if input == "l" {
                let (username, master_key, master_key_hash) = Program::get_login_info();
                match self.login(username, master_key, master_key_hash) {
                    Ok(()) => {
                        self.load_and_decrypt_data()?;
                        break;
                    }
                    Err(e) => {
                        println!("{}", e);
                    }
                }
            } else if input == "r" {
                let user = Program::get_register_info()?;
                self.register_user(user)?;
                println!("User registered successfully!");
                //break;
            } else {
                println!("Invalid input.");
            }
        }

        // let record = Record::new("YouTube".to_string(), Some("vanyo66".to_string()), Some("vanyo@abv.bg".to_string()), Some("a1w222".to_string()));
        // self.add_record(record).unwrap();

        enable_raw_mode().expect("Failed to enable raw mode");
        let (tx, rx) = mpsc::channel();
        let tick_rate = Duration::from_millis(200);
        thread::spawn(move || {
            let mut last_tick = Instant::now();
            loop {
                let timeout = tick_rate
                    .checked_sub(last_tick.elapsed())
                    .unwrap_or_else(|| Duration::from_secs(0));

                if event::poll(timeout).expect("poll works") {
                    if let Event::Key(key) = event::read().expect("can read events") {
                        tx.send(ProgramEvent::Input(key)).expect("can send events");
                    }
                }

                if last_tick.elapsed() >= tick_rate {
                    if let Ok(_) = tx.send(ProgramEvent::Tick) {
                        last_tick = Instant::now();
                    }
                }
            }
        });

        self.terminal.clear()?;

        self.active_menu_item = MenuItem::Main;

        let mut record_list_state = ListState::default();
        record_list_state.select(Some(0));

        let mut edit_list_state = ListState::default();
        edit_list_state.select(Some(0));

        let mut edit_record = Record::new("".to_string(), None, None, None);

        loop {
            self.terminal.draw(|rect| {
                let size = rect.size();
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .margin(2)
                    .constraints(
                        [
                            Constraint::Length(3),
                            Constraint::Min(2),
                            Constraint::Length(3),
                        ]
                        .as_ref(),
                    )
                    .split(size);

                let menu = MENU_TITLES
                    .iter()
                    .map(|t| {
                        let (first, rest) = t.split_at(1);
                        Spans::from(vec![
                            Span::styled(
                                first,
                                Style::default()
                                    .fg(Color::Yellow)
                                    .add_modifier(Modifier::UNDERLINED),
                            ),
                            Span::styled(rest, Style::default().fg(Color::White)),
                        ])
                    })
                    .collect();

                let tabs = Tabs::new(menu)
                    .select(self.active_menu_item.clone().into())
                    .block(Block::default().title("Menu").borders(Borders::ALL))
                    .style(Style::default().fg(Color::White))
                    .highlight_style(Style::default().fg(Color::Yellow))
                    .divider(Span::raw("|"));

                rect.render_widget(tabs, chunks[0]);

                match self.active_menu_item {
                    MenuItem::Main => {
                        let records_chunk = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [Constraint::Percentage(20), Constraint::Percentage(80)].as_ref(),
                            )
                            .split(chunks[1]);
                        let render_result = Program::render_records(
                            &record_list_state,
                            &self.records,
                            &self.show_password,
                        );
                        if let Some((left, right)) = render_result {
                            rect.render_stateful_widget(
                                left,
                                records_chunk[0],
                                &mut record_list_state,
                            );
                            rect.render_widget(right, records_chunk[1]);
                        } else {
                        }
                    }
                    MenuItem::Help => rect.render_widget(Program::render_help(), chunks[1]),
                    MenuItem::Add => {
                        let edit_chunk = Layout::default()
                            .direction(Direction::Horizontal)
                            .constraints(
                                [Constraint::Percentage(20), Constraint::Percentage(80)].as_ref(),
                            )
                            .split(chunks[1]);

                        if let Some((left, right)) = Program::render_add(&edit_record) {
                            rect.render_stateful_widget(left, edit_chunk[0], &mut edit_list_state);
                            rect.render_widget(right, edit_chunk[1]);
                        }
                    }
                }
            })?;

            self.handle_input(
                &rx,
                &mut record_list_state,
                &mut edit_list_state,
                &mut edit_record,
            )?;

            if self.should_quit {
                self.save_data()?;
                self.terminal.clear()?;
                disable_raw_mode().expect("Failed to disable raw mode");
                self.terminal.show_cursor()?;
                break;
            }
        }

        Ok(())
    }

    pub fn save_data(&self) -> Result<(), Box<dyn Error>> {
        if let Some(logged_user) = &self.logged_user {
            let path_to_data = format!("./data/{}.json", logged_user.username);
            let data = serde_json::to_string(&self.records)?;
            let encrypted_data = self.encrypt_data(&data);
            fs::write(path_to_data, encrypted_data).expect("Error while writing records to file!");
        } else {
            return Err(Box::new(LogicError::NoLoggedUser));
        }
        Ok(())
    }

    fn handle_input(
        &mut self,
        rx: &Receiver<ProgramEvent<KeyEvent>>,
        records_list_state: &mut ListState,
        edit_list_state: &mut ListState,
        edit_record: &mut Record,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // handle events
        match rx.recv()? {
            ProgramEvent::Input(event) => match event.code {
                KeyCode::Char('q') => {
                    if self.active_menu_item != MenuItem::Add {
                        self.should_quit = true;
                    } else {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push('q');
                        }
                    }
                }
                KeyCode::Char('h') => {
                    if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Help;
                    } else {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push('h');
                        }
                    }
                }
                KeyCode::Char('a') => {
                    if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Add;
                        edit_list_state.select(Some(0));
                    } else {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push('a');
                        }
                    }
                }
                KeyCode::Char('m') => {
                    if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Main;
                    } else {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push('m');
                        }
                    }
                }
                KeyCode::Char('s') => {
                    if self.active_menu_item != MenuItem::Add {
                        self.show_password = !self.show_password;
                    } else {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push('s');
                        }
                    }
                }
                KeyCode::Char('d') => {
                    if self.active_menu_item != MenuItem::Add
                        && self.active_menu_item == MenuItem::Main
                    {
                        if let Some(selected) = records_list_state.selected() {
                            self.records.remove(selected);
                            records_list_state.select(Some(0));
                        } else {
                            return Err(Box::new(LogicError::NoSelectedRecord {}));
                        }
                    } else {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push('d');
                        }
                    }
                }
                KeyCode::Char('e') => {
                    if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Add;
                        edit_list_state.select(Some(0));
                        if let Some(selected) = records_list_state.selected() {
                            edit_record.clone_from(&self.records[selected]);
                            self.edit_mode = true;
                        }
                    } else {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push('e');
                        }
                    }
                }
                KeyCode::Up => {
                    if self.active_menu_item == MenuItem::Main {
                        if let Some(selected) = records_list_state.selected() {
                            let records_len = self.records.len();
                            if selected <= 0 {
                                records_list_state.select(Some(records_len - 1));
                            } else {
                                records_list_state.select(Some(selected - 1));
                            }
                        }
                    } else if self.active_menu_item == MenuItem::Add {
                        if let Some(selected) = edit_list_state.selected() {
                            let len = Record::len(); // this is hardcoded for now
                            if selected <= 0 {
                                edit_list_state.select(Some(len - 1));
                            } else {
                                edit_list_state.select(Some(selected - 1));
                            }
                        }
                    }
                }
                KeyCode::Down => {
                    if self.active_menu_item == MenuItem::Main {
                        if let Some(selected) = records_list_state.selected() {
                            let records_len = self.records.len();
                            if selected >= records_len - 1 {
                                records_list_state.select(Some(0));
                            } else {
                                records_list_state.select(Some(selected + 1));
                            }
                        }
                    } else if self.active_menu_item == MenuItem::Add {
                        if let Some(selected) = edit_list_state.selected() {
                            let len = Record::len(); // this is hardcoded for now
                            if selected >= len - 1 {
                                edit_list_state.select(Some(0));
                            } else {
                                edit_list_state.select(Some(selected + 1));
                            }
                        }
                    }
                }
                KeyCode::Left => {}
                KeyCode::Right => {}
                KeyCode::Char(c) => {
                    if self.active_menu_item == MenuItem::Add {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.push(c);
                        }
                    }
                }
                KeyCode::Backspace => {
                    if self.active_menu_item == MenuItem::Add {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.pop();
                        }
                    }
                }
                KeyCode::Esc => {
                    if self.active_menu_item == MenuItem::Add {
                        self.active_menu_item = MenuItem::Main;
                    }
                }
                KeyCode::Enter => {
                    if self.active_menu_item == MenuItem::Add && edit_record.record_name.len() > 0 {
                        self.active_menu_item = MenuItem::Main;
                        if self.edit_mode {
                            self.records
                                .iter_mut()
                                .find(|r| r.record_name == edit_record.record_name)
                                .map(|r| {
                                    r.clone_from(edit_record);
                                });
                        } else {
                            self.records.push(edit_record.clone());
                        }
                        edit_record.clear();
                    }
                }
                KeyCode::Delete => {
                    if let Some(user) = self.logged_user.as_ref() {
                        self.delete_user(user.username.clone().as_ref())?;
                    } else {
                        return Err(Box::new(LogicError::NoLoggedUser {}));
                    }
                },
                KeyCode::F(n) => {
                    match n {
                        1 | 2 | 3 => {
                            // Copy the selected field 1 -> username, 2 -> email, 3 -> password
                            let selected_record = self.records.get(
                                records_list_state
                                    .selected()
                                    .expect("there is always a selected record"),
                            ).unwrap();
                            let data;
                            match n {
                                1 => {
                                    data = selected_record.username.clone();
                                }
                                2 => {
                                    data = selected_record.email.clone();
                                }
                                3 => {
                                    data = selected_record.password.clone();
                                }
                                _ => unreachable!(),
                            }
                            // Copy the data to the clipboard
                            terminal_clipboard::set_string(data.unwrap_or_default()).unwrap();
                        }
                        _ => {}
                    }
                }
                _ => {}
            },
            ProgramEvent::Tick => {}
        }
        Ok(())
    }

    fn render_help<'a>() -> Paragraph<'a> {
        let home = Paragraph::new(vec![
            Spans::from(vec![Span::raw("")]),
            Spans::from(vec![Span::raw("Press `m` to return to the main menu.")]),
            Spans::from(vec![Span::raw("Press `h` to see this help menu.")]),
            Spans::from(vec![Span::raw("Press `s` to toggle showing the password.")]),
            Spans::from(vec![Span::raw("Press `q` to quit.")]),
            Spans::from(vec![Span::raw("Press `a` to add a new record.")]),
            Spans::from(vec![Span::raw("Press `d` to delete the current record.")]),
            Spans::from(vec![Span::raw("Press `e` to edit the current record.")]),
            Spans::from(vec![Span::raw("Press `up` and `down` to select a record.")]),
            Spans::from(vec![Span::raw("Press `left` and `right` to select a field.")]),
            Spans::from(vec![Span::raw("Press `enter` when you are in edit/add mode to save the record.")]),
            Spans::from(vec![Span::raw("Press `esc` to go back to main when you are in edit/add mode.")]),
            Spans::from(vec![Span::raw("When you edit a record, you can only edit the username, email or password.")]),
            Spans::from(vec![Span::raw("You can't edit the record name, because it's the record ID. You have to delete it and create a new one.")]),
            Spans::from(vec![Span::raw("Press `delete` to delete your account and all saved passwords.")]),
        ])
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .title("Help")
                .border_type(BorderType::Plain),
        );
        home
    }

    fn render_add<'a>(record: &Record) -> Option<(List<'a>, List<'a>)> {
        let mut items: Vec<_> = Vec::new();
        // We need to render something for each field in the record, even if the field is empty for now.
        if record.record_name.is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(record.record_name.clone()));
        }
        if record.username.is_none() || record.username.as_ref().unwrap().is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(
                record.username.clone().unwrap_or("_".to_string()),
            ));
        }
        if record.email.is_none() || record.email.as_ref().unwrap().is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(
                record.email.clone().unwrap_or("_".to_string()),
            ));
        }
        if record.password.is_none() || record.password.as_ref().unwrap().is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(
                record.password.clone().unwrap_or("_".to_string()),
            ));
        }

        let mut labels: Vec<_> = Vec::new();
        labels.push(ListItem::new("Record Name".to_string()));
        labels.push(ListItem::new("Username".to_string()));
        labels.push(ListItem::new("Email".to_string()));
        labels.push(ListItem::new("Password".to_string()));

        let records = Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White))
            .title("Records list")
            .border_type(BorderType::Plain);

        let labels_block = Block::default()
            .borders(Borders::ALL)
            .title("Labels")
            .border_type(BorderType::Plain);

        let list = List::new(items).block(records);

        let labels = List::new(labels)
            .block(labels_block)
            .highlight_style(
                Style::default()
                    .bg(Color::Yellow)
                    .fg(Color::Black)
                    .add_modifier(Modifier::BOLD),
            )
            .highlight_symbol(">")
            .repeat_highlight_symbol(true);

        Some((labels, list))
    }

    fn render_records<'a>(
        records_list_state: &ListState,
        records_list: &Vec<Record>,
        show_password: &bool,
    ) -> Option<(List<'a>, Table<'a>)> {
        let records = Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White))
            .title("Records list")
            .border_type(BorderType::Plain);

        let items: Vec<_> = records_list
            .iter()
            .map(|record| {
                ListItem::new(Spans::from(vec![Span::styled(
                    record.record_name.clone(),
                    Style::default(),
                )]))
            })
            .collect();

        let selected_record = records_list.get(
            records_list_state
                .selected()
                .expect("there is always a selected record"),
        );

        let selected_record = match selected_record {
            Some(record) => record.clone(),
            None => return None,
        };

        let list = List::new(items).block(records).highlight_style(
            Style::default()
                .bg(Color::Yellow)
                .fg(Color::Black)
                .add_modifier(Modifier::BOLD),
        );

        let password: String;
        if *show_password {
            password = selected_record.password.unwrap_or_default().to_string();
        } else {
            password = "********".to_string();
        }

        let records_detail = Table::new(vec![Row::new(vec![
            Cell::from(Span::raw(
                selected_record.username.unwrap_or_default().to_string(),
            )),
            Cell::from(Span::raw(
                selected_record.email.unwrap_or_default().to_string(),
            )),
            Cell::from(Span::raw(password)),
        ])])
        .header(Row::new(vec![
            Cell::from(Span::styled(
                "Username",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Cell::from(Span::styled(
                "Email",
                Style::default().add_modifier(Modifier::BOLD),
            )),
            Cell::from(Span::styled(
                "Password",
                Style::default().add_modifier(Modifier::BOLD),
            )),
        ]))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .title("Detail information")
                .border_type(BorderType::Plain),
        )
        .widths(&[
            Constraint::Percentage(22),
            Constraint::Percentage(55),
            Constraint::Percentage(23),
        ]);

        Some((list, records_detail))
    }

    pub fn decrypt_data(&self, block: &Vec<u8>) -> String {
        let user = match &self.logged_user {
            Some(u) => u,
            None => panic!("No logged user!"),
        };

        // if the block is empty, return an empty string
        if block.is_empty() {
            return String::new();
        }

        let password = user.password.as_bytes();

        let mut username_for_salt = user.username.clone();
        username_for_salt.shrink_to(16);
        for _ in 0..16 - user.username.len() {
            username_for_salt.push('p');
        }

        assert_eq!(username_for_salt.len(), 16);

        let salt = match SaltString::new(&username_for_salt) {
            Ok(salt) => salt,
            Err(e) => {
                panic!("Error while creating salt string:{}", e);
            }
        };

        let password_hash = match Pbkdf2.hash_password(password, &salt) {
            Ok(hash) => hash,
            Err(e) => panic!("Error while hashing the master key:{}", e),
        };

        let password_hash = match password_hash.hash {
            Some(hash) => hash.to_string(),
            None => panic!("Error while hashing the master key"),
        };

        let mut key: [u8; 16] = [0; 16];

        for i in 0..16 {
            key[i] = password_hash.as_bytes()[i];
        }

        let iv = username_for_salt.as_bytes();

        let cipher = Aes128CbcDec::new_from_slices(&key, &iv);

        let cipher = match cipher {
            Ok(cipher) => cipher,
            Err(e) => panic!("Error while creating the cipher: {}", e),
        };

        let decrypt_block = cipher.decrypt_padded_vec_mut::<Pkcs7>(block.as_slice());

        let decrypt_block = match decrypt_block {
            Ok(block) => block,
            Err(e) => panic!("Error while decrypting the block: {}", e),
        };

        let mut decrypt_block_string: String = String::new();

        for i in 0..decrypt_block.len() {
            decrypt_block_string.push(decrypt_block[i] as char);
        }

        decrypt_block_string
    }

    pub fn encrypt_data(&self, block: &str) -> Vec<u8> {
        let user = match &self.logged_user {
            Some(u) => u,
            None => panic!("No logged user!"),
        };

        let password = user.password.as_bytes();

        let mut username_for_salt = user.username.clone();
        username_for_salt.shrink_to(16);
        for _ in 0..16 - user.username.len() {
            username_for_salt.push('p');
        }

        assert_eq!(username_for_salt.len(), 16);

        let salt = match SaltString::new(&username_for_salt) {
            Ok(salt) => salt,
            Err(e) => {
                panic!("Error while creating salt string:{}", e);
            }
        };

        let password_hash = match Pbkdf2.hash_password(password, &salt) {
            Ok(hash) => hash,
            Err(e) => panic!("Error while hashing the master key:{}", e),
        };

        let password_hash = match password_hash.hash {
            Some(hash) => hash.to_string(),
            None => panic!("Error while hashing the master key"),
        };

        let mut key: [u8; 16] = [0; 16];

        for i in 0..16 {
            key[i] = password_hash.as_bytes()[i];
        }

        let iv = username_for_salt.as_bytes();

        let cipher = Aes128CbcEnc::new_from_slices(&key, &iv);

        let cipher = match cipher {
            Ok(cipher) => cipher,
            Err(e) => panic!("Error while creating the cipher: {}", e),
        };

        let encrypt_block = cipher.encrypt_padded_vec_mut::<Pkcs7>(block.as_bytes());

        encrypt_block
    }

    pub fn get_len_of_records(&self) -> usize {
        self.records.len()
    }

    pub fn get_record_by_name(&self, name: &str) -> Option<&Record> {
        for record in &self.records {
            if record.record_name == name {
                return Some(record);
            }
        }
        None
    }
}
