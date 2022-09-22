use std::error::Error;
use std::io::{self, Stdout};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use std::{fs, thread};

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use naive_opt::string_search_indices;
use passwords::PasswordGenerator;
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

use crate::encryption::{encrypt_data, decrypt_data};
use crate::record::Record;

const PATH_TO_CONFIG: &str = "./data/.conf";

const MINIMUM_PASSWORD_LENGTH: usize = 4;

const MENU_TITLES: &[&str] = &["Main", "Add/Edit", "Help"];

#[derive(Debug, Snafu)]
pub enum LogicError {
    #[snafu(display("No logged user found!"))]
    NoLoggedUser,
    #[snafu(display("The element '{name}' is already in the list! Please choose another name."))]
    DuplicationError { name: String },
    #[snafu(display("The user '{name}' is already logged! Please logout first!"))]
    AlreadyLoggedUser { name: String },
    #[snafu(display("Always should be a selected record"))]
    NoSelectedRecord {},
    #[snafu(display("Unexpected error: {err}"))]
    UnexpectedError { err: String },
}

pub struct Program {
    records: Vec<Record>,
    should_quit: bool,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active_menu_item: MenuItem,
    logged_user: Option<User>,
    show_password: bool,
    edit_mode: bool,
    popup: Option<Popup>,
    search_term: String,
    search_results: Vec<usize>,
    search_results_index: Option<usize>,
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

    pub fn is_empty(&self) -> bool {
        self.username.is_empty() || self.password.is_empty()
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

#[derive(Debug, Clone, PartialEq, Eq)]
enum Popup {
    DeleteARecord,
    DeleteAnAccount,
    Exit,
    RecordAlreadyExists { name: String },
    Search,
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
            popup: None,
            search_term: String::new(),
            search_results: Vec::new(),
            search_results_index: None,
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
            } else {
                println!("Invalid input.");
            }
        }

        enable_raw_mode().expect("Failed to enable raw mode");
        let (tx, rx) = mpsc::channel();
        let tick_rate = Duration::from_millis(200);

        // Reading for events key press or tick
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

                if last_tick.elapsed() >= tick_rate && tx.send(ProgramEvent::Tick).is_ok() {
                    last_tick = Instant::now();
                }
            }
        });

        self.terminal.clear()?;

        self.active_menu_item = MenuItem::Main;

        let mut record_list_state = ListState::default();
        record_list_state.select(Some(0));

        let mut edit_list_state = ListState::default();
        edit_list_state.select(Some(0));

        let mut edit_record = Record::new("", "", "", "");

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
                            Constraint::Length(6),
                        ]
                        .as_ref(),
                    )
                    .split(size);

                let menu = MENU_TITLES
                    .iter()
                    .map(|item| {
                        Spans::from(vec![Span::styled(*item, Style::default().fg(Color::White))])
                    })
                    .collect();

                let tabs = Tabs::new(menu)
                    .select(self.active_menu_item.into())
                    .block(Block::default().title("Menu").borders(Borders::ALL))
                    .style(Style::default().fg(Color::White))
                    .highlight_style(
                        Style::default()
                            .fg(Color::Yellow)
                            .add_modifier(Modifier::UNDERLINED),
                    )
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
                        }
                        if let Some(popup) = &self.popup {
                            match popup {
                                Popup::RecordAlreadyExists { name: _ } => {
                                    if let Some(help_paragraph) =
                                        Program::render_help_line(MenuItem::Main)
                                    {
                                        rect.render_widget(help_paragraph, chunks[2]);
                                    }
                                }
                                Popup::Search => {
                                    rect.render_widget(
                                        Program::render_search(&self.search_term),
                                        chunks[2],
                                    );
                                }
                                Popup::DeleteARecord => {
                                    let popup_content = Program::render_popup(
                                        "Do you want to delete this record? (y/n)",
                                    );
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                                Popup::DeleteAnAccount => {
                                    let popup_content = Program::render_popup(
                                        "Do you want to delete this account? (y/n)",
                                    );
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                                Popup::Exit => {
                                    let popup_content =
                                        Program::render_popup("Do you want to exit? (y/n)");
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                            }
                        } else if let Some(help_paragraph) =
                            Program::render_help_line(MenuItem::Main)
                        {
                            rect.render_widget(help_paragraph, chunks[2]);
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

                        if let Some(Popup::RecordAlreadyExists { name }) = &self.popup {
                            let popup_content = Program::render_message(format!(
                                "Record with a name \"{}\", already exists!",
                                name
                            ));
                            rect.render_widget(popup_content, chunks[2]);
                        } else if let Some(help_paragraph) =
                            Program::render_help_line(MenuItem::Add)
                        {
                            rect.render_widget(help_paragraph, chunks[2]);
                        }
                    }
                }
            })?;

            let handle_result = self.handle_input(
                &rx,
                &mut record_list_state,
                &mut edit_list_state,
                &mut edit_record,
            );

            match handle_result {
                Ok(()) => {}
                Err(e) => {
                    if let Some(LogicError::DuplicationError { name }) =
                        e.downcast_ref::<LogicError>()
                    {
                        self.popup = Some(Popup::RecordAlreadyExists {
                            name: name.to_string(),
                        });
                    } else {
                        return Err(e);
                    }
                }
            }

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
            password: master_key,
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
        if self.logged_user.is_none() || self.logged_user.as_ref().unwrap().username != username {
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

    fn users_exist(username: &str, users: &[User]) -> bool {
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
            Err(Box::new(io::Error::new(
                io::ErrorKind::Other,
                "Username not found or wrong password!",
            )))
        } else {
            let user = User {
                username,
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

    pub fn add_record(&mut self, record: Record) -> Result<&Record, Box<dyn Error>> {
        if self.logged_user.is_some() {
            if self.records.contains(&record) {
                Err(Box::new(LogicError::DuplicationError {
                    name: record.name,
                }))
            } else {
                self.records.push(record);
                return Ok(self
                    .records
                    .last()
                    .expect("Critical error: failed to get last record"));
            }
        } else {
            Err(Box::new(LogicError::NoLoggedUser))
        }
    }

    pub fn delete_record(&mut self, record_name: &str) -> Result<(), Box<dyn Error>> {
        if self.logged_user.is_some() {
            self.records.retain(|r| r.name != record_name);
            Ok(())
        } else {
            Err(Box::new(LogicError::NoLoggedUser))
        }
    }

    pub fn save_data(&self) -> Result<(), Box<dyn Error>> {
        if let Some(logged_user) = &self.logged_user {
            let path_to_data = format!("./data/{}.json", logged_user.username);
            let data = serde_json::to_string(&self.records)?;
            let encrypted_data = encrypt_data(logged_user,&data);
            //fix the unwrap
            fs::write(path_to_data, encrypted_data.unwrap()).expect("Error while writing records to file!");
        } else {
            return Err(Box::new(LogicError::NoLoggedUser));
        }
        Ok(())
    }

    fn write_letter(letter: char, edit_list_state: &ListState, edit_record: &mut Record) {
        if let Some(selected) = edit_list_state.selected() {
            let data = &mut edit_record[selected];
            data.push(letter);
        }
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
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('q');
                    } else if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Main;
                        self.popup = Some(Popup::Exit);
                    } else {
                        Program::write_letter('q', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('h') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('h');
                    } else if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Help;
                    } else {
                        Program::write_letter('h', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('a') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('a');
                    } else if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Add;
                        edit_list_state.select(Some(0));
                    } else {
                        Program::write_letter('a', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('m') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('m');
                    } else if self.active_menu_item != MenuItem::Add {
                        self.active_menu_item = MenuItem::Main;
                    } else {
                        Program::write_letter('m', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('s') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('s');
                    } else if self.active_menu_item != MenuItem::Add {
                        self.show_password = !self.show_password;
                    } else {
                        Program::write_letter('s', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('d') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('d');
                    } else if self.active_menu_item == MenuItem::Main {
                        self.popup = Some(Popup::DeleteARecord);
                    } else if self.active_menu_item == MenuItem::Add {
                        Program::write_letter('d', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('e') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('e');
                    } else if self.active_menu_item == MenuItem::Main {
                        self.active_menu_item = MenuItem::Add;
                        edit_list_state.select(Some(0));
                        if let Some(selected) = records_list_state.selected() {
                            edit_record.clone_from(&self.records[selected]);
                            self.edit_mode = true;
                        }
                    } else if self.active_menu_item == MenuItem::Add {
                        Program::write_letter('e', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('n') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('n');
                    } else if self.active_menu_item == MenuItem::Main {
                        self.popup = None;
                    } else if self.active_menu_item == MenuItem::Add {
                        Program::write_letter('n', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('f') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('f');
                    } else if self.active_menu_item == MenuItem::Main {
                        self.popup = Some(Popup::Search);
                    } else if self.active_menu_item == MenuItem::Add {
                        Program::write_letter('f', edit_list_state, edit_record);
                    }
                }
                KeyCode::Char('y') => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push('y');
                    } else if self.active_menu_item == MenuItem::Main {
                        if let Some(popup) = &self.popup {
                            match popup {
                                Popup::DeleteARecord => {
                                    if let Some(selected) = records_list_state.selected() {
                                        self.records.remove(selected);
                                        records_list_state.select(Some(0));
                                    } else {
                                        return Err(Box::new(LogicError::NoSelectedRecord {}));
                                    }
                                }
                                Popup::DeleteAnAccount => {
                                    if let Some(user) = self.logged_user.as_ref() {
                                        self.delete_user(user.username.clone().as_ref())?;
                                    } else {
                                        return Err(Box::new(LogicError::NoLoggedUser {}));
                                    }
                                }
                                Popup::Exit => self.should_quit = true,
                                _ => {}
                            }
                        }
                        self.popup = None;
                    } else if self.active_menu_item == MenuItem::Add {
                        Program::write_letter('y', edit_list_state, edit_record);
                    }
                }
                KeyCode::Up => {
                    if self.active_menu_item == MenuItem::Main {
                        if let Some(selected) = records_list_state.selected() {
                            let records_len = self.records.len();
                            if selected == 0 {
                                records_list_state.select(Some(records_len - 1));
                            } else {
                                records_list_state.select(Some(selected - 1));
                            }
                        }
                    } else if self.active_menu_item == MenuItem::Add {
                        if let Some(selected) = edit_list_state.selected() {
                            let len = Record::len(); // this is hardcoded for now
                            if selected == 0 {
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
                KeyCode::Left => {
                    if self.active_menu_item == MenuItem::Main
                        && self.popup == Some(Popup::Search)
                        && !self.search_results.is_empty()
                    {
                        if let Some(selected) = self.search_results_index {
                            if selected == 0 {
                                self.search_results_index = Some(self.search_results.len() - 1);
                            } else {
                                self.search_results_index = Some(selected - 1);
                            }
                            records_list_state.select(Some(
                                self.search_results[self.search_results_index.unwrap()],
                            ));
                        }
                    } else {
                        match self.active_menu_item {
                            MenuItem::Main => self.active_menu_item = MenuItem::Help,
                            MenuItem::Add => self.active_menu_item = MenuItem::Main,
                            MenuItem::Help => self.active_menu_item = MenuItem::Add,
                        }
                    }
                }
                KeyCode::Right => {
                    if self.active_menu_item == MenuItem::Main
                        && self.popup == Some(Popup::Search)
                        && !self.search_results.is_empty()
                    {
                        if let Some(selected) = self.search_results_index {
                            if selected == self.search_results.len() - 1 {
                                self.search_results_index = Some(0);
                            } else {
                                self.search_results_index = Some(selected + 1);
                            }
                            records_list_state.select(Some(
                                self.search_results[self.search_results_index.unwrap()],
                            ));
                        }
                    } else {
                        match self.active_menu_item {
                            MenuItem::Main => self.active_menu_item = MenuItem::Add,
                            MenuItem::Add => self.active_menu_item = MenuItem::Help,
                            MenuItem::Help => self.active_menu_item = MenuItem::Main,
                        }
                    }
                }
                KeyCode::Char(c) => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.push(c);
                    } else if self.active_menu_item == MenuItem::Add {
                        Program::write_letter(c, edit_list_state, edit_record);
                    }
                }
                KeyCode::Backspace => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.pop();
                    } else if self.active_menu_item == MenuItem::Add {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.pop();
                        }
                    }
                }
                KeyCode::Esc => {
                    if self.active_menu_item == MenuItem::Add {
                        self.active_menu_item = MenuItem::Main;
                    } else if self.active_menu_item == MenuItem::Main {
                        self.popup = None;
                        self.search_results.clear();
                        self.search_results_index = None;
                    }
                }
                KeyCode::Enter => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_results = Program::search(&self.records, &self.search_term);
                        if !self.search_results.is_empty() {
                            self.search_results_index = Some(0);
                            records_list_state.select(Some(self.search_results[0]));
                        } else {
                            self.popup = None;
                        }
                    } else if self.active_menu_item == MenuItem::Add
                        && !edit_record.name.is_empty()
                    {
                        // Remove the popup if there is one
                        self.popup = None;

                        if self.edit_mode {
                            if let Some(r) = self
                                .records
                                .iter_mut()
                                .find(|r| r == &edit_record)
                            {
                                r.clone_from(edit_record);
                                self.active_menu_item = MenuItem::Main;
                            }
                        } else if let Err(e) = self.add_record(edit_record.clone()) {
                            return Err(e);
                        } else {
                            self.active_menu_item = MenuItem::Main;
                        }
                        edit_record.clear();
                    }
                }
                KeyCode::Delete => {
                    if self.active_menu_item == MenuItem::Main && self.popup == Some(Popup::Search)
                    {
                        self.search_term.clear();
                    } else if self.active_menu_item == MenuItem::Main {
                        self.popup = Some(Popup::DeleteAnAccount);
                    } else if self.active_menu_item == MenuItem::Add {
                        if let Some(selected) = edit_list_state.selected() {
                            let data = &mut edit_record[selected];
                            data.clear();
                        }
                    }
                }
                KeyCode::F(n) => {
                    match n {
                        1 | 2 | 3 => {
                            // Copy the selected field 1 -> username, 2 -> email, 3 -> password
                            let selected_record = self
                                .records
                                .get(
                                    records_list_state
                                        .selected()
                                        .expect("there is always a selected record"),
                                )
                                .unwrap();
                            let data = match n {
                                1 => selected_record.username.clone(),
                                2 => selected_record.email.clone(),
                                3 => selected_record.password.clone(),
                                _ => unreachable!(),
                            };
                            // Copy the data to the clipboard
                            terminal_clipboard::set_string(data).unwrap();
                        }
                        4 => {
                            // Password generator
                            if self.active_menu_item == MenuItem::Add {
                                let pg = PasswordGenerator {
                                    length: 12,
                                    numbers: true,
                                    lowercase_letters: true,
                                    uppercase_letters: true,
                                    symbols: false,
                                    spaces: false,
                                    exclude_similar_characters: false,
                                    strict: true,
                                };

                                let password = pg.generate_one();
                                if let Ok(password) = password {
                                    edit_record.password = password;
                                }
                            }
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
            Spans::from(vec![Span::raw("Use `left` and `right` arrows to navigate through the menus. Use `up` and `down` arrows to navigate through the records and fields.")]),
            Spans::from(vec![Span::raw("Press 'm' from help menu to see the Main menu. Press `h` to see this help menu, from Main.")]),
            Spans::from(vec![Span::raw("Press `s` to toggle showing the password in Main menu.")]),
            Spans::from(vec![Span::raw("Press `a` to add a new record.")]),
            Spans::from(vec![Span::raw("Press `d` to delete the currently selected record.")]),
            Spans::from(vec![Span::raw("Press `e` to edit the currently selected record.")]),
            Spans::from(vec![Span::raw("Press 'f' to open search box. Type in the search term and press enter to search. To cancel search press ESC.")]),
            Spans::from(vec![Span::raw("When you are in search mode, use `left` and `right` arrows to navigate through all matches.")]),
            Spans::from(vec![Span::raw("When you view a record press F1 to copy the username, F2 to copy the email, F3 to copy the password. Press F4 to generate a random password when you are in Add/Edit mode.")]),
            Spans::from(vec![Span::raw("Press `enter` when you are in edit/add mode to save the record.")]),
            Spans::from(vec![Span::raw("Press `esc` to go back to main when you are in edit/add mode.")]),
            Spans::from(vec![Span::raw("When you edit a record, you can only edit the username, email or password, but not the record name.")]),
            Spans::from(vec![Span::raw("Press `q` to quit.")]),
            Spans::from(vec![Span::raw("When you need to confirm something, a message will be shown in the bottom of the screen. Press 'y' to confirm and 'n' to cancel.")]),
            Spans::from(vec![Span::raw("Press `delete` to delete your account and all saved passwords.")]),
        ])
        .alignment(Alignment::Center)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .title("Help")
                .border_type(BorderType::Rounded),
        );
        home
    }

    fn render_help_line<'a>(active_menu_item: MenuItem) -> Option<Paragraph<'a>> {
        match active_menu_item {
            MenuItem::Main => {
                let paragraph = Paragraph::new(vec![
                    Spans::from(vec![Span::raw("Press 'a' to add a new record. Press 'e' to start editing the current record. Press 'f' to open search box.")]),
                    Spans::from(vec![Span::raw("To cancel search press ESC. Press 'up' and 'down' arrows to navigate through fields. Press 'd' to delete the current record.")]),
                    Spans::from(vec![Span::raw("Press 's'` to toggle showing the password. Use 'left' and 'right' arrows to navigate through menus.")]),
                    Spans::from(vec![Span::raw("When you view a record press F1 to copy the username, F2 to copy the email, F3 to copy the password. Press 'q' to quit. Press 'h' to see the help page for more information.")]),
                ])
                .alignment(Alignment::Left)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::White).add_modifier(Modifier::ITALIC))
                        .title("Help")
                        .border_type(BorderType::Double),
                );
                Some(paragraph)
            }
            MenuItem::Add => {
                let paragraph = Paragraph::new(vec![
                    Spans::from(vec![Span::raw("Use 'up' and 'down' arrows to select a field. Use `left` and `right` arrows to navigate through the menus.")]),
                    Spans::from(vec![Span::raw("Press 'enter' to save the record. Use `left` and `right` arrows to navigate through the menus.")]),
                    Spans::from(vec![Span::raw("Press F4 to generate a random password. If you edit a record, you can only edit the username, email or password, but not the record name!")]),
                    Spans::from(vec![Span::raw("Press `esc` to go back to main menu. See help for more information.")]),
                ])
                .alignment(Alignment::Left)
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .style(Style::default().fg(Color::White).add_modifier(Modifier::ITALIC))
                        .title("Help")
                        .border_type(BorderType::Double),
                );
                Some(paragraph)
            }
            _ => None,
        }
    }

    fn render_search<'a>(search_text: &String) -> Paragraph<'a> {
        let paragraph = Paragraph::new(Span::styled(
            format!("Search: {}", search_text),
            Style::default().fg(Color::White),
        ))
        .alignment(Alignment::Center);
        paragraph
    }

    fn render_add<'a>(record: &Record) -> Option<(List<'a>, List<'a>)> {
        let mut items: Vec<_> = Vec::new();
        // We need to render something for each field in the record, even if the field is empty for now.
        if record.name.is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(record.name.clone()));
        }
        if record.username.is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(
                record.username.clone(),
            ));
        }
        if record.email.is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(
                record.email.clone(),
            ));
        }
        if record.password.is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(
                record.password.clone(),
            ));
        }

        let labels: Vec<_> = vec![
            ListItem::new("Record name"),
            ListItem::new("Username"),
            ListItem::new("Email"),
            ListItem::new("Password"),
        ];

        let records = Block::default()
            .borders(Borders::ALL)
            .style(Style::default().fg(Color::White))
            .border_type(BorderType::Plain);

        let labels_block = Block::default()
            .borders(Borders::ALL)
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
        records_list: &[Record],
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
                    record.name.clone(),
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

        let password = if *show_password {
            selected_record.password.clone()
        } else {
            "********".to_string()
        };

        let records_detail = Table::new(vec![Row::new(vec![
            Cell::from(Span::raw(selected_record.username)),
            Cell::from(Span::raw(selected_record.email)),
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

    fn render_popup(prompt_text: &str) -> Paragraph {
        let paragraph = Paragraph::new(Span::styled(
            prompt_text,
            Style::default()
                .add_modifier(Modifier::SLOW_BLINK)
                .fg(Color::Red),
        ));
        paragraph
    }

    fn render_message<'a>(message: String) -> Paragraph<'a> {
        let paragraph = Paragraph::new(Span::styled(
            message,
            Style::default().add_modifier(Modifier::BOLD).fg(Color::Red),
        ));
        paragraph
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

            let data = decrypt_data(logged_user,&encrypted_data);

            let data: Result<Vec<Record>, serde_json::Error> = serde_json::from_str(&data.unwrap());
            // TODO: Fix this function!

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

    pub fn get_len_of_records(&self) -> usize {
        self.records.len()
    }

    pub fn get_record_by_name(&self, name: &str) -> Option<&Record> {
        for record in &self.records {
            if record.name == name {
                return Some(record);
            }
        }
        None
    }

    pub fn search(records: &Vec<Record>, needle: &str) -> Vec<usize> {
        let mut haystack = String::new();
        let mut indexes = Vec::new(); // all intervals are inclusive for both ends
        let mut result = Vec::new();
        for record in records {
            indexes.push((
                haystack.len(),
                haystack.len() + record.name.len(),
                false,
            ));
            haystack.push_str(&record.name);
            haystack.push(' ');
        }
        let v: Vec<_> = string_search_indices(&haystack, needle).collect();

        for (i, _) in v {
            // the boolean flag is needed to avoid duplicates. for example if we have one record 'ab ab' and other 'ab' and we search for 'ab' we will get two indexes for the first record
            for (count, (start, end, flag)) in indexes.iter_mut().enumerate() {
                if !*flag && i >= *start && i <= *end {
                    result.push(count);
                    *flag = true;
                    break;
                }
            }
        }
        result
    }

    pub fn get_logged_user(&self) -> Option<&User> {
        match &self.logged_user {
            Some(user) => Some(user),
            None => None,
        }
    }
}