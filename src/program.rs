use std::error::Error;
use std::io::{self, Stdout};
use std::sync::mpsc::{self};
use std::time::{Duration, Instant};
use std::{fs, thread};

use crossterm::event::{self, Event};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use naive_opt::string_search_indices;
use sha256::digest;
use snafu::Snafu;
use terminal_clipboard::ClipboardError;
use tui::backend::CrosstermBackend;
use tui::layout::{Alignment, Constraint, Direction, Layout};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans};
use tui::widgets::{
    Block, BorderType, Borders, Cell, List, ListItem, ListState, Paragraph, Row, Table, Tabs,
};
use tui::Terminal;

use crate::encryption::{decrypt_data, encrypt_data, EncryptionError};
use crate::input_handler::handle_input;
use crate::record::Record;
use crate::user::User;

const PATH_TO_CONFIG: &str = "./data/.conf";

pub const MINIMUM_PASSWORD_LENGTH: usize = 4;

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
    #[snafu(display("Password must be at least {err} chars:"))]
    PasswordTooShort { err: usize },
}

pub struct Program {
    pub records: Vec<Record>,
    pub should_quit: bool,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    pub active_menu_item: MenuItem,
    pub logged_user: Option<User>,
    pub show_password: bool,
    pub popup: Option<Popup>,
    pub search_term: String,
    pub search_results: Vec<usize>,
    pub search_results_index: Option<usize>,
    pub editing_existing_record: bool,
    pub mode: Mode,
    pub new_password: String,
    pub generating_password_options: GeneratePasswordOptions,
}

pub enum ProgramEvent<I> {
    Input(I),
    Tick,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MenuItem {
    Main,
    Add,
    Help,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Mode {
    Normal,
    Insert,
    Popup,
    Search,
    ChangePass,
    InputBox,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Popup {
    DeleteARecord,
    DeleteAnAccount,
    Exit,
    RecordAlreadyExists { name: String },
    Search,
    Error { message: String },
    Information { message: String },
    ChangePassword,
    InputBox { message: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratePasswordOptions {
    pub length: String,
    pub uppercase: bool,
    pub lowercase: bool,
    pub numbers: bool,
    pub symbols: bool,
}

impl GeneratePasswordOptions {
    pub fn default() -> Self {
        Self {
            length: "8".to_string(),
            uppercase: true,
            lowercase: true,
            numbers: true,
            symbols: false,
        }
    }
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
            popup: None,
            search_term: String::new(),
            search_results: Vec::new(),
            search_results_index: None,
            editing_existing_record: false,
            mode: Mode::Normal,
            new_password: String::new(),
            generating_password_options: GeneratePasswordOptions::default(),
        }
    }

    pub fn initial_login(&mut self) -> Result<(), Box<dyn Error>> {
        self.terminal.clear()?;
        self.terminal.show_cursor()?;
        disable_raw_mode().expect("Failed to disable raw mode");
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
        self.terminal.clear()?;
        self.terminal.hide_cursor()?;
        enable_raw_mode().expect("Failed to enable raw mode");
        Ok(())
    }

    pub fn run(&mut self) -> Result<(), Box<dyn Error>> {
        self.initial_login()?;

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

        self.active_menu_item = MenuItem::Main;

        let mut record_list_state = ListState::default();
        record_list_state.select(Some(0));

        let mut edit_list_state = ListState::default();
        edit_list_state.select(Some(0));

        let mut edit_record = Record::new("", "", "", "");

        let mut confirmed_password: String = String::new();

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
                                    if let Some(help_paragraph) = Program::render_help_line(
                                        MenuItem::Main,
                                        &self.logged_user.as_ref().unwrap().username,
                                    ) {
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
                                        Color::Yellow,
                                    );
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                                Popup::DeleteAnAccount => {
                                    let popup_content = Program::render_popup(
                                        "Do you want to delete this account? (y/n)",
                                        Color::Red,
                                    );
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                                Popup::Exit => {
                                    let popup_content = Program::render_popup(
                                        "Do you want to exit? (y/n)",
                                        Color::Yellow,
                                    );
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                                Popup::Error { message } => {
                                    let message =
                                        format!("Error! {} Press esc to close the popup.", message);
                                    let popup_content = Program::render_popup(&message, Color::Red);
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                                Popup::ChangePassword => {
                                    rect.render_widget(
                                        Program::render_change_password(
                                            &self.new_password,
                                            &self.show_password,
                                        ),
                                        chunks[2],
                                    );
                                }
                                Popup::Information { message } => {
                                    let popup_content =
                                        Program::render_popup(message, Color::Green);
                                    rect.render_widget(popup_content, chunks[2]);
                                }
                                Popup::InputBox { message } => {
                                    rect.render_widget(
                                        Program::render_input_box(
                                            message,
                                            self.generating_password_options
                                                .length
                                                .parse::<usize>()
                                                .unwrap_or(1),
                                        ),
                                        chunks[2],
                                    );
                                }
                            }
                        } else if let Some(help_paragraph) = Program::render_help_line(
                            MenuItem::Main,
                            &self.logged_user.as_ref().unwrap().username,
                        ) {
                            rect.render_widget(help_paragraph, chunks[2]);
                        }
                    }
                    MenuItem::Help => {
                        rect.render_widget(Program::render_help(), chunks[1]);
                    }
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
                        } else if let Some(help_paragraph) = Program::render_help_line(
                            MenuItem::Add,
                            &self.logged_user.as_ref().unwrap().username,
                        ) {
                            rect.render_widget(help_paragraph, chunks[2]);
                        }
                    }
                }
            })?;

            let handle_result = handle_input(
                self,
                &rx,
                &mut record_list_state,
                &mut edit_list_state,
                &mut edit_record,
                &mut confirmed_password,
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
            } else if username.len() < 4 {
                println!("Username is too short!");
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

        Ok(User::new(username, master_key))
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
                Err(Box::new(LogicError::DuplicationError { name: record.name }))
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
            let encrypted_data = encrypt_data(logged_user, &data);
            //TODO: fix the unwrap
            fs::write(path_to_data, encrypted_data.unwrap())
                .expect("Error while writing records to file!");
        } else {
            return Err(Box::new(LogicError::NoLoggedUser));
        }
        Ok(())
    }

    pub fn write_letter(letter: char, edit_list_state: &ListState, edit_record: &mut Record) {
        if let Some(selected) = edit_list_state.selected() {
            let data = &mut edit_record[selected];
            data.push(letter);
        }
    }

    pub fn copy_to_clipboard(
        &self,
        records_list_state: &mut ListState,
        n: u8,
    ) -> Result<(), ClipboardError> {
        let selected_record = self
            .records
            .get(
                records_list_state
                    .selected()
                    .expect("there is always a selected record"),
            )
            .unwrap();
        let data = match n {
            1 => Some(selected_record.username.clone()),
            2 => Some(selected_record.email.clone()),
            3 => Some(selected_record.password.clone()),
            _ => None,
        };
        if let Some(data) = data {
            terminal_clipboard::set_string(data)?;
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
            Spans::from(vec![Span::raw("Press `F7` to change you password.")]),
            Spans::from(vec![Span::raw("Press `F8` to set the desired generated password length.")]),
            Spans::from(vec![Span::raw("Press `enter` when you are in edit/add mode to save the record.")]),
            Spans::from(vec![Span::raw("Press `esc` to go back to main when you are in edit/add mode.")]),
            Spans::from(vec![Span::raw("When you edit a record, you can only edit the username, email or password, but not the record name.")]),
            Spans::from(vec![Span::raw("Press `q` to quit.")]),
            Spans::from(vec![Span::raw("When you need to confirm something, a message will be shown in the bottom of the screen. Press 'y' to confirm and 'n' to cancel.")]),
            Spans::from(vec![Span::raw("Press `delete` to delete your account and all saved passwords.")]),
        ])
        .alignment(Alignment::Left)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .style(Style::default().fg(Color::White))
                .title("Help")
                .border_type(BorderType::Rounded),
        );
        home
    }

    fn render_help_line<'a>(
        active_menu_item: MenuItem,
        logged_user: &str,
    ) -> Option<Paragraph<'a>> {
        let logged_user_msg = format!("Logged in as: {}", logged_user);
        match active_menu_item {
            MenuItem::Main => {
                let paragraph = Paragraph::new(vec![
                    Spans::from(vec![Span::raw(logged_user_msg)]),
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

    fn render_input_box<'a>(message: &String, length: usize) -> Paragraph<'a> {
        let paragraph = Paragraph::new(Span::styled(
            format!("{}: {}", message, length),
            Style::default().fg(Color::White),
        ))
        .alignment(Alignment::Center);
        paragraph
    }

    fn render_change_password<'a>(new_password: &String, show_password: &bool) -> Paragraph<'a> {
        let shown_pass;
        if *show_password {
            shown_pass = new_password.clone();
        } else {
            shown_pass = "*".repeat(new_password.len());
        }
        let paragraph = Paragraph::new(Span::styled(
            format!("New password: {}", shown_pass),
            Style::default().fg(Color::Yellow),
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
            items.push(ListItem::new(record.username.clone()));
        }
        if record.email.is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(record.email.clone()));
        }
        if record.password.is_empty() {
            items.push(ListItem::new("_".to_string()));
        } else {
            items.push(ListItem::new(record.password.clone()));
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

    fn render_popup(prompt_text: &str, color: Color) -> Paragraph {
        let paragraph = Paragraph::new(Span::styled(
            prompt_text,
            Style::default()
                .add_modifier(Modifier::SLOW_BLINK)
                .fg(color),
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

    pub fn load_and_decrypt_data(&mut self) -> Result<(), Box<dyn Error>> {
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

            let data = match decrypt_data(logged_user, &encrypted_data) {
                Ok(data) => data,
                Err(error) => match error.downcast_ref::<EncryptionError>().unwrap() {
                    EncryptionError::EmptyBlockError {} => String::new(),
                    _ => return Err(error),
                },
            };

            let data: Result<Vec<Record>, serde_json::Error> = serde_json::from_str(&data);
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
        self.records.iter().find(|&record| record.name == name)
    }

    pub fn search(records: &Vec<Record>, needle: &str) -> Vec<usize> {
        let mut haystack = String::new();
        let mut indexes = Vec::new(); // all intervals are inclusive for both ends
        let mut result = Vec::new();
        for record in records {
            indexes.push((haystack.len(), haystack.len() + record.name.len(), false));
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

    pub fn change_password(new_pass: &str, user: &mut User) -> Result<(), Box<dyn Error>> {
        let new_pass_hash = digest(new_pass);
        let user_with_new_pass_hash = User::new(user.username.clone(), new_pass_hash);
        user.change_password(new_pass)?;
        let mut users = Program::load_config().expect("Critical error: failed to load config");
        let user_index = users
            .iter()
            .position(|u| u.username == user.username)
            .expect("Critical error: failed to find user in config");
        users[user_index] = user_with_new_pass_hash;
        fs::write(PATH_TO_CONFIG, &serde_json::to_vec(&users)?)?;

        Ok(())
    }
}
