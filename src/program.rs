use std::error::Error;
use std::io::{self, Stdout};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use std::{fs, thread};

use crossterm::event::{self, Event, KeyCode, KeyEvent};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use serde::{Serialize, Deserialize};
use sha256::digest;
use snafu::Snafu;
use tui::backend::CrosstermBackend;
use tui::layout::{Alignment, Constraint, Direction, Layout};
use tui::style::{Color, Modifier, Style};
use tui::text::{Span, Spans};
use tui::widgets::{Block, BorderType, Borders, ListState, Paragraph, Tabs, Wrap};
use tui::Terminal;

use crate::directory::Directory;
use crate::record::Record;

const PATH_TO_CONFIG: &str = "./data/.conf";

const MINIMUM_PASSWORD_LENGTH: usize = 4;

const MENU_TITLES: &'static [&str] = &["Main", "Add", "Help"];

#[derive(Debug, Snafu)]
enum LogicError {
    #[snafu(display("No logged user found!"))]
    NoLoggedUser,
    #[snafu(display("The widget '{widget_name}' could not be found"))]
    WidgetNotFound { widget_name: String },
}


pub struct Program {
    records: Vec<Record>,
    should_quit: bool,
    directories: Vec<Directory>,
    terminal: Terminal<CrosstermBackend<Stdout>>,
    active_menu_item: MenuItem,
    logged_user: Option<User>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct User {
    username: String,
    password: String,
}

enum ProgramEvent<I> {
    Input(I),
    Tick,
}

#[derive(Copy, Clone, Debug)]
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
            directories: Vec::new(),
            terminal: Terminal::new(CrosstermBackend::new(io::stdout())).unwrap(),
            active_menu_item: MenuItem::Main,
            logged_user: None,
        }
    }

    fn register_user(&self) -> Result<(), Box<dyn Error>> {
        let mut username = String::new();
        let mut master_key = String::new();
        let mut users = Program::load_config().expect("Critical error: failed to load config");

        loop {
            println!("Please enter your username: ");
            io::stdin().read_line(&mut username)?;
            username = username.trim().to_string();
            if !Program::users_exist(&username,&users) {
                println!("Username already exists!");
                continue;
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
                println!("Master key must be at least {} characters long!", MINIMUM_PASSWORD_LENGTH);
            }
        }

        master_key = digest(master_key); 
        let user = User {
            username: username.to_string(),
            password: master_key.to_string(),
        };
        
        users.push(user);

        fs::write(PATH_TO_CONFIG, &serde_json::to_vec(&users)?)?;
        Ok(())
    }

    fn users_exist(username: &str, users: &Vec<User>) -> bool {
        !users.iter().any(|u| u.username == username)
    }

    fn login(&mut self) -> Result<(User), Box<dyn Error>> {

        let mut username = String::new();
        println!("Please enter your username: ");
        io::stdin().read_line(&mut username)?;
        let username = username.trim();

        let master_key = rpassword::prompt_password("Please enter your master key: ").unwrap();
        let master_key = master_key.trim();
        let master_key = digest(master_key);

        let users = Program::load_config().expect("Critical error: failed to load config");
        let user = users.iter().find(|u| u.username == username);
        if user.is_none() {
            return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Username not found!")));
        } else {
            let user = user.unwrap();
            if user.password == master_key {
                //TODO: Change user password to hashed version of encryption key.
                let password = user.password.clone();
                return Ok(User{
                    username: username.to_string(),
                    password: password,
                });
            } else {
                return Err(Box::new(io::Error::new(io::ErrorKind::Other, "Incorrect master key!")));
            }
        }
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
        //TODO: Load data after login, and decrypt it.
        if let Some(logged_user) = &self.logged_user {
            let path_to_data = format!("./data/{}.json", logged_user.username);
            let data = fs::read_to_string(&path_to_data);
            let data = match data {
                Ok(data) => data,
                Err(error) => match error.kind() {
                    io::ErrorKind::NotFound => {
                        fs::write(path_to_data, b"")?;
                        "".to_string()
                    }
                    _ => {
                        return Err(Box::new(error));
                    }
                }
            };
                
        } else {
            return Err(Box::new(LogicError::NoLoggedUser));
        }
        
        Ok(())
    }

    fn decrypt_data() -> Result<(), Box<dyn Error>> {
        Ok(())
    }

    fn add_record(&mut self, record: Record) -> Result<&Record, Box<dyn Error>> {
        if let Some(logged_user) = &self.logged_user {
            self.records.push(record);
            Ok(self.records.last().expect("Critical error: failed to add record"))
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
                match self.login() {
                    Ok(user) => {
                        self.logged_user = Some(user); // Login successful.
                        self.load_and_decrypt_data()?;
                        break;
                    }
                    Err(e) => {
                        println!("{}", e);
                    }
                }
            } else if input == "r" {
                self.register_user()?;
                break;
            } else {
                println!("Invalid input.");
            }
        }

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

        let mut pet_list_state = ListState::default();
        pet_list_state.select(Some(0));

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
                    MenuItem::Main => {}
                    MenuItem::Help => rect.render_widget(Program::render_help(), chunks[1]),
                    MenuItem::Add => {}
                }
            })?;

            self.handle_input(&rx)?;

            if (self.should_quit) {
                self.terminal.clear()?;
                disable_raw_mode().expect("Failed to disable raw mode");
                self.terminal.show_cursor()?;
                break;
            }
        }
        Ok(())
    }

    fn handle_input(
        &mut self,
        rx: &Receiver<ProgramEvent<KeyEvent>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        // handle events
        match rx.recv()? {
            ProgramEvent::Input(event) => match event.code {
                KeyCode::Char('q') => self.should_quit = true,
                KeyCode::Char('h') => self.active_menu_item = MenuItem::Help,
                KeyCode::Char('a') => self.active_menu_item = MenuItem::Add,
                KeyCode::Char('d') => {
                    // Delete record
                }
                KeyCode::Down => {
                    // Navigate down
                }
                KeyCode::Up => {
                    // Navigate up
                }
                KeyCode::Left => {
                    // Navigate left
                }
                KeyCode::Right => {
                    // Navigate right
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
        Spans::from(vec![Span::raw("Press `m` to return to the main menu. Press `h` to see this help menu. Press `a` to add a new record. Press `d` to delete a record.")]),
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
}
