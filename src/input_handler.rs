use std::sync::mpsc::Receiver;

use crossterm::event::{KeyCode, KeyEvent};
use passwords::PasswordGenerator;
use tui::widgets::ListState;

use crate::{
    program::{LogicError, MenuItem, Mode, Popup, Program, ProgramEvent},
    record::Record,
};

pub fn handle_input(
    program: &mut Program,
    rx: &Receiver<ProgramEvent<KeyEvent>>,
    records_list_state: &mut ListState,
    edit_list_state: &mut ListState,
    edit_record: &mut Record,
    confirmed_password: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    match program.mode {
        Mode::Normal => handle_input_normal_mode(
            program,
            rx,
            records_list_state,
            edit_list_state,
            edit_record,
        ),
        Mode::Insert => handle_input_insert_mode(program, rx, edit_list_state, edit_record),
        Mode::Popup => handle_input_popup_mode(program, rx, records_list_state),
        Mode::Search => handle_input_search_mode(program, rx, records_list_state),
        Mode::ChangePass => handle_input_change_password(program, rx, confirmed_password),
        Mode::InputBox => handle_input_input_box(program, rx),
    }
}

fn handle_input_normal_mode(
    program: &mut Program,
    rx: &Receiver<ProgramEvent<KeyEvent>>,
    records_list_state: &mut ListState,
    edit_list_state: &mut ListState,
    edit_record: &mut Record,
) -> Result<(), Box<dyn std::error::Error>> {
    match rx.recv()? {
        ProgramEvent::Input(event) => match event.code {
            KeyCode::Char('q') => {
                program.active_menu_item = MenuItem::Main;
                program.popup = Some(Popup::Exit);
                program.mode = Mode::Popup;
            }
            KeyCode::Char('h') => program.active_menu_item = MenuItem::Help,
            KeyCode::Char('a') => {
                program.active_menu_item = MenuItem::Add;
                edit_list_state.select(Some(0));
            }
            KeyCode::Char('m') => program.active_menu_item = MenuItem::Main,
            KeyCode::Char('s') => program.show_password = !program.show_password,
            KeyCode::Char('d') | KeyCode::Delete => {
                program.popup = Some(Popup::DeleteARecord);
                program.mode = Mode::Popup;
            }
            KeyCode::Char('e') => {
                program.active_menu_item = MenuItem::Add;
                program.mode = Mode::Insert;
                program.editing_existing_record = true;
                edit_list_state.select(Some(0));
                if let Some(selected) = records_list_state.selected() {
                    edit_record.clone_from(&program.records[selected]);
                }
            }
            KeyCode::Char('f') => {
                program.popup = Some(Popup::Search);
                program.mode = Mode::Search;
            }
            KeyCode::Up => {
                if let Some(selected) = records_list_state.selected() {
                    let records_len = program.records.len();
                    if selected == 0 {
                        records_list_state.select(Some(records_len - 1));
                    } else {
                        records_list_state.select(Some(selected - 1));
                    }
                }
            }
            KeyCode::Down => {
                if let Some(selected) = records_list_state.selected() {
                    let records_len = program.records.len();
                    if selected >= records_len - 1 {
                        records_list_state.select(Some(0));
                    } else {
                        records_list_state.select(Some(selected + 1));
                    }
                }
            }
            KeyCode::Left => {
                if program.active_menu_item == MenuItem::Main {
                    program.active_menu_item = MenuItem::Help;
                } else {
                    //on help
                    program.active_menu_item = MenuItem::Add;
                    program.mode = Mode::Insert;
                }
            }
            KeyCode::Right => {
                if program.active_menu_item == MenuItem::Main {
                    program.active_menu_item = MenuItem::Add;
                    program.mode = Mode::Insert;
                } else {
                    //on help
                    program.active_menu_item = MenuItem::Main;
                }
            }
            KeyCode::Esc => {
                program.popup = None;
                program.search_results.clear();
                program.search_results_index = None;
                program.mode = Mode::Normal;
            }
            KeyCode::F(7) => {
                program.popup = Some(Popup::ChangePassword);
                program.mode = Mode::ChangePass;
            }
            KeyCode::F(8) => {
                program.popup = Some(Popup::InputBox {
                    message: "Enter the desired generate password length".to_string(),
                });
                program.mode = Mode::InputBox;
            }
            KeyCode::F(n) => {
                let result = program.copy_to_clipboard(records_list_state, n);
                if let Err(e) = result {
                    let message = String::from("Error copying to clipboard: ") + &e.to_string();
                    program.popup = Some(Popup::Error { message });
                    program.mode = Mode::Popup;
                }
            }
            _ => {}
        },
        ProgramEvent::Tick => {}
    }
    Ok(())
}

fn handle_input_insert_mode(
    program: &mut Program,
    rx: &Receiver<ProgramEvent<KeyEvent>>,
    edit_list_state: &mut ListState,
    edit_record: &mut Record,
) -> Result<(), Box<dyn std::error::Error>> {
    match rx.recv()? {
        ProgramEvent::Input(event) => match event.code {
            KeyCode::Char(letter) => Program::write_letter(letter, edit_list_state, edit_record),
            KeyCode::Up => {
                if let Some(selected) = edit_list_state.selected() {
                    let len = Record::len(); // this is hardcoded for now
                    if selected == 0 {
                        edit_list_state.select(Some(len - 1));
                    } else {
                        edit_list_state.select(Some(selected - 1));
                    }
                }
            }
            KeyCode::Down => {
                if let Some(selected) = edit_list_state.selected() {
                    let len = Record::len(); // this is hardcoded for now
                    if selected >= len - 1 {
                        edit_list_state.select(Some(0));
                    } else {
                        edit_list_state.select(Some(selected + 1));
                    }
                }
            }
            KeyCode::Left => {
                program.active_menu_item = MenuItem::Main;
                program.mode = Mode::Normal;
            }
            KeyCode::Right => {
                program.active_menu_item = MenuItem::Help;
                program.mode = Mode::Normal;
            }
            KeyCode::Backspace | KeyCode::Delete => {
                if let Some(selected) = edit_list_state.selected() {
                    let data = &mut edit_record[selected];
                    data.pop();
                }
            }
            KeyCode::Esc => {
                program.active_menu_item = MenuItem::Main;
                program.mode = Mode::Normal;
                program.editing_existing_record = false;
                edit_record.clear();
                program.popup = None;
            }
            KeyCode::Enter => {
                if !edit_record.name.is_empty() {
                    // Remove the popup if there is one
                    program.popup = None;

                    if program.editing_existing_record {
                        if let Some(r) = program.records.iter_mut().find(|r| r == &edit_record) {
                            r.clone_from(edit_record);
                            program.active_menu_item = MenuItem::Main;
                        }
                    } else if let Err(e) = program.add_record(edit_record.clone()) {
                        return Err(e);
                    } else {
                        program.active_menu_item = MenuItem::Main;
                    }
                    edit_record.clear();
                }
                program.active_menu_item = MenuItem::Main;
                program.mode = Mode::Normal;
            }
            KeyCode::F(4) => {
                // Password generator
                //TODO: Improve this
                if program.active_menu_item == MenuItem::Add {
                    let password = generate_password(
                        program
                            .generating_password_options
                            .length
                            .parse::<usize>()
                            .unwrap_or(8),
                        false,
                    );
                    if let Ok(password) = password {
                        edit_record.password = password;
                    }
                }
            }
            _ => {}
        },
        ProgramEvent::Tick => {}
    }
    Ok(())
}

fn generate_password(length: usize, symbols: bool) -> Result<String, &'static str> {
    let pg = PasswordGenerator {
        length,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols,
        spaces: false,
        exclude_similar_characters: false,
        strict: true,
    };
    pg.generate_one()
}

fn handle_input_popup_mode(
    program: &mut Program,
    rx: &Receiver<ProgramEvent<KeyEvent>>,
    records_list_state: &mut ListState,
) -> Result<(), Box<dyn std::error::Error>> {
    match rx.recv()? {
        ProgramEvent::Input(event) => match event.code {
            KeyCode::Char('n') | KeyCode::Esc => {
                program.popup = None;
                program.mode = Mode::Normal;
            }
            KeyCode::Char('y') => {
                if let Some(popup) = &program.popup {
                    match popup {
                        Popup::DeleteARecord => {
                            if let Some(selected) = records_list_state.selected() {
                                program.records.remove(selected);
                                records_list_state.select(Some(0));
                            } else {
                                return Err(Box::new(LogicError::NoSelectedRecord {}));
                            }
                        }
                        Popup::DeleteAnAccount => {
                            if let Some(user) = program.logged_user.as_ref() {
                                program.delete_user(user.username.clone().as_ref())?;
                            } else {
                                return Err(Box::new(LogicError::NoLoggedUser {}));
                            }
                        }
                        Popup::Exit => program.should_quit = true,
                        _ => {}
                    }
                }
                program.popup = None;
                program.mode = Mode::Normal;
            }
            _ => {}
        },
        ProgramEvent::Tick => {}
    }
    Ok(())
}

fn handle_input_search_mode(
    program: &mut Program,
    rx: &Receiver<ProgramEvent<KeyEvent>>,
    records_list_state: &mut ListState,
) -> Result<(), Box<dyn std::error::Error>> {
    match rx.recv()? {
        ProgramEvent::Input(event) => match event.code {
            KeyCode::Char(letter) => {
                program.search_term.push(letter);
            }
            KeyCode::Left => {
                if !program.search_results.is_empty() {
                    if let Some(selected) = program.search_results_index {
                        if selected == 0 {
                            program.search_results_index = Some(program.search_results.len() - 1);
                        } else {
                            program.search_results_index = Some(selected - 1);
                        }
                        records_list_state.select(Some(
                            program.search_results[program.search_results_index.unwrap()],
                        ));
                    }
                }
            }
            KeyCode::Right => {
                if !program.search_results.is_empty() {
                    if let Some(selected) = program.search_results_index {
                        if selected == program.search_results.len() - 1 {
                            program.search_results_index = Some(0);
                        } else {
                            program.search_results_index = Some(selected + 1);
                        }
                        records_list_state.select(Some(
                            program.search_results[program.search_results_index.unwrap()],
                        ));
                    }
                }
            }
            KeyCode::Backspace => {
                program.search_term.pop();
            }
            KeyCode::Delete => {
                program.search_term.clear();
            }
            KeyCode::Esc => {
                program.popup = None;
                program.search_results.clear();
                program.search_results_index = None;
                program.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                program.search_results = Program::search(&program.records, &program.search_term);
                if !program.search_results.is_empty() {
                    program.search_results_index = Some(0);
                    records_list_state.select(Some(program.search_results[0]));
                } else {
                    program.popup = None;
                    program.mode = Mode::Normal;
                }
            }
            _ => {}
        },
        ProgramEvent::Tick => {}
    }
    Ok(())
}

fn handle_input_change_password(
    program: &mut Program,
    rx: &Receiver<ProgramEvent<KeyEvent>>,
    confirmed_password: &mut String,
) -> Result<(), Box<dyn std::error::Error>> {
    match rx.recv()? {
        ProgramEvent::Input(event) => match event.code {
            KeyCode::Char(letter) => {
                program.new_password.push(letter);
            }
            KeyCode::Backspace => {
                program.new_password.pop();
            }
            KeyCode::Delete => {
                program.new_password.clear();
            }
            KeyCode::Esc => {
                program.popup = None;
                program.new_password.clear();
                program.mode = Mode::Normal;
            }
            KeyCode::F(7) => program.show_password = !program.show_password,
            KeyCode::Enter => {
                let change_pass_result = Program::change_password(
                    &program.new_password,
                    program
                        .logged_user
                        .as_mut()
                        .expect("No logged user while changing the password. Critical error."),
                );

                if let Err(e) = change_pass_result {
                    program.popup = Some(Popup::Error {
                        message: e.to_string(),
                    });
                } else {
                    if confirmed_password.is_empty() {
                        *confirmed_password = program.new_password.clone();
                        program.new_password.clear();
                    } else if *confirmed_password == program.new_password {
                        program.new_password.clear();
                        confirmed_password.clear();
                        program.mode = Mode::Popup;
                        program.popup = Some(Popup::Information {
                            message: "Password successfully changed!".to_string(),
                        });
                    } else {
                        program.new_password.clear();
                        confirmed_password.clear();
                        program.mode = Mode::Popup;
                        program.popup = Some(Popup::Error {
                            message: "Password does not match!".to_string(),
                        });
                    }
                }
            }
            _ => {}
        },
        ProgramEvent::Tick => {}
    }
    Ok(())
}

fn handle_input_input_box(
    program: &mut Program,
    rx: &Receiver<ProgramEvent<KeyEvent>>,
) -> Result<(), Box<dyn std::error::Error>> {
    match rx.recv()? {
        ProgramEvent::Input(event) => match event.code {
            KeyCode::Char(letter) => {
                if letter.is_numeric() {
                    program.generating_password_options.length.push(letter);
                }
            }
            KeyCode::Backspace => {
                program.generating_password_options.length.pop();
            }
            KeyCode::Delete => {
                program.generating_password_options.length.clear();
            }
            KeyCode::Esc => {
                program.popup = None;
                program.generating_password_options.length = String::new();
                program.mode = Mode::Normal;
            }
            KeyCode::Enter => {
                program.popup = None;
                program.mode = Mode::Normal;
                if !number_in_range(
                    program
                        .generating_password_options
                        .length
                        .parse::<usize>()
                        .unwrap_or(4),
                    4,
                    64,
                ) {
                    program.generating_password_options.length = "4".to_string();
                }
            }
            _ => {}
        },
        ProgramEvent::Tick => {}
    }
    Ok(())
}

fn number_in_range(number: usize, min: usize, max: usize) -> bool {
    number >= min && number <= max
}
