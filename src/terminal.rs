use std::io::stdout;

use crossterm::{
    cursor::{Hide, MoveTo, Show},
    event::{read, Event},
    execute,
    terminal::{size, Clear, ClearType}, style::{SetBackgroundColor, Color, SetForegroundColor},
};

pub struct Size {
    pub columns: u16,
    pub rows: u16,
}
pub struct Terminal {
    size: Size,
    _stdout: std::io::Stdout,
}

impl Terminal {
    pub fn default() -> crossterm::Result<Self> {
        let (columns, rows) = size()?;
        Ok(Self {
            size: Size {
                columns,
                rows : rows - 1,
            },
            _stdout: stdout(),
        })
    }
    pub fn size(&self) -> &Size {
        &self.size
    }

    pub fn set_size(&mut self, size: Size) {
        self.size = size;
    }

    pub fn clear_screen(&mut self) -> crossterm::Result<()> {
        execute!(self._stdout, Clear(ClearType::All),)
    }

    // pub fn set_cursor(&mut self,Position { x, y }: &Position) -> crossterm::Result<()> {
    //     execute!(self._stdout, MoveTo(*x as u16, *y as u16))
    // }

    pub fn hide_cursor(&mut self) -> crossterm::Result<()> {
        execute!(self._stdout, Hide)
    }

    pub fn show_cursor(&mut self) -> crossterm::Result<()> {
        execute!(self._stdout, Show)
    }

    pub fn clear_current_line(&mut self) -> crossterm::Result<()> {
        execute!(self._stdout, Clear(ClearType::CurrentLine))
    }

    pub fn set_background_color(&mut self,color: Color) -> crossterm::Result<()> {
        execute!(self._stdout, SetBackgroundColor(color))
    }

    pub fn reset_background_color(&mut self) -> crossterm::Result<()> {
        execute!(self._stdout, SetBackgroundColor(Color::Reset))
    }

    pub fn set_text_color(&mut self,color: Color) -> crossterm::Result<()> {
        execute!(self._stdout, SetForegroundColor(color))
    }

    pub fn reset_text_color(&mut self) -> crossterm::Result<()> {
        execute!(self._stdout, SetForegroundColor(Color::Reset))
    }

    pub fn read_key() -> crossterm::Result<Event> {
        loop {
            if let Ok(key) = read() {
                return Ok(key);
            }
        }
    }
}