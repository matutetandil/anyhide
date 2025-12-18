//! Terminal User Interface for Anyhide Chat.
//!
//! This module provides a visual chat interface using ratatui.

mod app;
pub mod event;
mod ui;

pub use app::{App, ChatMessage, ConnectionStatus, MessageAuthor};
pub use event::{Event, EventHandler, handle_command, handle_key_event, KeyAction};
pub use ui::render;

use std::io;

use crossterm::{
    event::{DisableMouseCapture, EnableMouseCapture},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{backend::CrosstermBackend, Terminal};

use crate::chat::error::ChatError;

/// Initialize the terminal for TUI mode.
pub fn init_terminal() -> Result<Terminal<CrosstermBackend<io::Stdout>>, ChatError> {
    enable_raw_mode().map_err(|e| ChatError::TransportError(format!("Failed to enable raw mode: {}", e)))?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)
        .map_err(|e| ChatError::TransportError(format!("Failed to enter alternate screen: {}", e)))?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend)
        .map_err(|e| ChatError::TransportError(format!("Failed to create terminal: {}", e)))
}

/// Restore the terminal to normal mode.
pub fn restore_terminal(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<(), ChatError> {
    disable_raw_mode().map_err(|e| ChatError::TransportError(format!("Failed to disable raw mode: {}", e)))?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )
    .map_err(|e| ChatError::TransportError(format!("Failed to leave alternate screen: {}", e)))?;
    terminal.show_cursor()
        .map_err(|e| ChatError::TransportError(format!("Failed to show cursor: {}", e)))?;
    Ok(())
}
