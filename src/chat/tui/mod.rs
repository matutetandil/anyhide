//! Terminal User Interface for Anyhide Chat.
//!
//! This module provides a visual chat interface using ratatui.
//!
//! ## Single-peer TUI (legacy)
//! - `App` - Single conversation state
//! - `render` - Single conversation UI
//!
//! ## Multi-contact TUI
//! - `MultiApp` - Multiple conversations with sidebar
//! - `render_multi` - Multi-contact UI with tabs

mod app;
pub mod event;
mod ui;
mod multi_app;
mod multi_ui;
mod multi_event;

// Single-peer exports (legacy, still used for single chat)
pub use app::{App, ChatMessage, ConnectionStatus, MessageAuthor};
pub use event::{Event, EventHandler, handle_command, handle_key_event, KeyAction};
pub use ui::render;

// Multi-contact exports
pub use multi_app::{
    ChatRequest, Contact, ContactStatus, Conversation, FocusedPanel, MultiApp, Notification,
    NotificationKind,
};
pub use multi_event::{handle_multi_command, handle_multi_key_event, MultiKeyAction};
pub use multi_ui::render_multi;

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
