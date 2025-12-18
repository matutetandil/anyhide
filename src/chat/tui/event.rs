//! Event handling for the TUI.

use std::time::Duration;

use crossterm::event::{self, Event as CrosstermEvent, KeyCode, KeyEvent, KeyModifiers};
use tokio::sync::mpsc;

use super::app::App;

/// Application events.
#[derive(Debug)]
pub enum Event {
    /// Terminal tick (for refreshing UI).
    Tick,
    /// Keyboard event.
    Key(KeyEvent),
    /// Mouse event (unused for now).
    Mouse(crossterm::event::MouseEvent),
    /// Terminal resize.
    Resize(u16, u16),
}

/// Event handler that reads terminal events in a separate task.
pub struct EventHandler {
    /// Sender to main loop.
    tx: mpsc::UnboundedSender<Event>,
    /// Receiver in main loop.
    rx: mpsc::UnboundedReceiver<Event>,
}

impl EventHandler {
    /// Create a new event handler.
    pub fn new() -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self { tx, rx }
    }

    /// Get the sender for spawning the event loop.
    pub fn sender(&self) -> mpsc::UnboundedSender<Event> {
        self.tx.clone()
    }

    /// Receive the next event.
    pub async fn next(&mut self) -> Option<Event> {
        self.rx.recv().await
    }

    /// Spawn the event reading task.
    pub fn spawn_reader(tx: mpsc::UnboundedSender<Event>, tick_rate: Duration) {
        tokio::spawn(async move {
            loop {
                // Poll for events with timeout
                if event::poll(tick_rate).unwrap_or(false) {
                    match event::read() {
                        Ok(CrosstermEvent::Key(key)) => {
                            if tx.send(Event::Key(key)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Mouse(mouse)) => {
                            if tx.send(Event::Mouse(mouse)).is_err() {
                                break;
                            }
                        }
                        Ok(CrosstermEvent::Resize(w, h)) => {
                            if tx.send(Event::Resize(w, h)).is_err() {
                                break;
                            }
                        }
                        _ => {}
                    }
                } else {
                    // Send tick on timeout
                    if tx.send(Event::Tick).is_err() {
                        break;
                    }
                }
            }
        });
    }
}

impl Default for EventHandler {
    fn default() -> Self {
        Self::new()
    }
}

/// Result of handling a key event.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyAction {
    /// No action needed.
    None,
    /// Quit the application.
    Quit,
    /// Send the current input as a message.
    SendMessage,
}

/// Handle a key event and update app state.
pub fn handle_key_event(app: &mut App, key: KeyEvent) -> KeyAction {
    match key.code {
        // Quit on Ctrl+C or Ctrl+Q
        KeyCode::Char('c') | KeyCode::Char('q') if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.should_quit = true;
            KeyAction::Quit
        }

        // Escape also quits
        KeyCode::Esc => {
            app.should_quit = true;
            KeyAction::Quit
        }

        // Enter sends the message
        KeyCode::Enter => {
            if !app.input.is_empty() {
                KeyAction::SendMessage
            } else {
                KeyAction::None
            }
        }

        // Backspace deletes character before cursor
        KeyCode::Backspace => {
            app.delete_char();
            KeyAction::None
        }

        // Delete removes character after cursor
        KeyCode::Delete => {
            app.delete_char_forward();
            KeyAction::None
        }

        // Arrow keys for cursor movement
        KeyCode::Left => {
            app.move_cursor_left();
            KeyAction::None
        }
        KeyCode::Right => {
            app.move_cursor_right();
            KeyAction::None
        }

        // Home/End for cursor
        KeyCode::Home => {
            app.move_cursor_home();
            KeyAction::None
        }
        KeyCode::End => {
            app.move_cursor_end();
            KeyAction::None
        }

        // Page Up/Down for scrolling
        KeyCode::PageUp => {
            app.scroll_up(5);
            KeyAction::None
        }
        KeyCode::PageDown => {
            app.scroll_down(5);
            KeyAction::None
        }

        // Up/Down arrows scroll when Ctrl is held
        KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.scroll_up(1);
            KeyAction::None
        }
        KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
            app.scroll_down(1);
            KeyAction::None
        }

        // Regular character input
        KeyCode::Char(c) => {
            app.enter_char(c);
            KeyAction::None
        }

        // Tab inserts spaces
        KeyCode::Tab => {
            app.enter_char(' ');
            app.enter_char(' ');
            KeyAction::None
        }

        _ => KeyAction::None,
    }
}

/// Handle special commands starting with /.
pub fn handle_command(app: &mut App, command: &str) -> KeyAction {
    let parts: Vec<&str> = command.trim().split_whitespace().collect();
    if parts.is_empty() {
        return KeyAction::None;
    }

    match parts[0] {
        "/quit" | "/q" | "/exit" => {
            app.should_quit = true;
            KeyAction::Quit
        }
        "/help" | "/h" | "/?" => {
            app.add_system_message("Commands:");
            app.add_system_message("  /quit, /q    - Exit chat");
            app.add_system_message("  /status, /s  - Show connection status");
            app.add_system_message("  /clear, /c   - Clear message history");
            app.add_system_message("  /help, /h    - Show this help");
            KeyAction::None
        }
        "/status" | "/s" => {
            app.add_system_message(format!("Status: {}", app.status.display()));
            if let Some(ref onion) = app.my_onion {
                app.add_system_message(format!("Your address: {}", onion));
            }
            app.add_system_message(format!(
                "Messages: {} sent, {} received",
                app.messages_sent, app.messages_received
            ));
            KeyAction::None
        }
        "/clear" | "/c" => {
            app.messages.clear();
            app.add_system_message("Chat history cleared");
            KeyAction::None
        }
        _ => {
            app.add_system_message(format!("Unknown command: {}", parts[0]));
            app.add_system_message("Type /help for available commands");
            KeyAction::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_quit_commands() {
        let mut app = App::new("test");

        assert_eq!(handle_command(&mut app, "/quit"), KeyAction::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn test_help_command() {
        let mut app = App::new("test");

        assert_eq!(handle_command(&mut app, "/help"), KeyAction::None);
        assert!(!app.messages.is_empty());
    }

    #[test]
    fn test_unknown_command() {
        let mut app = App::new("test");

        assert_eq!(handle_command(&mut app, "/unknown"), KeyAction::None);
        assert!(app.messages.iter().any(|m| m.content.contains("Unknown")));
    }
}
