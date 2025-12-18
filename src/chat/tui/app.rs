//! Application state for the TUI.

use std::time::{SystemTime, UNIX_EPOCH};

/// Who sent the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageAuthor {
    /// Message from the local user.
    You,
    /// Message from the remote peer.
    Peer(String),
    /// System message (status, errors, etc).
    System,
}

/// A chat message with metadata.
#[derive(Debug, Clone)]
pub struct ChatMessage {
    /// Who sent the message.
    pub author: MessageAuthor,
    /// The message content.
    pub content: String,
    /// Unix timestamp when received/sent.
    pub timestamp: u64,
}

impl ChatMessage {
    /// Create a new chat message.
    pub fn new(author: MessageAuthor, content: String) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            author,
            content,
            timestamp,
        }
    }

    /// Create a system message.
    pub fn system(content: impl Into<String>) -> Self {
        Self::new(MessageAuthor::System, content.into())
    }

    /// Create a message from the local user.
    pub fn from_you(content: impl Into<String>) -> Self {
        Self::new(MessageAuthor::You, content.into())
    }

    /// Create a message from the peer.
    pub fn from_peer(name: impl Into<String>, content: impl Into<String>) -> Self {
        Self::new(MessageAuthor::Peer(name.into()), content.into())
    }

    /// Format the timestamp as HH:MM.
    pub fn formatted_time(&self) -> String {
        let secs = self.timestamp % 86400; // Seconds in day
        let hours = (secs / 3600) % 24;
        let minutes = (secs % 3600) / 60;
        format!("{:02}:{:02}", hours, minutes)
    }
}

/// Connection status for the chat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionStatus {
    /// Not connected yet.
    Disconnected,
    /// Bootstrapping Tor.
    BootstrappingTor,
    /// Creating hidden service.
    CreatingHiddenService,
    /// Waiting for peer connection.
    WaitingForPeer,
    /// Connected and ready to chat.
    Connected,
    /// Connection lost or error.
    Error(String),
}

impl ConnectionStatus {
    /// Get a display string for the status.
    pub fn display(&self) -> &str {
        match self {
            ConnectionStatus::Disconnected => "Disconnected",
            ConnectionStatus::BootstrappingTor => "Bootstrapping Tor...",
            ConnectionStatus::CreatingHiddenService => "Creating hidden service...",
            ConnectionStatus::WaitingForPeer => "Waiting for peer...",
            ConnectionStatus::Connected => "Connected",
            ConnectionStatus::Error(_) => "Error",
        }
    }
}

/// Application state for the chat TUI.
pub struct App {
    /// The peer's name (contact alias).
    pub peer_name: String,
    /// Current input text.
    pub input: String,
    /// Cursor position in the input.
    pub cursor_position: usize,
    /// Chat message history.
    pub messages: Vec<ChatMessage>,
    /// Current connection status.
    pub status: ConnectionStatus,
    /// Whether the app should quit.
    pub should_quit: bool,
    /// Scroll offset for message history (0 = bottom).
    pub scroll_offset: usize,
    /// Our .onion address (shown in status).
    pub my_onion: Option<String>,
    /// Messages sent count.
    pub messages_sent: u32,
    /// Messages received count.
    pub messages_received: u32,
    /// Maximum message length in characters.
    pub max_message_len: usize,
}

/// Default maximum message length.
pub const DEFAULT_MAX_MESSAGE_LEN: usize = 256;

impl App {
    /// Create a new App instance with default max message length.
    pub fn new(peer_name: impl Into<String>) -> Self {
        Self::with_max_len(peer_name, DEFAULT_MAX_MESSAGE_LEN)
    }

    /// Create a new App instance with custom max message length.
    pub fn with_max_len(peer_name: impl Into<String>, max_message_len: usize) -> Self {
        Self {
            peer_name: peer_name.into(),
            input: String::new(),
            cursor_position: 0,
            messages: Vec::new(),
            status: ConnectionStatus::Disconnected,
            should_quit: false,
            scroll_offset: 0,
            my_onion: None,
            messages_sent: 0,
            messages_received: 0,
            max_message_len,
        }
    }

    /// Get remaining characters available for input.
    pub fn remaining_chars(&self) -> usize {
        self.max_message_len.saturating_sub(self.input.chars().count())
    }

    /// Check if input is at max length.
    pub fn is_input_at_max(&self) -> bool {
        self.input.chars().count() >= self.max_message_len
    }

    /// Add a system message.
    pub fn add_system_message(&mut self, content: impl Into<String>) {
        self.messages.push(ChatMessage::system(content));
        self.scroll_to_bottom();
    }

    /// Add a message from the local user.
    pub fn add_my_message(&mut self, content: impl Into<String>) {
        self.messages.push(ChatMessage::from_you(content));
        self.messages_sent += 1;
        self.scroll_to_bottom();
    }

    /// Add a message from the peer.
    pub fn add_peer_message(&mut self, content: impl Into<String>) {
        self.messages
            .push(ChatMessage::from_peer(&self.peer_name, content));
        self.messages_received += 1;
        self.scroll_to_bottom();
    }

    /// Set the connection status.
    pub fn set_status(&mut self, status: ConnectionStatus) {
        self.status = status;
    }

    /// Set our .onion address.
    pub fn set_my_onion(&mut self, onion: impl Into<String>) {
        self.my_onion = Some(onion.into());
    }

    /// Move cursor left.
    pub fn move_cursor_left(&mut self) {
        let cursor_moved_left = self.cursor_position.saturating_sub(1);
        self.cursor_position = self.clamp_cursor(cursor_moved_left);
    }

    /// Move cursor right.
    pub fn move_cursor_right(&mut self) {
        let cursor_moved_right = self.cursor_position.saturating_add(1);
        self.cursor_position = self.clamp_cursor(cursor_moved_right);
    }

    /// Insert a character at cursor position (respects max length).
    pub fn enter_char(&mut self, c: char) {
        // Don't insert if at max length
        if self.is_input_at_max() {
            return;
        }
        let index = self.byte_index();
        self.input.insert(index, c);
        self.move_cursor_right();
    }

    /// Delete character before cursor.
    pub fn delete_char(&mut self) {
        if self.cursor_position == 0 {
            return;
        }

        let current_index = self.cursor_position;
        let from_left_to_current_index = current_index - 1;

        // Get byte positions
        let before_char_to_delete = self.input.chars().take(from_left_to_current_index);
        let after_char_to_delete = self.input.chars().skip(current_index);

        self.input = before_char_to_delete.chain(after_char_to_delete).collect();
        self.move_cursor_left();
    }

    /// Delete character after cursor.
    pub fn delete_char_forward(&mut self) {
        if self.cursor_position >= self.input.chars().count() {
            return;
        }

        let current_index = self.cursor_position;
        let before_char = self.input.chars().take(current_index);
        let after_char = self.input.chars().skip(current_index + 1);

        self.input = before_char.chain(after_char).collect();
    }

    /// Clamp cursor position to valid range.
    fn clamp_cursor(&self, new_cursor_pos: usize) -> usize {
        new_cursor_pos.clamp(0, self.input.chars().count())
    }

    /// Get byte index for cursor position.
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.cursor_position)
            .unwrap_or(self.input.len())
    }

    /// Take the current input and clear it.
    pub fn take_input(&mut self) -> String {
        self.cursor_position = 0;
        std::mem::take(&mut self.input)
    }

    /// Scroll to the bottom of messages.
    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
    }

    /// Scroll up by n lines.
    pub fn scroll_up(&mut self, n: usize) {
        self.scroll_offset = self.scroll_offset.saturating_add(n);
        // Clamp to max scroll
        let max_scroll = self.messages.len().saturating_sub(1);
        self.scroll_offset = self.scroll_offset.min(max_scroll);
    }

    /// Scroll down by n lines.
    pub fn scroll_down(&mut self, n: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(n);
    }

    /// Move cursor to start of input.
    pub fn move_cursor_home(&mut self) {
        self.cursor_position = 0;
    }

    /// Move cursor to end of input.
    pub fn move_cursor_end(&mut self) {
        self.cursor_position = self.input.chars().count();
    }

    /// Check if connected.
    pub fn is_connected(&self) -> bool {
        self.status == ConnectionStatus::Connected
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_creation() {
        let app = App::new("bob");
        assert_eq!(app.peer_name, "bob");
        assert!(app.input.is_empty());
        assert!(app.messages.is_empty());
        assert!(!app.should_quit);
    }

    #[test]
    fn test_input_handling() {
        let mut app = App::new("bob");

        app.enter_char('H');
        app.enter_char('i');
        assert_eq!(app.input, "Hi");
        assert_eq!(app.cursor_position, 2);

        app.delete_char();
        assert_eq!(app.input, "H");
        assert_eq!(app.cursor_position, 1);
    }

    #[test]
    fn test_message_history() {
        let mut app = App::new("bob");

        app.add_system_message("Connected");
        app.add_my_message("Hello");
        app.add_peer_message("Hi there");

        assert_eq!(app.messages.len(), 3);
        assert_eq!(app.messages_sent, 1);
        assert_eq!(app.messages_received, 1);
    }

    #[test]
    fn test_take_input() {
        let mut app = App::new("bob");
        app.enter_char('H');
        app.enter_char('i');

        let input = app.take_input();
        assert_eq!(input, "Hi");
        assert!(app.input.is_empty());
        assert_eq!(app.cursor_position, 0);
    }

    #[test]
    fn test_max_message_length_default() {
        let app = App::new("bob");
        assert_eq!(app.max_message_len, DEFAULT_MAX_MESSAGE_LEN);
        assert_eq!(app.remaining_chars(), DEFAULT_MAX_MESSAGE_LEN);
    }

    #[test]
    fn test_max_message_length_custom() {
        let app = App::with_max_len("bob", 100);
        assert_eq!(app.max_message_len, 100);
        assert_eq!(app.remaining_chars(), 100);
    }

    #[test]
    fn test_remaining_chars_decreases() {
        let mut app = App::with_max_len("bob", 10);
        assert_eq!(app.remaining_chars(), 10);

        app.enter_char('H');
        assert_eq!(app.remaining_chars(), 9);

        app.enter_char('e');
        app.enter_char('l');
        app.enter_char('l');
        app.enter_char('o');
        assert_eq!(app.remaining_chars(), 5);
    }

    #[test]
    fn test_cannot_exceed_max_length() {
        let mut app = App::with_max_len("bob", 5);

        // Type exactly 5 characters
        for c in "Hello".chars() {
            app.enter_char(c);
        }
        assert_eq!(app.input, "Hello");
        assert_eq!(app.remaining_chars(), 0);
        assert!(app.is_input_at_max());

        // Try to type more - should be rejected
        app.enter_char('!');
        assert_eq!(app.input, "Hello"); // Still "Hello", not "Hello!"
        assert_eq!(app.remaining_chars(), 0);
    }

    #[test]
    fn test_can_delete_at_max_length() {
        let mut app = App::with_max_len("bob", 5);

        for c in "Hello".chars() {
            app.enter_char(c);
        }
        assert!(app.is_input_at_max());

        // Delete should work
        app.delete_char();
        assert_eq!(app.input, "Hell");
        assert_eq!(app.remaining_chars(), 1);
        assert!(!app.is_input_at_max());

        // Now we can type again
        app.enter_char('!');
        assert_eq!(app.input, "Hell!");
    }
}
