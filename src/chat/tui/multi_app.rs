//! Multi-contact application state for the TUI.
//!
//! This module provides the state management for multi-contact chat TUI,
//! where users can manage multiple conversations simultaneously.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

// Re-export from single-peer app for compatibility
pub use super::app::{ChatMessage, ConnectionStatus, MessageAuthor, DEFAULT_MAX_MESSAGE_LEN};

/// Contact status in the sidebar.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContactStatus {
    /// Contact is online (connected session).
    Online,
    /// Contact is offline (no active session).
    Offline,
    /// Ephemeral contact (not saved).
    Ephemeral,
    /// Connecting to contact.
    Connecting,
    /// Incoming chat request (waiting for us to accept).
    IncomingRequest,
    /// We sent a request, waiting for them to accept.
    PendingAccept,
}

impl ContactStatus {
    /// Get the icon for this status.
    pub fn icon(&self) -> &'static str {
        match self {
            ContactStatus::Online => "●",
            ContactStatus::Offline => "○",
            ContactStatus::Ephemeral => "◌",
            ContactStatus::Connecting => "◐",
            ContactStatus::IncomingRequest => "◀",  // Arrow pointing at us
            ContactStatus::PendingAccept => "▶",    // Arrow pointing at them
        }
    }

    /// Whether this status represents a pending request.
    pub fn is_request(&self) -> bool {
        matches!(self, ContactStatus::IncomingRequest | ContactStatus::PendingAccept)
    }
}

/// Chat service (hidden service) status.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChatServiceStatus {
    /// Hidden service is starting up.
    Starting,
    /// Hidden service is ready and listening.
    Ready,
    /// Hidden service encountered an error.
    Error,
}

impl ChatServiceStatus {
    /// Get the icon for this status.
    pub fn icon(&self) -> &'static str {
        match self {
            ChatServiceStatus::Starting => "◐",  // Half-filled
            ChatServiceStatus::Ready => "●",     // Filled (green)
            ChatServiceStatus::Error => "○",     // Empty (red)
        }
    }

    /// Get the label for this status.
    pub fn label(&self) -> &'static str {
        match self {
            ChatServiceStatus::Starting => "Starting",
            ChatServiceStatus::Ready => "Ready",
            ChatServiceStatus::Error => "Error",
        }
    }
}

/// Type of notification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NotificationKind {
    /// Chat request from a known contact.
    KnownContactRequest,
    /// Chat request from an unknown/ephemeral source.
    EphemeralRequest,
    /// Connection established.
    Connected,
    /// Connection lost.
    Disconnected,
    /// Error occurred.
    Error,
    /// Informational message.
    Info,
}

impl NotificationKind {
    /// Get the icon for this notification type.
    pub fn icon(&self) -> &'static str {
        match self {
            NotificationKind::KnownContactRequest => "👤",
            NotificationKind::EphemeralRequest => "👻",
            NotificationKind::Connected => "✓",
            NotificationKind::Disconnected => "✗",
            NotificationKind::Error => "⚠",
            NotificationKind::Info => "ℹ",
        }
    }
}

/// A notification for the UI.
#[derive(Debug, Clone)]
pub struct Notification {
    /// Unique ID for this notification.
    pub id: u64,
    /// Notification type.
    pub kind: NotificationKind,
    /// Message to display.
    pub message: String,
    /// Associated contact/onion (if any).
    pub source: Option<String>,
    /// Timestamp when notification was created.
    pub timestamp: u64,
    /// Whether this notification has been seen.
    pub seen: bool,
}

impl Notification {
    /// Create a new notification.
    pub fn new(id: u64, kind: NotificationKind, message: impl Into<String>) -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            id,
            kind,
            message: message.into(),
            source: None,
            timestamp,
            seen: false,
        }
    }

    /// Set the source of this notification.
    pub fn with_source(mut self, source: impl Into<String>) -> Self {
        self.source = Some(source.into());
        self
    }

    /// Get display text for this notification.
    pub fn display(&self) -> String {
        format!("{} {}", self.kind.icon(), self.message)
    }
}

/// A pending chat request.
#[derive(Debug, Clone)]
pub struct ChatRequest {
    /// Unique ID for this request.
    pub id: u64,
    /// Source onion address.
    pub onion_address: String,
    /// Contact name (if known).
    pub contact_name: Option<String>,
    /// Whether this is from a known contact.
    pub is_known: bool,
    /// Timestamp when request was received.
    pub timestamp: u64,
}

/// A contact in the sidebar.
#[derive(Debug, Clone)]
pub struct Contact {
    /// Contact name (alias or ~ephemeral).
    pub name: String,
    /// Current status.
    pub status: ContactStatus,
    /// Number of unread messages.
    pub unread: u32,
    /// Whether this is an ephemeral contact.
    pub is_ephemeral: bool,
    /// Onion address (for known contacts).
    pub onion_address: Option<String>,
}

impl Contact {
    /// Create a new offline contact.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ContactStatus::Offline,
            unread: 0,
            is_ephemeral: false,
            onion_address: None,
        }
    }

    /// Create a new contact with onion address.
    pub fn with_onion(name: impl Into<String>, onion: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ContactStatus::Offline,
            unread: 0,
            is_ephemeral: false,
            onion_address: Some(onion.into()),
        }
    }

    /// Create a new ephemeral contact.
    pub fn ephemeral(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ContactStatus::Ephemeral,
            unread: 0,
            is_ephemeral: true,
            onion_address: None,
        }
    }

    /// Create ephemeral contact with onion address (for incoming requests).
    pub fn ephemeral_with_onion(name: impl Into<String>, onion: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            status: ContactStatus::Ephemeral,
            unread: 0,
            is_ephemeral: true,
            onion_address: Some(onion.into()),
        }
    }

    /// Get display name with unread badge.
    pub fn display_name(&self) -> String {
        if self.unread > 0 {
            format!("{} {} ({})", self.status.icon(), self.name, self.unread)
        } else {
            format!("{} {}", self.status.icon(), self.name)
        }
    }

    /// Get tab label with unread badge.
    pub fn tab_label(&self) -> String {
        if self.unread > 0 {
            format!(" {} ({}) ", self.name, self.unread)
        } else {
            format!(" {} ", self.name)
        }
    }
}

/// A conversation with a contact.
#[derive(Debug, Clone)]
pub struct Conversation {
    /// Contact name.
    pub contact_name: String,
    /// Chat message history.
    pub messages: Vec<ChatMessage>,
    /// Messages sent count.
    pub messages_sent: u32,
    /// Messages received count.
    pub messages_received: u32,
    /// Scroll offset for message history.
    pub scroll_offset: usize,
}

impl Conversation {
    /// Create a new empty conversation.
    pub fn new(contact_name: impl Into<String>) -> Self {
        Self {
            contact_name: contact_name.into(),
            messages: Vec::new(),
            messages_sent: 0,
            messages_received: 0,
            scroll_offset: 0,
        }
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
            .push(ChatMessage::from_peer(&self.contact_name, content));
        self.messages_received += 1;
        self.scroll_to_bottom();
    }

    /// Scroll to bottom.
    pub fn scroll_to_bottom(&mut self) {
        self.scroll_offset = 0;
    }

    /// Scroll up.
    pub fn scroll_up(&mut self, n: usize) {
        self.scroll_offset = self.scroll_offset.saturating_add(n);
        let max_scroll = self.messages.len().saturating_sub(1);
        self.scroll_offset = self.scroll_offset.min(max_scroll);
    }

    /// Scroll down.
    pub fn scroll_down(&mut self, n: usize) {
        self.scroll_offset = self.scroll_offset.saturating_sub(n);
    }
}

/// Which panel is currently focused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FocusedPanel {
    /// Contact list sidebar.
    Sidebar,
    /// Conversation tabs.
    Tabs,
    /// Message input.
    Input,
}

/// Type of dialog currently shown.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DialogKind {
    /// Confirm initiating a chat (asks for passphrase).
    InitiateChat {
        /// Contact name to chat with.
        contact_name: String,
        /// Contact's onion address.
        onion_address: String,
    },
    /// Incoming chat request (accept/cancel).
    IncomingRequest {
        /// Request ID.
        request_id: u64,
        /// Source name (contact name or truncated onion).
        source_name: String,
        /// Source onion address.
        onion_address: String,
        /// Whether this is from a known contact.
        is_known: bool,
    },
    /// Accept a chat and enter passphrase.
    AcceptChat {
        /// Request ID being accepted.
        request_id: u64,
        /// Source name.
        source_name: String,
        /// Source onion address.
        onion_address: String,
    },
    /// Generic error message.
    Error {
        /// Error title.
        title: String,
        /// Error message.
        message: String,
    },
    /// View a notification.
    ViewNotification {
        /// Notification ID.
        notification_id: u64,
        /// Notification icon.
        icon: String,
        /// Notification message.
        message: String,
        /// Source (if any).
        source: Option<String>,
    },
    /// Add a new contact dialog (multi-field).
    AddContact,
    /// Quick ephemeral chat dialog (single field: onion address).
    QuickEphemeral,
}

/// Input field for multi-field dialogs.
#[derive(Debug, Clone)]
pub struct DialogInputField {
    /// Field label.
    pub label: String,
    /// Current value.
    pub value: String,
    /// Cursor position.
    pub cursor: usize,
    /// Placeholder text.
    pub placeholder: String,
    /// Whether this field is required.
    pub required: bool,
}

/// A dialog/modal shown over the TUI.
#[derive(Debug, Clone)]
pub struct Dialog {
    /// Kind of dialog.
    pub kind: DialogKind,
    /// Password/passphrase input (if applicable).
    pub password_input: String,
    /// Cursor position in password input.
    pub password_cursor: usize,
    /// Currently focused button (0 = OK/Accept, 1 = Cancel).
    pub focused_button: usize,
    /// Multi-field inputs (for AddContact, QuickEphemeral).
    pub fields: Vec<DialogInputField>,
    /// Currently focused field index.
    pub focused_field: usize,
}

impl Dialog {
    /// Create a new dialog.
    pub fn new(kind: DialogKind) -> Self {
        Self {
            kind,
            password_input: String::new(),
            password_cursor: 0,
            focused_button: 0,
            fields: Vec::new(),
            focused_field: 0,
        }
    }

    /// Create an initiate chat dialog.
    pub fn initiate_chat(contact_name: impl Into<String>, onion_address: impl Into<String>) -> Self {
        Self::new(DialogKind::InitiateChat {
            contact_name: contact_name.into(),
            onion_address: onion_address.into(),
        })
    }

    /// Create an incoming request dialog.
    pub fn incoming_request(
        request_id: u64,
        source_name: impl Into<String>,
        onion_address: impl Into<String>,
        is_known: bool,
    ) -> Self {
        Self::new(DialogKind::IncomingRequest {
            request_id,
            source_name: source_name.into(),
            onion_address: onion_address.into(),
            is_known,
        })
    }

    /// Create an accept chat dialog (with passphrase input).
    pub fn accept_chat(
        request_id: u64,
        source_name: impl Into<String>,
        onion_address: impl Into<String>,
    ) -> Self {
        Self::new(DialogKind::AcceptChat {
            request_id,
            source_name: source_name.into(),
            onion_address: onion_address.into(),
        })
    }

    /// Create an error dialog.
    pub fn error(title: impl Into<String>, message: impl Into<String>) -> Self {
        Self::new(DialogKind::Error {
            title: title.into(),
            message: message.into(),
        })
    }

    /// Create a view notification dialog.
    pub fn view_notification(notification: &Notification) -> Self {
        Self::new(DialogKind::ViewNotification {
            notification_id: notification.id,
            icon: notification.kind.icon().to_string(),
            message: notification.message.clone(),
            source: notification.source.clone(),
        })
    }

    /// Create an add contact dialog.
    pub fn add_contact() -> Self {
        let mut dialog = Self::new(DialogKind::AddContact);
        dialog.fields = vec![
            DialogInputField {
                label: "Name".to_string(),
                value: String::new(),
                cursor: 0,
                placeholder: "Contact alias".to_string(),
                required: true,
            },
            DialogInputField {
                label: "Onion".to_string(),
                value: String::new(),
                cursor: 0,
                placeholder: "abc...xyz.onion".to_string(),
                required: true,
            },
            DialogInputField {
                label: "Public Key".to_string(),
                value: String::new(),
                cursor: 0,
                placeholder: "Path to .pub file".to_string(),
                required: true,
            },
            DialogInputField {
                label: "Sign Key".to_string(),
                value: String::new(),
                cursor: 0,
                placeholder: "Path to .sign.pub file".to_string(),
                required: true,
            },
        ];
        dialog
    }

    /// Create a quick ephemeral chat dialog.
    pub fn quick_ephemeral() -> Self {
        let mut dialog = Self::new(DialogKind::QuickEphemeral);
        dialog.fields = vec![DialogInputField {
            label: "Onion".to_string(),
            value: String::new(),
            cursor: 0,
            placeholder: "abc...xyz.onion:port".to_string(),
            required: true,
        }];
        dialog
    }

    /// Check if this dialog needs password input.
    pub fn needs_password(&self) -> bool {
        matches!(
            self.kind,
            DialogKind::InitiateChat { .. } | DialogKind::AcceptChat { .. }
        )
    }

    /// Check if this dialog has multi-field input.
    pub fn has_fields(&self) -> bool {
        !self.fields.is_empty()
    }

    /// Get the title for this dialog.
    pub fn title(&self) -> &str {
        match &self.kind {
            DialogKind::InitiateChat { .. } => "Start Chat",
            DialogKind::IncomingRequest { .. } => "Incoming Request",
            DialogKind::AcceptChat { .. } => "Accept Chat",
            DialogKind::Error { title, .. } => title,
            DialogKind::ViewNotification { .. } => "Notification",
            DialogKind::AddContact => "Add Contact",
            DialogKind::QuickEphemeral => "Quick Chat",
        }
    }

    /// Type a character into the password input.
    pub fn type_char(&mut self, c: char) {
        if self.has_fields() {
            if let Some(field) = self.fields.get_mut(self.focused_field) {
                field.value.insert(field.cursor, c);
                field.cursor += 1;
            }
        } else {
            self.password_input.insert(self.password_cursor, c);
            self.password_cursor += 1;
        }
    }

    /// Delete character before cursor.
    pub fn delete_char(&mut self) {
        if self.has_fields() {
            if let Some(field) = self.fields.get_mut(self.focused_field) {
                if field.cursor > 0 {
                    field.cursor -= 1;
                    field.value.remove(field.cursor);
                }
            }
        } else if self.password_cursor > 0 {
            self.password_cursor -= 1;
            self.password_input.remove(self.password_cursor);
        }
    }

    /// Move to next field.
    pub fn next_field(&mut self) {
        if self.has_fields() && self.focused_field < self.fields.len() - 1 {
            self.focused_field += 1;
        }
    }

    /// Move to previous field.
    pub fn prev_field(&mut self) {
        if self.has_fields() && self.focused_field > 0 {
            self.focused_field -= 1;
        }
    }

    /// Toggle focused button.
    pub fn toggle_button(&mut self) {
        self.focused_button = 1 - self.focused_button;
    }

    /// Check if all required fields are filled.
    pub fn validate_fields(&self) -> bool {
        self.fields
            .iter()
            .filter(|f| f.required)
            .all(|f| !f.value.trim().is_empty())
    }

    /// Get field value by index.
    pub fn field_value(&self, idx: usize) -> Option<&str> {
        self.fields.get(idx).map(|f| f.value.as_str())
    }
}

/// Multi-contact application state.
pub struct MultiApp {
    // === Contacts ===
    /// All known contacts.
    pub contacts: Vec<Contact>,
    /// Index of selected contact in sidebar.
    pub selected_contact: usize,
    /// Sidebar scroll offset.
    pub sidebar_scroll: usize,
    /// Selected sidebar button (0 = Add, 1 = Quick, None = contact list).
    pub selected_sidebar_button: Option<usize>,

    // === Conversations ===
    /// Active conversations (contact_name -> conversation).
    pub conversations: HashMap<String, Conversation>,
    /// Open tabs (ordered list of contact names).
    pub tabs: Vec<String>,
    /// Currently active tab index.
    pub active_tab: usize,

    // === Input ===
    /// Current input text.
    pub input: String,
    /// Cursor position in input.
    pub cursor_position: usize,
    /// Maximum message length.
    pub max_message_len: usize,

    // === UI State ===
    /// Which panel is focused.
    pub focused_panel: FocusedPanel,
    /// Whether the app should quit.
    pub should_quit: bool,

    // === Global Status ===
    /// Tor connection status.
    pub tor_status: ConnectionStatus,
    /// Chat/Hidden service status.
    pub chat_status: ChatServiceStatus,
    /// Our .onion address.
    pub my_onion: Option<String>,
    /// Temporary status message (errors, warnings).
    pub status_message: Option<(String, u64)>, // (message, timestamp)

    // === Notifications & Requests ===
    /// Pending chat requests (not yet accepted/rejected).
    pub pending_requests: Vec<ChatRequest>,
    /// Notification queue (non-invasive alerts).
    pub notifications: Vec<Notification>,
    /// Counter for unique IDs.
    next_id: u64,

    // === Dialogs ===
    /// Currently active dialog (if any).
    pub active_dialog: Option<Dialog>,

    // === Console (Doom-style command input) ===
    /// Whether the console is open.
    pub console_open: bool,
    /// Console input text.
    pub console_input: String,
    /// Console cursor position.
    pub console_cursor: usize,
    /// Console output history (lines).
    pub console_output: Vec<String>,
    /// Console scroll offset.
    pub console_scroll: usize,
    /// Command history (for up/down navigation).
    pub console_history: Vec<String>,
    /// Current position in history (None = new command).
    pub console_history_index: Option<usize>,
    /// Temporary storage for current input when navigating history.
    pub console_history_temp: String,
}

impl MultiApp {
    /// Create a new multi-contact app.
    pub fn new() -> Self {
        Self {
            contacts: Vec::new(),
            selected_contact: 0,
            sidebar_scroll: 0,
            selected_sidebar_button: None,
            conversations: HashMap::new(),
            tabs: Vec::new(),
            active_tab: 0,
            input: String::new(),
            cursor_position: 0,
            max_message_len: DEFAULT_MAX_MESSAGE_LEN,
            focused_panel: FocusedPanel::Sidebar,
            should_quit: false,
            tor_status: ConnectionStatus::Disconnected,
            chat_status: ChatServiceStatus::Starting,
            my_onion: None,
            status_message: None,
            pending_requests: Vec::new(),
            notifications: Vec::new(),
            next_id: 1,
            active_dialog: None,
            console_open: false,
            console_input: String::new(),
            console_cursor: 0,
            console_output: Vec::new(),
            console_scroll: 0,
            console_history: Vec::new(),
            console_history_index: None,
            console_history_temp: String::new(),
        }
    }

    /// Get the next unique ID.
    fn next_id(&mut self) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        id
    }

    // === Dialog Management ===

    /// Check if a dialog is currently active.
    pub fn has_dialog(&self) -> bool {
        self.active_dialog.is_some()
    }

    /// Show a dialog.
    pub fn show_dialog(&mut self, dialog: Dialog) {
        self.active_dialog = Some(dialog);
    }

    /// Close the current dialog.
    pub fn close_dialog(&mut self) {
        self.active_dialog = None;
    }

    /// Show initiate chat dialog.
    pub fn show_initiate_dialog(&mut self, contact_name: &str, onion_address: &str) {
        self.active_dialog = Some(Dialog::initiate_chat(contact_name, onion_address));
    }

    /// Show incoming request dialog.
    pub fn show_incoming_request_dialog(&mut self, request: &ChatRequest) {
        let source_name = request.contact_name.clone()
            .unwrap_or_else(|| format!("~{}", &request.onion_address[..8.min(request.onion_address.len())]));
        self.active_dialog = Some(Dialog::incoming_request(
            request.id,
            source_name,
            &request.onion_address,
            request.is_known,
        ));
    }

    /// Show accept chat dialog (with passphrase).
    pub fn show_accept_dialog(&mut self, request_id: u64, source_name: &str, onion_address: &str) {
        self.active_dialog = Some(Dialog::accept_chat(request_id, source_name, onion_address));
    }

    /// Show error dialog.
    pub fn show_error_dialog(&mut self, title: &str, message: &str) {
        self.active_dialog = Some(Dialog::error(title, message));
    }

    /// Load contacts from config.
    pub fn load_contacts(&mut self, contacts: Vec<Contact>) {
        self.contacts = contacts;
    }

    /// Add a contact.
    pub fn add_contact(&mut self, contact: Contact) {
        // Check if already exists
        if !self.contacts.iter().any(|c| c.name == contact.name) {
            self.contacts.push(contact);
        }
    }

    /// Get the currently active conversation, if any.
    pub fn active_conversation(&self) -> Option<&Conversation> {
        self.tabs
            .get(self.active_tab)
            .and_then(|name| self.conversations.get(name))
    }

    /// Get mutable reference to active conversation.
    pub fn active_conversation_mut(&mut self) -> Option<&mut Conversation> {
        if let Some(name) = self.tabs.get(self.active_tab).cloned() {
            self.conversations.get_mut(&name)
        } else {
            None
        }
    }

    /// Get the currently selected contact.
    pub fn selected_contact(&self) -> Option<&Contact> {
        self.contacts.get(self.selected_contact)
    }

    /// Open a conversation with a contact (creates tab if needed).
    pub fn open_conversation(&mut self, contact_name: &str) {
        // Create conversation if it doesn't exist
        if !self.conversations.contains_key(contact_name) {
            self.conversations
                .insert(contact_name.to_string(), Conversation::new(contact_name));
        }

        // Add to tabs if not already there
        if !self.tabs.contains(&contact_name.to_string()) {
            self.tabs.push(contact_name.to_string());
        }

        // Switch to this tab
        if let Some(idx) = self.tabs.iter().position(|n| n == contact_name) {
            self.active_tab = idx;
        }

        // Clear unread for this contact
        if let Some(contact) = self.contacts.iter_mut().find(|c| c.name == contact_name) {
            contact.unread = 0;
        }

        // Focus on input
        self.focused_panel = FocusedPanel::Input;
    }

    /// Close the active tab.
    pub fn close_active_tab(&mut self) {
        if self.tabs.is_empty() {
            return;
        }

        let name = self.tabs.remove(self.active_tab);

        // Remove conversation
        self.conversations.remove(&name);

        // Adjust active tab
        if self.active_tab >= self.tabs.len() && self.active_tab > 0 {
            self.active_tab -= 1;
        }

        // If no tabs left, focus sidebar
        if self.tabs.is_empty() {
            self.focused_panel = FocusedPanel::Sidebar;
        }
    }

    /// Switch to next tab.
    pub fn next_tab(&mut self) {
        if !self.tabs.is_empty() {
            self.active_tab = (self.active_tab + 1) % self.tabs.len();
            // Clear unread
            if let Some(name) = self.tabs.get(self.active_tab) {
                if let Some(contact) = self.contacts.iter_mut().find(|c| &c.name == name) {
                    contact.unread = 0;
                }
            }
        }
    }

    /// Switch to previous tab.
    pub fn prev_tab(&mut self) {
        if !self.tabs.is_empty() {
            self.active_tab = if self.active_tab == 0 {
                self.tabs.len() - 1
            } else {
                self.active_tab - 1
            };
            // Clear unread
            if let Some(name) = self.tabs.get(self.active_tab) {
                if let Some(contact) = self.contacts.iter_mut().find(|c| &c.name == name) {
                    contact.unread = 0;
                }
            }
        }
    }

    /// Move selection up in sidebar.
    pub fn select_up(&mut self) {
        match self.selected_sidebar_button {
            Some(0) => {
                // From Add button, go back to last contact
                self.selected_sidebar_button = None;
                if !self.contacts.is_empty() {
                    self.selected_contact = self.contacts.len() - 1;
                }
            }
            Some(1) => {
                // From Quick button, go to Add button
                self.selected_sidebar_button = Some(0);
            }
            Some(_) => {
                self.selected_sidebar_button = Some(0);
            }
            None => {
                // In contacts list
                if !self.contacts.is_empty() {
                    if self.selected_contact == 0 {
                        // Wrap to Quick button (bottom of sidebar)
                        self.selected_sidebar_button = Some(1);
                    } else {
                        self.selected_contact -= 1;
                    }
                } else {
                    // No contacts, wrap to Quick button
                    self.selected_sidebar_button = Some(1);
                }
            }
        }
    }

    /// Move selection down in sidebar.
    pub fn select_down(&mut self) {
        match self.selected_sidebar_button {
            Some(0) => {
                // From Add button, go to Quick button
                self.selected_sidebar_button = Some(1);
            }
            Some(1) => {
                // From Quick button, wrap to first contact
                self.selected_sidebar_button = None;
                self.selected_contact = 0;
            }
            Some(_) => {
                self.selected_sidebar_button = None;
                self.selected_contact = 0;
            }
            None => {
                // In contacts list
                if self.contacts.is_empty() {
                    // No contacts, go to Add button
                    self.selected_sidebar_button = Some(0);
                } else if self.selected_contact >= self.contacts.len() - 1 {
                    // At last contact, go to Add button
                    self.selected_sidebar_button = Some(0);
                } else {
                    self.selected_contact += 1;
                }
            }
        }
    }

    /// Cycle focus between panels.
    pub fn cycle_focus(&mut self) {
        self.focused_panel = match self.focused_panel {
            FocusedPanel::Sidebar => {
                if self.tabs.is_empty() {
                    FocusedPanel::Sidebar
                } else {
                    FocusedPanel::Input
                }
            }
            FocusedPanel::Tabs => FocusedPanel::Input,
            FocusedPanel::Input => FocusedPanel::Sidebar,
        };
    }

    /// Receive a message from a contact (updates unread if not active).
    pub fn receive_message(&mut self, contact_name: &str, content: &str) {
        // Create conversation if needed
        if !self.conversations.contains_key(contact_name) {
            self.conversations
                .insert(contact_name.to_string(), Conversation::new(contact_name));
        }

        // Add message
        if let Some(conv) = self.conversations.get_mut(contact_name) {
            conv.add_peer_message(content);
        }

        // Update unread if not the active tab
        let is_active = self.tabs.get(self.active_tab).map(|n| n == contact_name).unwrap_or(false);
        if !is_active {
            if let Some(contact) = self.contacts.iter_mut().find(|c| c.name == contact_name) {
                contact.unread += 1;
            }
        }
    }

    /// Update contact status.
    pub fn set_contact_status(&mut self, contact_name: &str, status: ContactStatus) {
        if let Some(contact) = self.contacts.iter_mut().find(|c| c.name == contact_name) {
            contact.status = status;
        }
    }

    /// Set temporary status message.
    pub fn set_status_message(&mut self, message: impl Into<String>) {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.status_message = Some((message.into(), timestamp));
    }

    /// Clear expired status message (after 5 seconds).
    pub fn clear_expired_status(&mut self) {
        if let Some((_, timestamp)) = &self.status_message {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            if now - timestamp >= 5 {
                self.status_message = None;
            }
        }
    }

    // === Notifications & Requests ===

    /// Add a notification.
    pub fn add_notification(&mut self, kind: NotificationKind, message: impl Into<String>) -> u64 {
        let id = self.next_id();
        let notification = Notification::new(id, kind, message);
        self.notifications.push(notification);
        id
    }

    /// Add a notification with source.
    pub fn add_notification_with_source(
        &mut self,
        kind: NotificationKind,
        message: impl Into<String>,
        source: impl Into<String>,
    ) -> u64 {
        let id = self.next_id();
        let notification = Notification::new(id, kind, message).with_source(source);
        self.notifications.push(notification);
        id
    }

    /// Get unseen notification count.
    pub fn unseen_notification_count(&self) -> usize {
        self.notifications.iter().filter(|n| !n.seen).count()
    }

    /// Get unseen notification count by kind.
    pub fn unseen_count_by_kind(&self, kind: &NotificationKind) -> usize {
        self.notifications
            .iter()
            .filter(|n| !n.seen && &n.kind == kind)
            .count()
    }

    /// Mark a notification as seen.
    pub fn mark_notification_seen(&mut self, id: u64) {
        if let Some(n) = self.notifications.iter_mut().find(|n| n.id == id) {
            n.seen = true;
        }
    }

    /// Mark all notifications as seen.
    pub fn mark_all_notifications_seen(&mut self) {
        for n in &mut self.notifications {
            n.seen = true;
        }
    }

    /// Remove a notification by ID.
    pub fn remove_notification(&mut self, id: u64) {
        self.notifications.retain(|n| n.id != id);
    }

    /// Clear old notifications (older than 60 seconds and seen).
    pub fn clear_old_notifications(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.notifications
            .retain(|n| !n.seen || now - n.timestamp < 60);
    }

    /// Get the first unseen notification (if any).
    pub fn first_unseen_notification(&self) -> Option<&Notification> {
        self.notifications.iter().find(|n| !n.seen)
    }

    /// Add a chat request (incoming).
    pub fn add_chat_request(&mut self, onion_address: impl Into<String>) -> u64 {
        let onion = onion_address.into();
        let id = self.next_id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Check if this is from a known contact (match by onion address)
        let (is_known, contact_name) = self
            .contacts
            .iter()
            .find(|c| c.onion_address.as_deref() == Some(&onion))
            .map(|c| (true, Some(c.name.clone())))
            .unwrap_or((false, None));

        let request = ChatRequest {
            id,
            onion_address: onion.clone(),
            contact_name: contact_name.clone(),
            is_known,
            timestamp,
        };
        self.pending_requests.push(request);

        // Add notification based on type
        let (kind, msg) = if is_known {
            let name = contact_name.as_deref().unwrap_or("contact");
            (
                NotificationKind::KnownContactRequest,
                format!("{} wants to chat", name),
            )
        } else {
            let short_onion = if onion.len() > 16 {
                format!("{}...", &onion[..12])
            } else {
                onion.clone()
            };
            (
                NotificationKind::EphemeralRequest,
                format!("Unknown: {}", short_onion),
            )
        };
        self.add_notification_with_source(kind, msg, onion);

        id
    }

    /// Add a chat request with a pre-resolved name (from signing key lookup).
    pub fn add_chat_request_with_name(&mut self, display_name: &str, is_known: bool) -> u64 {
        let id = self.next_id();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let request = ChatRequest {
            id,
            onion_address: display_name.to_string(),
            contact_name: if is_known { Some(display_name.to_string()) } else { None },
            is_known,
            timestamp,
        };
        self.pending_requests.push(request);

        // Add notification
        let (kind, msg) = if is_known {
            (
                NotificationKind::KnownContactRequest,
                format!("{} wants to chat", display_name),
            )
        } else {
            (
                NotificationKind::EphemeralRequest,
                format!("Unknown: {}", display_name),
            )
        };
        self.add_notification_with_source(kind, msg, display_name.to_string());

        id
    }

    /// Get pending request count.
    pub fn pending_request_count(&self) -> usize {
        self.pending_requests.len()
    }

    /// Get pending request count by type.
    pub fn pending_request_count_by_type(&self, known: bool) -> usize {
        self.pending_requests
            .iter()
            .filter(|r| r.is_known == known)
            .count()
    }

    /// Get a pending request by ID.
    pub fn get_request(&self, id: u64) -> Option<&ChatRequest> {
        self.pending_requests.iter().find(|r| r.id == id)
    }

    /// Accept a chat request (returns the request and removes it from pending).
    pub fn accept_request(&mut self, id: u64) -> Option<ChatRequest> {
        let pos = self.pending_requests.iter().position(|r| r.id == id)?;
        let request = self.pending_requests.remove(pos);

        // Add notification
        let name = request
            .contact_name
            .as_deref()
            .unwrap_or(&request.onion_address);
        self.add_notification(NotificationKind::Info, format!("Connecting to {}...", name));

        // Remove the request notification
        self.notifications.retain(|n| {
            n.source.as_deref() != Some(&request.onion_address)
                || !matches!(
                    n.kind,
                    NotificationKind::KnownContactRequest | NotificationKind::EphemeralRequest
                )
        });

        Some(request)
    }

    /// Reject a chat request (removes it from pending).
    pub fn reject_request(&mut self, id: u64) -> Option<ChatRequest> {
        let pos = self.pending_requests.iter().position(|r| r.id == id)?;
        let request = self.pending_requests.remove(pos);

        // Remove the request notification
        self.notifications.retain(|n| {
            n.source.as_deref() != Some(&request.onion_address)
                || !matches!(
                    n.kind,
                    NotificationKind::KnownContactRequest | NotificationKind::EphemeralRequest
                )
        });

        Some(request)
    }

    /// Check if there's a pending request from this source.
    pub fn has_pending_request(&self, onion_address: &str) -> bool {
        self.pending_requests
            .iter()
            .any(|r| r.onion_address == onion_address)
    }

    // === Input handling ===

    /// Get remaining characters.
    pub fn remaining_chars(&self) -> usize {
        self.max_message_len.saturating_sub(self.input.chars().count())
    }

    /// Check if at max length.
    pub fn is_input_at_max(&self) -> bool {
        self.input.chars().count() >= self.max_message_len
    }

    /// Insert a character.
    pub fn enter_char(&mut self, c: char) {
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
        let from_left = current_index - 1;
        let before = self.input.chars().take(from_left);
        let after = self.input.chars().skip(current_index);
        self.input = before.chain(after).collect();
        self.move_cursor_left();
    }

    /// Move cursor left.
    pub fn move_cursor_left(&mut self) {
        self.cursor_position = self.cursor_position.saturating_sub(1);
    }

    /// Move cursor right.
    pub fn move_cursor_right(&mut self) {
        let max = self.input.chars().count();
        self.cursor_position = (self.cursor_position + 1).min(max);
    }

    /// Move cursor to start.
    pub fn move_cursor_home(&mut self) {
        self.cursor_position = 0;
    }

    /// Move cursor to end.
    pub fn move_cursor_end(&mut self) {
        self.cursor_position = self.input.chars().count();
    }

    /// Get byte index for cursor.
    fn byte_index(&self) -> usize {
        self.input
            .char_indices()
            .map(|(i, _)| i)
            .nth(self.cursor_position)
            .unwrap_or(self.input.len())
    }

    /// Take the current input.
    pub fn take_input(&mut self) -> String {
        self.cursor_position = 0;
        std::mem::take(&mut self.input)
    }

    // === Console Management ===

    /// Toggle the console open/closed.
    pub fn toggle_console(&mut self) {
        self.console_open = !self.console_open;
        if !self.console_open {
            self.console_input.clear();
            self.console_cursor = 0;
            self.console_history_index = None;
            self.console_history_temp.clear();
        }
    }

    /// Open the console.
    pub fn open_console(&mut self) {
        self.console_open = true;
    }

    /// Close the console.
    pub fn close_console(&mut self) {
        self.console_open = false;
        self.console_input.clear();
        self.console_cursor = 0;
        self.console_history_index = None;
        self.console_history_temp.clear();
    }

    /// Type a character in the console.
    pub fn console_type_char(&mut self, c: char) {
        // Reset history navigation when typing
        self.console_history_index = None;
        self.console_input.insert(self.console_cursor, c);
        self.console_cursor += 1;
    }

    /// Delete character before cursor in console.
    pub fn console_delete_char(&mut self) {
        if self.console_cursor > 0 {
            self.console_history_index = None;
            self.console_cursor -= 1;
            self.console_input.remove(self.console_cursor);
        }
    }

    /// Move console cursor left.
    pub fn console_cursor_left(&mut self) {
        self.console_cursor = self.console_cursor.saturating_sub(1);
    }

    /// Move console cursor right.
    pub fn console_cursor_right(&mut self) {
        let max = self.console_input.chars().count();
        self.console_cursor = (self.console_cursor + 1).min(max);
    }

    /// Take the console input (but keep console open).
    pub fn take_console_input(&mut self) -> String {
        let input = std::mem::take(&mut self.console_input);
        // Add to history if non-empty
        if !input.is_empty() {
            self.console_history.push(input.clone());
        }
        self.console_cursor = 0;
        self.console_history_index = None;
        self.console_history_temp.clear();
        input
    }

    /// Navigate to previous command in history (Up arrow).
    pub fn console_history_prev(&mut self) {
        if self.console_history.is_empty() {
            return;
        }

        match self.console_history_index {
            None => {
                // Save current input and go to most recent history
                self.console_history_temp = self.console_input.clone();
                self.console_history_index = Some(self.console_history.len() - 1);
            }
            Some(0) => {
                // Already at oldest, do nothing
                return;
            }
            Some(idx) => {
                self.console_history_index = Some(idx - 1);
            }
        }

        // Load history entry
        if let Some(idx) = self.console_history_index {
            self.console_input = self.console_history[idx].clone();
            self.console_cursor = self.console_input.chars().count();
        }
    }

    /// Navigate to next command in history (Down arrow).
    pub fn console_history_next(&mut self) {
        match self.console_history_index {
            None => {
                // Not in history mode, do nothing
                return;
            }
            Some(idx) if idx >= self.console_history.len() - 1 => {
                // At most recent, restore temp input
                self.console_input = std::mem::take(&mut self.console_history_temp);
                self.console_cursor = self.console_input.chars().count();
                self.console_history_index = None;
            }
            Some(idx) => {
                self.console_history_index = Some(idx + 1);
                self.console_input = self.console_history[idx + 1].clone();
                self.console_cursor = self.console_input.chars().count();
            }
        }
    }

    /// Add output lines to the console.
    pub fn console_print(&mut self, text: &str) {
        for line in text.lines() {
            self.console_output.push(line.to_string());
        }
        // Auto-scroll to bottom
        self.console_scroll = 0;
    }

    /// Add a single line to console output.
    pub fn console_println(&mut self, line: &str) {
        self.console_output.push(line.to_string());
        self.console_scroll = 0;
    }

    /// Clear console output.
    pub fn console_clear(&mut self) {
        self.console_output.clear();
        self.console_scroll = 0;
    }

    /// Scroll console up.
    pub fn console_scroll_up(&mut self, lines: usize) {
        let max_scroll = self.console_output.len().saturating_sub(5);
        self.console_scroll = (self.console_scroll + lines).min(max_scroll);
    }

    /// Scroll console down.
    pub fn console_scroll_down(&mut self, lines: usize) {
        self.console_scroll = self.console_scroll.saturating_sub(lines);
    }

    /// Securely clear all console data (zeroize).
    pub fn console_zeroize(&mut self) {
        self.console_input.zeroize();
        self.console_cursor = 0;
        for line in &mut self.console_output {
            line.zeroize();
        }
        self.console_output.clear();
        self.console_scroll = 0;
        for cmd in &mut self.console_history {
            cmd.zeroize();
        }
        self.console_history.clear();
        self.console_history_index = None;
        self.console_history_temp.zeroize();
    }
}

impl Default for MultiApp {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_contact_display() {
        let mut contact = Contact::new("alice");
        assert_eq!(contact.display_name(), "○ alice");

        contact.status = ContactStatus::Online;
        assert_eq!(contact.display_name(), "● alice");

        contact.unread = 3;
        assert_eq!(contact.display_name(), "● alice (3)");
    }

    #[test]
    fn test_contact_tab_label() {
        let mut contact = Contact::new("bob");
        assert_eq!(contact.tab_label(), " bob ");

        contact.unread = 2;
        assert_eq!(contact.tab_label(), " bob (2) ");
    }

    #[test]
    fn test_ephemeral_contact() {
        let contact = Contact::ephemeral("~guest");
        assert!(contact.is_ephemeral);
        assert_eq!(contact.status, ContactStatus::Ephemeral);
        assert_eq!(contact.display_name(), "◌ ~guest");
    }

    #[test]
    fn test_open_conversation() {
        let mut app = MultiApp::new();
        app.add_contact(Contact::new("alice"));

        assert!(app.tabs.is_empty());
        assert!(app.conversations.is_empty());

        app.open_conversation("alice");

        assert_eq!(app.tabs.len(), 1);
        assert_eq!(app.tabs[0], "alice");
        assert!(app.conversations.contains_key("alice"));
        assert_eq!(app.active_tab, 0);
    }

    #[test]
    fn test_tab_navigation() {
        let mut app = MultiApp::new();
        app.open_conversation("alice");
        app.open_conversation("bob");
        app.open_conversation("charlie");

        assert_eq!(app.active_tab, 2); // charlie is active

        app.prev_tab();
        assert_eq!(app.active_tab, 1); // bob

        app.prev_tab();
        assert_eq!(app.active_tab, 0); // alice

        app.prev_tab();
        assert_eq!(app.active_tab, 2); // wraps to charlie

        app.next_tab();
        assert_eq!(app.active_tab, 0); // wraps to alice
    }

    #[test]
    fn test_receive_message_updates_unread() {
        let mut app = MultiApp::new();
        app.add_contact(Contact::new("alice"));
        app.add_contact(Contact::new("bob"));

        // Open alice's conversation
        app.open_conversation("alice");

        // Receive message from bob (not active)
        app.receive_message("bob", "Hello!");

        // Bob should have unread
        let bob = app.contacts.iter().find(|c| c.name == "bob").unwrap();
        assert_eq!(bob.unread, 1);

        // Alice should have no unread (active)
        app.receive_message("alice", "Hi!");
        let alice = app.contacts.iter().find(|c| c.name == "alice").unwrap();
        assert_eq!(alice.unread, 0);
    }

    #[test]
    fn test_close_tab() {
        let mut app = MultiApp::new();
        app.open_conversation("alice");
        app.open_conversation("bob");

        assert_eq!(app.tabs.len(), 2);

        app.active_tab = 0;
        app.close_active_tab();

        assert_eq!(app.tabs.len(), 1);
        assert_eq!(app.tabs[0], "bob");
        assert!(!app.conversations.contains_key("alice"));
    }

    #[test]
    fn test_sidebar_navigation() {
        let mut app = MultiApp::new();
        app.add_contact(Contact::new("alice"));
        app.add_contact(Contact::new("bob"));
        app.add_contact(Contact::new("charlie"));

        assert_eq!(app.selected_contact, 0);
        assert_eq!(app.selected_sidebar_button, None);

        app.select_down();
        assert_eq!(app.selected_contact, 1);
        assert_eq!(app.selected_sidebar_button, None);

        app.select_down();
        assert_eq!(app.selected_contact, 2);
        assert_eq!(app.selected_sidebar_button, None);

        // After last contact, go to Add button
        app.select_down();
        assert_eq!(app.selected_sidebar_button, Some(0)); // Add button

        // Then to Quick button
        app.select_down();
        assert_eq!(app.selected_sidebar_button, Some(1)); // Quick button

        // Then wrap to first contact
        app.select_down();
        assert_eq!(app.selected_contact, 0);
        assert_eq!(app.selected_sidebar_button, None);

        // Go up should wrap to Quick button
        app.select_up();
        assert_eq!(app.selected_sidebar_button, Some(1)); // Quick button

        // Then to Add button
        app.select_up();
        assert_eq!(app.selected_sidebar_button, Some(0)); // Add button

        // Then to last contact
        app.select_up();
        assert_eq!(app.selected_contact, 2);
        assert_eq!(app.selected_sidebar_button, None);
    }

    #[test]
    fn test_notification_add_and_count() {
        let mut app = MultiApp::new();

        assert_eq!(app.unseen_notification_count(), 0);

        app.add_notification(NotificationKind::Info, "Test message");
        assert_eq!(app.unseen_notification_count(), 1);

        app.add_notification(NotificationKind::Error, "Error message");
        assert_eq!(app.unseen_notification_count(), 2);

        // Mark one as seen
        let first_id = app.notifications[0].id;
        app.mark_notification_seen(first_id);
        assert_eq!(app.unseen_notification_count(), 1);

        // Mark all as seen
        app.mark_all_notifications_seen();
        assert_eq!(app.unseen_notification_count(), 0);
    }

    #[test]
    fn test_notification_by_kind() {
        let mut app = MultiApp::new();

        app.add_notification(NotificationKind::KnownContactRequest, "Alice wants to chat");
        app.add_notification(NotificationKind::EphemeralRequest, "Unknown request");
        app.add_notification(NotificationKind::Info, "Info message");

        assert_eq!(app.unseen_count_by_kind(&NotificationKind::KnownContactRequest), 1);
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::EphemeralRequest), 1);
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::Info), 1);
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::Error), 0);
    }

    #[test]
    fn test_chat_request_unknown() {
        let mut app = MultiApp::new();

        let id = app.add_chat_request("abc123xyz456.onion");

        assert_eq!(app.pending_request_count(), 1);
        assert_eq!(app.pending_request_count_by_type(false), 1); // unknown
        assert_eq!(app.pending_request_count_by_type(true), 0);  // known

        // Should create a notification
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::EphemeralRequest), 1);

        // Request should exist
        let request = app.get_request(id).unwrap();
        assert!(!request.is_known);
        assert!(request.contact_name.is_none());
    }

    #[test]
    fn test_chat_request_known_contact() {
        let mut app = MultiApp::new();
        let onion = "knowncontact12345.onion";
        app.add_contact(Contact::with_onion("alice", onion));

        let id = app.add_chat_request(onion);

        assert_eq!(app.pending_request_count(), 1);
        assert_eq!(app.pending_request_count_by_type(true), 1);  // known
        assert_eq!(app.pending_request_count_by_type(false), 0); // unknown

        // Should create a known contact notification
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::KnownContactRequest), 1);

        // Request should be from known contact
        let request = app.get_request(id).unwrap();
        assert!(request.is_known);
        assert_eq!(request.contact_name, Some("alice".to_string()));
    }

    #[test]
    fn test_accept_request() {
        let mut app = MultiApp::new();

        let id = app.add_chat_request("test123.onion");
        assert_eq!(app.pending_request_count(), 1);

        // Accept the request
        let request = app.accept_request(id).unwrap();
        assert_eq!(request.onion_address, "test123.onion");
        assert_eq!(app.pending_request_count(), 0);

        // Notification should be removed and replaced with "Connecting..."
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::EphemeralRequest), 0);
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::Info), 1);
    }

    #[test]
    fn test_reject_request() {
        let mut app = MultiApp::new();

        let id = app.add_chat_request("test456.onion");
        assert_eq!(app.pending_request_count(), 1);

        // Reject the request
        let request = app.reject_request(id).unwrap();
        assert_eq!(request.onion_address, "test456.onion");
        assert_eq!(app.pending_request_count(), 0);

        // Request notification should be removed
        assert_eq!(app.unseen_count_by_kind(&NotificationKind::EphemeralRequest), 0);
    }

    #[test]
    fn test_has_pending_request() {
        let mut app = MultiApp::new();

        assert!(!app.has_pending_request("test.onion"));

        app.add_chat_request("test.onion");
        assert!(app.has_pending_request("test.onion"));
        assert!(!app.has_pending_request("other.onion"));
    }

    #[test]
    fn test_contact_status_icons() {
        assert_eq!(ContactStatus::Online.icon(), "●");
        assert_eq!(ContactStatus::Offline.icon(), "○");
        assert_eq!(ContactStatus::Ephemeral.icon(), "◌");
        assert_eq!(ContactStatus::Connecting.icon(), "◐");
        assert_eq!(ContactStatus::IncomingRequest.icon(), "◀");
        assert_eq!(ContactStatus::PendingAccept.icon(), "▶");
    }

    #[test]
    fn test_contact_with_onion() {
        let contact = Contact::with_onion("alice", "abc123.onion");
        assert_eq!(contact.name, "alice");
        assert_eq!(contact.onion_address, Some("abc123.onion".to_string()));
        assert!(!contact.is_ephemeral);
    }

    #[test]
    fn test_ephemeral_with_onion() {
        let contact = Contact::ephemeral_with_onion("~guest", "xyz789.onion");
        assert_eq!(contact.name, "~guest");
        assert_eq!(contact.onion_address, Some("xyz789.onion".to_string()));
        assert!(contact.is_ephemeral);
        assert_eq!(contact.status, ContactStatus::Ephemeral);
    }
}
