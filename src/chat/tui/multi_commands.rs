//! Chat command system using Strategy pattern.
//!
//! Each command is a separate struct implementing the `ChatCommand` trait,
//! following the Open/Closed Principle - add new commands without modifying existing code.

use super::multi_app::MultiApp;
use super::multi_event::MultiKeyAction;

// ============================================================================
// Command Trait (Strategy Interface)
// ============================================================================

/// Trait for chat commands (Strategy pattern).
pub trait ChatCommand: Send + Sync {
    /// Command name (primary).
    fn name(&self) -> &'static str;

    /// Command aliases (shortcuts).
    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    /// Short description for help.
    fn description(&self) -> &'static str;

    /// Execute the command with given arguments.
    fn execute(&self, app: &mut MultiApp, args: &[&str]) -> MultiKeyAction;
}

// ============================================================================
// Command Implementations
// ============================================================================

/// Quit the application.
pub struct QuitCommand;

impl ChatCommand for QuitCommand {
    fn name(&self) -> &'static str {
        "quit"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["q", "exit"]
    }

    fn description(&self) -> &'static str {
        "Quit the application"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        app.should_quit = true;
        MultiKeyAction::Quit
    }
}

/// Close the active tab.
pub struct CloseCommand;

impl ChatCommand for CloseCommand {
    fn name(&self) -> &'static str {
        "close"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["c"]
    }

    fn description(&self) -> &'static str {
        "Close active conversation tab"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        app.close_active_tab();
        MultiKeyAction::CloseTab
    }
}

/// Show session status.
pub struct StatusCommand;

impl ChatCommand for StatusCommand {
    fn name(&self) -> &'static str {
        "status"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["s"]
    }

    fn description(&self) -> &'static str {
        "Show session status"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        if let Some(conv) = app.active_conversation_mut() {
            conv.add_system_message(format!(
                "Session: {} | Sent: {} | Received: {}",
                conv.contact_name, conv.messages_sent, conv.messages_received
            ));
        }
        MultiKeyAction::None
    }
}

/// Clear conversation messages.
pub struct ClearCommand;

impl ChatCommand for ClearCommand {
    fn name(&self) -> &'static str {
        "clear"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    fn description(&self) -> &'static str {
        "Clear conversation messages"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        if let Some(conv) = app.active_conversation_mut() {
            conv.messages.clear();
            conv.scroll_offset = 0;
        }
        MultiKeyAction::None
    }
}

/// Show pending chat requests.
pub struct RequestsCommand;

impl ChatCommand for RequestsCommand {
    fn name(&self) -> &'static str {
        "requests"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["r"]
    }

    fn description(&self) -> &'static str {
        "Show pending chat requests"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        let known = app.pending_request_count_by_type(true);
        let unknown = app.pending_request_count_by_type(false);
        let msg = format!(
            "Pending requests: {} known, {} unknown. Press 'r' in sidebar to view.",
            known, unknown
        );
        if let Some(conv) = app.active_conversation_mut() {
            conv.add_system_message(&msg);
        } else {
            app.set_status_message(&msg);
        }
        MultiKeyAction::ViewRequests
    }
}

/// Show notification count.
pub struct NotificationsCommand;

impl ChatCommand for NotificationsCommand {
    fn name(&self) -> &'static str {
        "notifications"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["n"]
    }

    fn description(&self) -> &'static str {
        "Show notification count"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        let unseen = app.unseen_notification_count();
        let msg = format!(
            "{} unseen notifications. Press 'n' to view, 'N' to clear all.",
            unseen
        );
        if let Some(conv) = app.active_conversation_mut() {
            conv.add_system_message(&msg);
        } else {
            app.set_status_message(&msg);
        }
        MultiKeyAction::None
    }
}

/// Show help with available commands.
pub struct HelpCommand;

impl ChatCommand for HelpCommand {
    fn name(&self) -> &'static str {
        "help"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["h", "?"]
    }

    fn description(&self) -> &'static str {
        "Show available commands and keyboard shortcuts"
    }

    fn execute(&self, app: &mut MultiApp, args: &[&str]) -> MultiKeyAction {
        let show_keys = args.first().map(|a| *a == "keys" || *a == "k").unwrap_or(false);

        let help_text = if show_keys {
            KEYBOARD_HELP.to_string()
        } else {
            let commands = CommandRegistry::default();
            format!(
                "{}\n\n{}\n\nTip: /help keys - show keyboard shortcuts",
                commands.help_text(),
                "Press Ctrl+/ to open console from anywhere"
            )
        };

        if let Some(conv) = app.active_conversation_mut() {
            conv.add_system_message(&help_text);
        } else {
            // When no conversation, show in status message
            app.set_status_message("Ctrl+/ for console, /help for commands");
        }
        MultiKeyAction::None
    }
}

/// Keyboard shortcuts help text.
const KEYBOARD_HELP: &str = r#"Keyboard Shortcuts:

GLOBAL:
  Ctrl+Q        Quit application
  Ctrl+P        Open command console (works everywhere)
  /             Open console (sidebar/tabs only)
  Tab           Switch panel (Sidebar → Input)
  Shift+Tab     Switch panel backwards
  Ctrl+W        Close active tab
  Ctrl+←/→      Switch tabs
  Alt+1-9       Go to tab by number

SIDEBAR:
  ↑/↓ or j/k    Navigate contacts
  Enter         Open conversation
  +             Add contact
  e             Quick ephemeral chat
  r             View known contact requests
  z             View unknown requests
  n             View notification
  N             Mark all notifications seen

INPUT:
  Enter         Send message
  PageUp/Down   Scroll messages (5 lines)
  Ctrl+↑/↓      Scroll messages (1 line)

TABS:
  ←/→ or h/l    Switch tabs
  PageUp/Down   Scroll messages

CONSOLE:
  ↑/↓           Navigate command history
  PgUp/PgDn     Scroll output
  Esc           Close console"#;

/// Show your .onion address.
pub struct MyOnionCommand;

impl ChatCommand for MyOnionCommand {
    fn name(&self) -> &'static str {
        "myonion"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["me"]
    }

    fn description(&self) -> &'static str {
        "Show your .onion address"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        let msg = match &app.my_onion {
            Some(onion) => format!("Your .onion: {}", onion),
            None => "No .onion address available".to_string(),
        };
        if let Some(conv) = app.active_conversation_mut() {
            conv.add_system_message(&msg);
        } else {
            app.set_status_message(&msg);
        }
        MultiKeyAction::None
    }
}

/// Show a contact's .onion address.
pub struct WhoCommand;

impl ChatCommand for WhoCommand {
    fn name(&self) -> &'static str {
        "who"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &[]
    }

    fn description(&self) -> &'static str {
        "Show contact's .onion address"
    }

    fn execute(&self, app: &mut MultiApp, args: &[&str]) -> MultiKeyAction {
        let msg = if let Some(name) = args.first() {
            // Look up by name
            if let Some(contact) = app.contacts.iter().find(|c| c.name.eq_ignore_ascii_case(name))
            {
                if let Some(ref onion) = contact.onion_address {
                    format!("{}'s .onion: {}", contact.name, onion)
                } else {
                    format!("{} has no .onion address stored", contact.name)
                }
            } else {
                format!("Contact '{}' not found", name)
            }
        } else {
            // Show selected contact's .onion
            if let Some(contact) = app.selected_contact() {
                if let Some(ref onion) = contact.onion_address {
                    format!("{}'s .onion: {}", contact.name, onion)
                } else {
                    format!("{} has no .onion address", contact.name)
                }
            } else {
                "Usage: /who <contact_name> or select a contact".to_string()
            }
        };

        if let Some(conv) = app.active_conversation_mut() {
            conv.add_system_message(&msg);
        } else {
            app.set_status_message(&msg);
        }
        MultiKeyAction::None
    }
}

/// Show debug information.
pub struct DebugCommand;

impl ChatCommand for DebugCommand {
    fn name(&self) -> &'static str {
        "debug"
    }

    fn aliases(&self) -> &'static [&'static str] {
        &["d"]
    }

    fn description(&self) -> &'static str {
        "Show debug information"
    }

    fn execute(&self, app: &mut MultiApp, _args: &[&str]) -> MultiKeyAction {
        let my_onion = app.my_onion.as_deref().unwrap_or("not set");
        let contacts_count = app.contacts.len();
        let pending_count = app.pending_request_count();
        let notif_count = app.unseen_notification_count();
        let conv_count = app.conversations.len();

        let msg = format!(
            "Debug info:\n\
             - My .onion: {}\n\
             - Contacts: {}\n\
             - Pending requests: {}\n\
             - Notifications: {}\n\
             - Active conversations: {}\n\
             - Tor status: {:?}",
            my_onion, contacts_count, pending_count, notif_count, conv_count, app.tor_status
        );

        if let Some(conv) = app.active_conversation_mut() {
            conv.add_system_message(&msg);
        } else {
            app.set_status_message("Open a chat to see debug info");
        }
        MultiKeyAction::None
    }
}

// ============================================================================
// Command Registry
// ============================================================================

/// Registry of all available commands.
pub struct CommandRegistry {
    commands: Vec<Box<dyn ChatCommand>>,
}

impl Default for CommandRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CommandRegistry {
    /// Create a new registry with all built-in commands.
    pub fn new() -> Self {
        let commands: Vec<Box<dyn ChatCommand>> = vec![
            Box::new(QuitCommand),
            Box::new(CloseCommand),
            Box::new(StatusCommand),
            Box::new(ClearCommand),
            Box::new(RequestsCommand),
            Box::new(NotificationsCommand),
            Box::new(HelpCommand),
            Box::new(DebugCommand),
            Box::new(MyOnionCommand),
            Box::new(WhoCommand),
        ];
        Self { commands }
    }

    /// Find a command by name or alias.
    pub fn find(&self, name: &str) -> Option<&dyn ChatCommand> {
        let name_lower = name.to_lowercase();
        for cmd in &self.commands {
            if cmd.name() == name_lower {
                return Some(cmd.as_ref());
            }
            if cmd.aliases().iter().any(|a| *a == name_lower) {
                return Some(cmd.as_ref());
            }
        }
        None
    }

    /// Execute a command by name with arguments.
    pub fn execute(&self, app: &mut MultiApp, name: &str, args: &[&str]) -> Option<MultiKeyAction> {
        self.find(name).map(|cmd| cmd.execute(app, args))
    }

    /// Generate help text listing all commands.
    pub fn help_text(&self) -> String {
        let mut lines: Vec<String> = vec!["Available commands:".to_string()];
        for cmd in &self.commands {
            let aliases = cmd.aliases();
            let alias_str = if aliases.is_empty() {
                String::new()
            } else {
                format!(" ({})", aliases.join(", "))
            };
            lines.push(format!("  /{}{} - {}", cmd.name(), alias_str, cmd.description()));
        }
        lines.join("\n")
    }
}

// ============================================================================
// Public Interface
// ============================================================================

/// Handle a chat command using the strategy pattern.
/// Returns the appropriate action or None if the command was not found.
pub fn execute_command(app: &mut MultiApp, input: &str) -> MultiKeyAction {
    let cmd = input.trim_start_matches('/');
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    let (name, args) = match parts.split_first() {
        Some((first, rest)) => (*first, rest),
        None => return MultiKeyAction::None,
    };

    let registry = CommandRegistry::default();

    match registry.execute(app, name, args) {
        Some(action) => action,
        None => {
            // Unknown command
            if let Some(conv) = app.active_conversation_mut() {
                conv.add_system_message(format!("Unknown command: {}. Try /help", input));
            }
            MultiKeyAction::None
        }
    }
}

/// Execute a command from the console, outputting to console instead of chat.
pub fn execute_console_command(app: &mut MultiApp, input: &str) -> MultiKeyAction {
    let cmd = input.trim_start_matches('/');
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    let (name, args) = match parts.split_first() {
        Some((first, rest)) => (*first, rest),
        None => return MultiKeyAction::None,
    };

    let registry = CommandRegistry::default();

    match registry.find(name) {
        Some(command) => {
            // Special handling for console output
            match name.to_lowercase().as_str() {
                "help" | "h" | "?" => {
                    let show_keys = args.first().map(|a| *a == "keys" || *a == "k").unwrap_or(false);
                    if show_keys {
                        app.console_print(KEYBOARD_HELP);
                    } else {
                        app.console_print(&registry.help_text());
                        app.console_println("");
                        app.console_println("Tip: help keys - show keyboard shortcuts");
                    }
                    MultiKeyAction::None
                }
                "status" | "s" => {
                    if let Some(conv) = app.active_conversation() {
                        app.console_println(&format!(
                            "Session: {} | Sent: {} | Received: {}",
                            conv.contact_name, conv.messages_sent, conv.messages_received
                        ));
                    } else {
                        app.console_println("No active conversation");
                    }
                    MultiKeyAction::None
                }
                "myonion" | "me" => {
                    match &app.my_onion {
                        Some(onion) => app.console_println(&format!("Your .onion: {}", onion)),
                        None => app.console_println("No .onion address available"),
                    };
                    MultiKeyAction::None
                }
                "who" => {
                    let msg = if let Some(name) = args.first() {
                        if let Some(contact) = app.contacts.iter().find(|c| c.name.eq_ignore_ascii_case(name)) {
                            if let Some(ref onion) = contact.onion_address {
                                format!("{}'s .onion: {}", contact.name, onion)
                            } else {
                                format!("{} has no .onion address stored", contact.name)
                            }
                        } else {
                            format!("Contact '{}' not found", name)
                        }
                    } else {
                        "Usage: who <contact_name>".to_string()
                    };
                    app.console_println(&msg);
                    MultiKeyAction::None
                }
                "debug" | "d" => {
                    let my_onion = app.my_onion.as_deref().unwrap_or("not set");
                    app.console_println(&format!("My .onion: {}", my_onion));
                    app.console_println(&format!("Contacts: {}", app.contacts.len()));
                    app.console_println(&format!("Pending requests: {}", app.pending_request_count()));
                    app.console_println(&format!("Notifications: {}", app.unseen_notification_count()));
                    app.console_println(&format!("Active conversations: {}", app.conversations.len()));
                    app.console_println(&format!("Tor status: {:?}", app.tor_status));
                    MultiKeyAction::None
                }
                "clear" => {
                    app.console_clear();
                    MultiKeyAction::None
                }
                "requests" | "r" => {
                    let known = app.pending_request_count_by_type(true);
                    let unknown = app.pending_request_count_by_type(false);
                    app.console_println(&format!("Pending: {} known, {} unknown", known, unknown));
                    MultiKeyAction::None
                }
                "notifications" | "n" => {
                    let unseen = app.unseen_notification_count();
                    app.console_println(&format!("{} unseen notifications", unseen));
                    MultiKeyAction::None
                }
                _ => {
                    // Execute normally for other commands
                    command.execute(app, args)
                }
            }
        }
        None => {
            app.console_println(&format!("Unknown command: {}. Try 'help'", name));
            MultiKeyAction::None
        }
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_command_registry_find_by_name() {
        let registry = CommandRegistry::new();

        assert!(registry.find("quit").is_some());
        assert!(registry.find("help").is_some());
        assert!(registry.find("myonion").is_some());
        assert!(registry.find("nonexistent").is_none());
    }

    #[test]
    fn test_command_registry_find_by_alias() {
        let registry = CommandRegistry::new();

        // "q" is alias for "quit"
        assert!(registry.find("q").is_some());
        assert_eq!(registry.find("q").unwrap().name(), "quit");

        // "me" is alias for "myonion"
        assert!(registry.find("me").is_some());
        assert_eq!(registry.find("me").unwrap().name(), "myonion");

        // "?" is alias for "help"
        assert!(registry.find("?").is_some());
        assert_eq!(registry.find("?").unwrap().name(), "help");
    }

    #[test]
    fn test_command_registry_case_insensitive() {
        let registry = CommandRegistry::new();

        assert!(registry.find("QUIT").is_some());
        assert!(registry.find("Quit").is_some());
        assert!(registry.find("HELP").is_some());
    }

    #[test]
    fn test_help_text_contains_all_commands() {
        let registry = CommandRegistry::new();
        let help = registry.help_text();

        // Check command names are present
        assert!(help.contains("/quit"));
        assert!(help.contains("/help"));
        assert!(help.contains("/myonion"));
        assert!(help.contains("/who"));

        // Check descriptions are present
        assert!(help.contains("Quit the application"));
        assert!(help.contains("Show available commands"));
    }

    #[test]
    fn test_quit_command_sets_should_quit() {
        let mut app = MultiApp::new();
        let cmd = QuitCommand;

        assert!(!app.should_quit);
        let action = cmd.execute(&mut app, &[]);
        assert!(app.should_quit);
        assert_eq!(action, MultiKeyAction::Quit);
    }

    #[test]
    fn test_execute_command_unknown() {
        let mut app = MultiApp::new();
        // Create a conversation so the error message can be added
        app.open_conversation("test");

        let action = execute_command(&mut app, "/unknowncommand");
        assert_eq!(action, MultiKeyAction::None);

        // Check error message was added
        let conv = app.active_conversation().unwrap();
        assert!(conv
            .messages
            .iter()
            .any(|m| m.content.contains("Unknown command")));
    }
}
