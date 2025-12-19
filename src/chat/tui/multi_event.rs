//! Event handling for multi-contact TUI.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::multi_app::{FocusedPanel, MultiApp};

/// Actions that can result from key events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiKeyAction {
    /// No action needed.
    None,
    /// Quit the application.
    Quit,
    /// Send the current message.
    SendMessage,
    /// Open conversation with selected contact.
    OpenConversation,
    /// Close the active tab.
    CloseTab,
    /// Add new contact (show dialog).
    AddContact,
    /// Quick ephemeral contact (show dialog).
    QuickEphemeral,
    /// Accept a pending chat request (id).
    AcceptRequest(u64),
    /// Reject a pending chat request (id).
    RejectRequest(u64),
    /// View pending requests.
    ViewRequests,
    /// Mark all notifications as seen.
    MarkNotificationsSeen,
}

/// Handle a key event for multi-contact TUI.
pub fn handle_multi_key_event(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    // Global shortcuts (work in any panel)
    match (key.modifiers, key.code) {
        // Ctrl+Q or Ctrl+C: Quit
        (KeyModifiers::CONTROL, KeyCode::Char('q'))
        | (KeyModifiers::CONTROL, KeyCode::Char('c')) => {
            app.should_quit = true;
            return MultiKeyAction::Quit;
        }
        // Escape: Quit or back to sidebar
        (_, KeyCode::Esc) => {
            if app.focused_panel == FocusedPanel::Input {
                app.focused_panel = FocusedPanel::Sidebar;
                return MultiKeyAction::None;
            } else {
                app.should_quit = true;
                return MultiKeyAction::Quit;
            }
        }
        // Tab: Cycle focus between panels
        (KeyModifiers::NONE, KeyCode::Tab) => {
            app.cycle_focus();
            return MultiKeyAction::None;
        }
        // Shift+Tab: Cycle focus backwards
        (KeyModifiers::SHIFT, KeyCode::BackTab) => {
            // Reverse cycle
            app.focused_panel = match app.focused_panel {
                FocusedPanel::Sidebar => FocusedPanel::Input,
                FocusedPanel::Tabs => FocusedPanel::Sidebar,
                FocusedPanel::Input => FocusedPanel::Sidebar,
            };
            return MultiKeyAction::None;
        }
        // Ctrl+W: Close tab
        (KeyModifiers::CONTROL, KeyCode::Char('w')) => {
            app.close_active_tab();
            return MultiKeyAction::CloseTab;
        }
        // Left/Right arrows for tab switching (when not in input)
        (KeyModifiers::CONTROL, KeyCode::Left) | (KeyModifiers::ALT, KeyCode::Left) => {
            app.prev_tab();
            return MultiKeyAction::None;
        }
        (KeyModifiers::CONTROL, KeyCode::Right) | (KeyModifiers::ALT, KeyCode::Right) => {
            app.next_tab();
            return MultiKeyAction::None;
        }
        // Number keys 1-9 for tab switching
        (KeyModifiers::ALT, KeyCode::Char(c)) if c.is_ascii_digit() && c != '0' => {
            let idx = c.to_digit(10).unwrap_or(1) as usize - 1;
            if idx < app.tabs.len() {
                app.active_tab = idx;
            }
            return MultiKeyAction::None;
        }
        _ => {}
    }

    // Panel-specific handling
    match app.focused_panel {
        FocusedPanel::Sidebar => handle_sidebar_key(app, key),
        FocusedPanel::Tabs => handle_tabs_key(app, key),
        FocusedPanel::Input => handle_input_key(app, key),
    }
}

/// Handle key events in the sidebar.
fn handle_sidebar_key(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    match key.code {
        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_up();
            MultiKeyAction::None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_down();
            MultiKeyAction::None
        }
        // Open conversation or accept request
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            if let Some(contact) = app.selected_contact().cloned() {
                // Check if this contact has a pending incoming request
                if contact.status == super::multi_app::ContactStatus::IncomingRequest {
                    // Find the request for this contact
                    if let Some(onion) = &contact.onion_address {
                        if let Some(request) = app.pending_requests.iter().find(|r| &r.onion_address == onion) {
                            return MultiKeyAction::AcceptRequest(request.id);
                        }
                    }
                }
                app.open_conversation(&contact.name);
                MultiKeyAction::OpenConversation
            } else {
                MultiKeyAction::None
            }
        }
        // Reject request (x or Delete)
        KeyCode::Char('x') | KeyCode::Delete => {
            if let Some(contact) = app.selected_contact().cloned() {
                if contact.status == super::multi_app::ContactStatus::IncomingRequest {
                    if let Some(onion) = &contact.onion_address {
                        if let Some(request) = app.pending_requests.iter().find(|r| &r.onion_address == onion) {
                            return MultiKeyAction::RejectRequest(request.id);
                        }
                    }
                }
            }
            MultiKeyAction::None
        }
        // Add contact
        KeyCode::Char('+') => MultiKeyAction::AddContact,
        // Quick ephemeral
        KeyCode::Char('e') => MultiKeyAction::QuickEphemeral,
        // View requests
        KeyCode::Char('r') => MultiKeyAction::ViewRequests,
        // Mark notifications as seen
        KeyCode::Char('n') => {
            app.mark_all_notifications_seen();
            MultiKeyAction::MarkNotificationsSeen
        }
        _ => MultiKeyAction::None,
    }
}

/// Handle key events in the tabs area.
fn handle_tabs_key(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    match key.code {
        KeyCode::Left | KeyCode::Char('h') => {
            app.prev_tab();
            MultiKeyAction::None
        }
        KeyCode::Right | KeyCode::Char('l') => {
            app.next_tab();
            MultiKeyAction::None
        }
        KeyCode::Enter | KeyCode::Down => {
            app.focused_panel = FocusedPanel::Input;
            MultiKeyAction::None
        }
        _ => MultiKeyAction::None,
    }
}

/// Handle key events in the input area.
fn handle_input_key(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    match key.code {
        // Send message
        KeyCode::Enter => {
            if !app.input.is_empty() {
                MultiKeyAction::SendMessage
            } else {
                MultiKeyAction::None
            }
        }
        // Character input
        KeyCode::Char(c) => {
            app.enter_char(c);
            MultiKeyAction::None
        }
        // Backspace
        KeyCode::Backspace => {
            app.delete_char();
            MultiKeyAction::None
        }
        // Cursor movement
        KeyCode::Left => {
            app.move_cursor_left();
            MultiKeyAction::None
        }
        KeyCode::Right => {
            app.move_cursor_right();
            MultiKeyAction::None
        }
        KeyCode::Home => {
            app.move_cursor_home();
            MultiKeyAction::None
        }
        KeyCode::End => {
            app.move_cursor_end();
            MultiKeyAction::None
        }
        // Scroll messages
        KeyCode::PageUp => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_up(5);
            }
            MultiKeyAction::None
        }
        KeyCode::PageDown => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_down(5);
            }
            MultiKeyAction::None
        }
        KeyCode::Up if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_up(1);
            }
            MultiKeyAction::None
        }
        KeyCode::Down if key.modifiers.contains(KeyModifiers::CONTROL) => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_down(1);
            }
            MultiKeyAction::None
        }
        _ => MultiKeyAction::None,
    }
}

/// Handle chat commands (starting with /).
pub fn handle_multi_command(app: &mut MultiApp, input: &str) -> MultiKeyAction {
    let cmd = input.trim_start_matches('/').to_lowercase();
    let parts: Vec<&str> = cmd.split_whitespace().collect();

    match parts.first().map(|s| *s) {
        Some("quit") | Some("q") | Some("exit") => {
            app.should_quit = true;
            MultiKeyAction::Quit
        }
        Some("close") | Some("c") => {
            app.close_active_tab();
            MultiKeyAction::CloseTab
        }
        Some("status") | Some("s") => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.add_system_message(format!(
                    "Session: {} | Sent: {} | Received: {}",
                    conv.contact_name, conv.messages_sent, conv.messages_received
                ));
            }
            MultiKeyAction::None
        }
        Some("clear") => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.messages.clear();
                conv.scroll_offset = 0;
            }
            MultiKeyAction::None
        }
        Some("requests") | Some("r") => {
            // Show pending requests in the active conversation or create a system message
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
        Some("notifications") | Some("n") => {
            let unseen = app.unseen_notification_count();
            let msg = format!("{} unseen notifications. Press 'n' in sidebar to clear.", unseen);
            if let Some(conv) = app.active_conversation_mut() {
                conv.add_system_message(&msg);
            } else {
                app.set_status_message(&msg);
            }
            MultiKeyAction::None
        }
        Some("help") | Some("h") => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.add_system_message("Commands: /quit /close /status /clear /requests /notifications /help");
            }
            MultiKeyAction::None
        }
        _ => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.add_system_message(format!("Unknown command: {}", input));
            }
            MultiKeyAction::None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chat::tui::multi_app::Contact;

    #[test]
    fn test_sidebar_navigation() {
        let mut app = MultiApp::new();
        app.add_contact(Contact::new("alice"));
        app.add_contact(Contact::new("bob"));
        app.focused_panel = FocusedPanel::Sidebar;

        let key = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        assert_eq!(app.selected_contact, 1);

        let key = KeyEvent::new(KeyCode::Up, KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        assert_eq!(app.selected_contact, 0);
    }

    #[test]
    fn test_open_conversation() {
        let mut app = MultiApp::new();
        app.add_contact(Contact::new("alice"));
        app.focused_panel = FocusedPanel::Sidebar;

        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let action = handle_multi_key_event(&mut app, key);

        assert_eq!(action, MultiKeyAction::OpenConversation);
        assert_eq!(app.tabs.len(), 1);
        assert_eq!(app.focused_panel, FocusedPanel::Input);
    }

    #[test]
    fn test_tab_cycling() {
        let mut app = MultiApp::new();
        app.focused_panel = FocusedPanel::Sidebar;

        let key = KeyEvent::new(KeyCode::Tab, KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        // No tabs, should stay on sidebar
        assert_eq!(app.focused_panel, FocusedPanel::Sidebar);

        // Add a conversation
        app.open_conversation("alice");
        app.focused_panel = FocusedPanel::Sidebar;

        handle_multi_key_event(&mut app, key);
        assert_eq!(app.focused_panel, FocusedPanel::Input);

        handle_multi_key_event(&mut app, key);
        assert_eq!(app.focused_panel, FocusedPanel::Sidebar);
    }

    #[test]
    fn test_input_handling() {
        let mut app = MultiApp::new();
        app.open_conversation("alice");
        app.focused_panel = FocusedPanel::Input;

        // Type some characters
        let key = KeyEvent::new(KeyCode::Char('H'), KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        let key = KeyEvent::new(KeyCode::Char('i'), KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);

        assert_eq!(app.input, "Hi");

        // Backspace
        let key = KeyEvent::new(KeyCode::Backspace, KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        assert_eq!(app.input, "H");
    }

    #[test]
    fn test_quit_shortcut() {
        let mut app = MultiApp::new();

        let key = KeyEvent::new(KeyCode::Char('q'), KeyModifiers::CONTROL);
        let action = handle_multi_key_event(&mut app, key);

        assert_eq!(action, MultiKeyAction::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn test_close_tab() {
        let mut app = MultiApp::new();
        app.open_conversation("alice");
        app.open_conversation("bob");

        assert_eq!(app.tabs.len(), 2);

        let key = KeyEvent::new(KeyCode::Char('w'), KeyModifiers::CONTROL);
        let action = handle_multi_key_event(&mut app, key);

        assert_eq!(action, MultiKeyAction::CloseTab);
        assert_eq!(app.tabs.len(), 1);
    }
}
