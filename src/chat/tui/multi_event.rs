//! Event handling for multi-contact TUI.

use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

use super::multi_app::{Dialog, DialogKind, FocusedPanel, MultiApp};

/// Actions that can result from key events.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MultiKeyAction {
    /// No action needed.
    None,
    /// Quit the application.
    Quit,
    /// Send the current message.
    SendMessage,
    /// Open conversation with selected contact (show dialog first).
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
    /// Notification viewed and dismissed.
    NotificationDismissed {
        notification_id: u64,
    },
    /// Dialog confirmed: initiate chat with passphrase.
    DialogInitiateChat {
        contact_name: String,
        onion_address: String,
        passphrase: String,
    },
    /// Dialog confirmed: accept incoming chat with passphrase.
    DialogAcceptChat {
        request_id: u64,
        onion_address: String,
        passphrase: String,
    },
    /// Dialog: user chose to accept (needs passphrase next).
    DialogAcceptRequest {
        request_id: u64,
        source_name: String,
        onion_address: String,
    },
    /// Dialog: user rejected incoming request.
    DialogRejectRequest {
        request_id: u64,
        onion_address: String,
    },
    /// Dialog closed/cancelled.
    DialogCancelled,
    /// Dialog confirmed: add a new contact.
    DialogAddContact {
        name: String,
        onion_address: String,
        public_key: String,
        signing_key: String,
    },
    /// Dialog confirmed: start quick ephemeral chat.
    DialogQuickEphemeral {
        onion_address: String,
    },
}

/// Handle a key event for multi-contact TUI.
pub fn handle_multi_key_event(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    // If a dialog is active, handle it first
    if app.has_dialog() {
        return handle_dialog_key_event(app, key);
    }

    // If console is open, handle it
    if app.console_open {
        return handle_console_key_event(app, key);
    }

    // Global shortcuts (work in any panel)
    match (key.modifiers, key.code) {
        // Ctrl+Q: Quit
        (KeyModifiers::CONTROL, KeyCode::Char('q')) => {
            app.should_quit = true;
            return MultiKeyAction::Quit;
        }
        // Ctrl+/ or Ctrl+_ or Ctrl+P: Toggle console
        // Note: Ctrl+/ sends different codes on different terminals
        (KeyModifiers::CONTROL, KeyCode::Char('/'))
        | (KeyModifiers::CONTROL, KeyCode::Char('_'))
        | (KeyModifiers::CONTROL, KeyCode::Char('p')) => {
            app.toggle_console();
            return MultiKeyAction::None;
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
        // Slash opens console
        KeyCode::Char('/') => {
            app.open_console();
            MultiKeyAction::None
        }
        // Navigation
        KeyCode::Up | KeyCode::Char('k') => {
            app.select_up();
            MultiKeyAction::None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            app.select_down();
            MultiKeyAction::None
        }
        // Open conversation, accept request, or activate button
        KeyCode::Enter | KeyCode::Right | KeyCode::Char('l') => {
            // Check if a sidebar button is selected
            if let Some(button_idx) = app.selected_sidebar_button {
                return match button_idx {
                    0 => MultiKeyAction::AddContact,
                    1 => MultiKeyAction::QuickEphemeral,
                    _ => MultiKeyAction::None,
                };
            }

            // Otherwise, handle contact selection
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
        // View requests from KNOWN contacts (👤)
        KeyCode::Char('r') => {
            if let Some(request) = app.pending_requests.iter().find(|r| r.is_known) {
                let source_name = request.contact_name.clone().unwrap_or_else(|| {
                    format!("~{}", &request.onion_address[..8.min(request.onion_address.len())])
                });
                app.active_dialog = Some(super::multi_app::Dialog::incoming_request(
                    request.id,
                    &source_name,
                    &request.onion_address,
                    true, // is_known
                ));
            } else {
                app.set_status_message("No requests from known contacts");
            }
            MultiKeyAction::ViewRequests
        }
        // View requests from UNKNOWN contacts (👻)
        KeyCode::Char('z') => {
            if let Some(request) = app.pending_requests.iter().find(|r| !r.is_known) {
                let source_name = if request.onion_address.len() > 16 {
                    format!("~{}...", &request.onion_address[..12])
                } else {
                    format!("~{}", &request.onion_address)
                };
                app.active_dialog = Some(super::multi_app::Dialog::incoming_request(
                    request.id,
                    &source_name,
                    &request.onion_address,
                    false, // is_known
                ));
            } else {
                app.set_status_message("No requests from unknown contacts");
            }
            MultiKeyAction::ViewRequests
        }
        // View/dismiss notifications
        KeyCode::Char('n') => {
            // Show first unseen notification in a dialog
            if let Some(notification) = app.first_unseen_notification() {
                app.active_dialog = Some(Dialog::view_notification(notification));
            } else {
                app.set_status_message("No unseen notifications");
            }
            MultiKeyAction::None
        }
        // Mark ALL notifications as seen (Shift+N)
        KeyCode::Char('N') => {
            app.mark_all_notifications_seen();
            MultiKeyAction::MarkNotificationsSeen
        }
        _ => MultiKeyAction::None,
    }
}

/// Handle key events in the tabs area.
fn handle_tabs_key(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    // Check modifier combinations first
    match (key.modifiers, key.code) {
        // Scroll messages with Ctrl+Up/Down
        (m, KeyCode::Up) if m.contains(KeyModifiers::CONTROL) => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_up(1);
            }
            MultiKeyAction::None
        }
        (m, KeyCode::Down) if m.contains(KeyModifiers::CONTROL) => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_down(1);
            }
            MultiKeyAction::None
        }
        // Slash opens console
        (_, KeyCode::Char('/')) => {
            app.open_console();
            MultiKeyAction::None
        }
        // Simple key matches
        (_, KeyCode::Left) | (_, KeyCode::Char('h')) => {
            app.prev_tab();
            MultiKeyAction::None
        }
        (_, KeyCode::Right) | (_, KeyCode::Char('l')) => {
            app.next_tab();
            MultiKeyAction::None
        }
        (_, KeyCode::Enter) | (_, KeyCode::Down) => {
            app.focused_panel = FocusedPanel::Input;
            MultiKeyAction::None
        }
        // Scroll messages
        (_, KeyCode::PageUp) => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_up(5);
            }
            MultiKeyAction::None
        }
        (_, KeyCode::PageDown) => {
            if let Some(conv) = app.active_conversation_mut() {
                conv.scroll_down(5);
            }
            MultiKeyAction::None
        }
        _ => MultiKeyAction::None,
    }
}

/// Handle key events when a dialog is active.
fn handle_dialog_key_event(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    let Some(dialog) = &mut app.active_dialog else {
        return MultiKeyAction::None;
    };

    match key.code {
        // Escape: Cancel dialog
        KeyCode::Esc => {
            app.close_dialog();
            MultiKeyAction::DialogCancelled
        }

        // Tab: Switch between fields or buttons
        KeyCode::Tab => {
            if dialog.has_fields() {
                // Move to next field, or wrap to first button
                if dialog.focused_field < dialog.fields.len() - 1 {
                    dialog.next_field();
                } else {
                    // Focus on OK button
                    dialog.focused_field = dialog.fields.len(); // Mark as "past fields"
                }
            } else if dialog.needs_password() {
                dialog.toggle_button();
            } else {
                dialog.toggle_button();
            }
            MultiKeyAction::None
        }

        KeyCode::BackTab => {
            if dialog.has_fields() {
                dialog.prev_field();
            } else {
                dialog.toggle_button();
            }
            MultiKeyAction::None
        }

        // Up/Down for field navigation in multi-field dialogs
        KeyCode::Up => {
            if dialog.has_fields() {
                dialog.prev_field();
            }
            MultiKeyAction::None
        }

        KeyCode::Down => {
            if dialog.has_fields() {
                dialog.next_field();
            }
            MultiKeyAction::None
        }

        // Enter: Confirm action
        KeyCode::Enter => {
            let dialog = app.active_dialog.take().unwrap();

            // Check if cancel button is focused
            if dialog.focused_button == 1 {
                return match &dialog.kind {
                    DialogKind::IncomingRequest { request_id, onion_address, .. } => {
                        MultiKeyAction::DialogRejectRequest {
                            request_id: *request_id,
                            onion_address: onion_address.clone(),
                        }
                    }
                    _ => MultiKeyAction::DialogCancelled,
                };
            }

            // OK button is focused
            match dialog.kind {
                DialogKind::InitiateChat { contact_name, onion_address } => {
                    if dialog.password_input.is_empty() {
                        // Re-show dialog with error
                        app.show_error_dialog("Error", "Passphrase cannot be empty");
                        return MultiKeyAction::None;
                    }
                    MultiKeyAction::DialogInitiateChat {
                        contact_name,
                        onion_address,
                        passphrase: dialog.password_input,
                    }
                }
                DialogKind::IncomingRequest { request_id, source_name, onion_address, .. } => {
                    // User accepted - now show passphrase dialog
                    MultiKeyAction::DialogAcceptRequest {
                        request_id,
                        source_name,
                        onion_address,
                    }
                }
                DialogKind::AcceptChat { request_id, onion_address, .. } => {
                    if dialog.password_input.is_empty() {
                        app.show_error_dialog("Error", "Passphrase cannot be empty");
                        return MultiKeyAction::None;
                    }
                    MultiKeyAction::DialogAcceptChat {
                        request_id,
                        onion_address,
                        passphrase: dialog.password_input,
                    }
                }
                DialogKind::Error { .. } => {
                    // Just close error dialogs
                    MultiKeyAction::None
                }
                DialogKind::ViewNotification { notification_id, .. } => {
                    // Mark as seen and dismiss
                    app.mark_notification_seen(notification_id);
                    MultiKeyAction::NotificationDismissed { notification_id }
                }
                DialogKind::AddContact => {
                    // Validate fields
                    if !dialog.validate_fields() {
                        app.show_error_dialog("Error", "All fields are required");
                        return MultiKeyAction::None;
                    }
                    MultiKeyAction::DialogAddContact {
                        name: dialog.field_value(0).unwrap_or_default().to_string(),
                        onion_address: dialog.field_value(1).unwrap_or_default().to_string(),
                        public_key: dialog.field_value(2).unwrap_or_default().to_string(),
                        signing_key: dialog.field_value(3).unwrap_or_default().to_string(),
                    }
                }
                DialogKind::QuickEphemeral => {
                    // Validate field
                    if !dialog.validate_fields() {
                        app.show_error_dialog("Error", "Onion address is required");
                        return MultiKeyAction::None;
                    }
                    MultiKeyAction::DialogQuickEphemeral {
                        onion_address: dialog.field_value(0).unwrap_or_default().to_string(),
                    }
                }
            }
        }

        // Character input for password or multi-field dialogs
        KeyCode::Char(c) => {
            if let Some(dialog) = &mut app.active_dialog {
                if dialog.has_fields() || dialog.needs_password() {
                    dialog.type_char(c);
                }
            }
            MultiKeyAction::None
        }

        // Backspace for password or multi-field dialogs
        KeyCode::Backspace => {
            if let Some(dialog) = &mut app.active_dialog {
                if dialog.has_fields() || dialog.needs_password() {
                    dialog.delete_char();
                }
            }
            MultiKeyAction::None
        }

        // Left/Right arrows for button navigation (when no active input)
        KeyCode::Left | KeyCode::Right => {
            if let Some(dialog) = &mut app.active_dialog {
                if !dialog.needs_password() && !dialog.has_fields() {
                    dialog.toggle_button();
                }
            }
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

/// Handle key events when the console is open.
fn handle_console_key_event(app: &mut MultiApp, key: KeyEvent) -> MultiKeyAction {
    match key.code {
        // Escape: Close console
        KeyCode::Esc => {
            app.close_console();
            MultiKeyAction::None
        }
        // Enter: Execute command
        KeyCode::Enter => {
            if app.console_input.is_empty() {
                return MultiKeyAction::None;
            }
            let input = app.take_console_input();
            // Show the command in output
            app.console_println(&format!("/{}", input));
            // Execute as command (add / prefix if not present)
            let cmd = if input.starts_with('/') {
                input
            } else {
                format!("/{}", input)
            };
            super::multi_commands::execute_console_command(app, &cmd)
        }
        // Character input
        KeyCode::Char(c) => {
            app.console_type_char(c);
            MultiKeyAction::None
        }
        // Backspace
        KeyCode::Backspace => {
            app.console_delete_char();
            MultiKeyAction::None
        }
        // Cursor movement
        KeyCode::Left => {
            app.console_cursor_left();
            MultiKeyAction::None
        }
        KeyCode::Right => {
            app.console_cursor_right();
            MultiKeyAction::None
        }
        // History navigation
        KeyCode::Up => {
            app.console_history_prev();
            MultiKeyAction::None
        }
        KeyCode::Down => {
            app.console_history_next();
            MultiKeyAction::None
        }
        // Scroll output
        KeyCode::PageUp => {
            app.console_scroll_up(5);
            MultiKeyAction::None
        }
        KeyCode::PageDown => {
            app.console_scroll_down(5);
            MultiKeyAction::None
        }
        _ => MultiKeyAction::None,
    }
}

/// Handle chat commands (starting with /).
/// Delegates to the command registry using Strategy pattern.
pub fn handle_multi_command(app: &mut MultiApp, input: &str) -> MultiKeyAction {
    super::multi_commands::execute_command(app, input)
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

    #[test]
    fn test_dialog_blocks_normal_keys() {
        use crate::chat::tui::multi_app::Dialog;
        let mut app = MultiApp::new();
        app.add_contact(Contact::new("alice"));
        app.focused_panel = FocusedPanel::Sidebar;

        // Show a dialog
        app.show_dialog(Dialog::initiate_chat("alice", "abc.onion"));

        // Down key should not change selection when dialog is active
        let key = KeyEvent::new(KeyCode::Down, KeyModifiers::NONE);
        let action = handle_multi_key_event(&mut app, key);

        // Should not navigate (dialog captures the key)
        assert_eq!(app.selected_contact, 0);
        assert_eq!(action, MultiKeyAction::None);
    }

    #[test]
    fn test_dialog_escape_cancels() {
        use crate::chat::tui::multi_app::Dialog;
        let mut app = MultiApp::new();

        // Show a dialog
        app.show_dialog(Dialog::initiate_chat("alice", "abc.onion"));
        assert!(app.has_dialog());

        // Escape should cancel
        let key = KeyEvent::new(KeyCode::Esc, KeyModifiers::NONE);
        let action = handle_multi_key_event(&mut app, key);

        assert_eq!(action, MultiKeyAction::DialogCancelled);
        assert!(!app.has_dialog());
    }

    #[test]
    fn test_dialog_password_input() {
        use crate::chat::tui::multi_app::Dialog;
        let mut app = MultiApp::new();

        // Show a dialog that needs password
        app.show_dialog(Dialog::initiate_chat("alice", "abc.onion"));

        // Type some characters
        let key = KeyEvent::new(KeyCode::Char('p'), KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        let key = KeyEvent::new(KeyCode::Char('a'), KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        let key = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);
        let key = KeyEvent::new(KeyCode::Char('s'), KeyModifiers::NONE);
        handle_multi_key_event(&mut app, key);

        // Check password was captured
        let dialog = app.active_dialog.as_ref().unwrap();
        assert_eq!(dialog.password_input, "pass");
    }

    #[test]
    fn test_dialog_confirm_with_passphrase() {
        use crate::chat::tui::multi_app::Dialog;
        let mut app = MultiApp::new();

        // Show a dialog
        let mut dialog = Dialog::initiate_chat("alice", "abc123.onion");
        dialog.password_input = "secret".to_string();
        app.show_dialog(dialog);

        // Press Enter to confirm
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let action = handle_multi_key_event(&mut app, key);

        assert!(matches!(action, MultiKeyAction::DialogInitiateChat { .. }));
        if let MultiKeyAction::DialogInitiateChat { contact_name, onion_address, passphrase } = action {
            assert_eq!(contact_name, "alice");
            assert_eq!(onion_address, "abc123.onion");
            assert_eq!(passphrase, "secret");
        }
    }

    #[test]
    fn test_dialog_cancel_button() {
        use crate::chat::tui::multi_app::Dialog;
        let mut app = MultiApp::new();

        // Show a dialog
        let mut dialog = Dialog::initiate_chat("alice", "abc.onion");
        dialog.password_input = "secret".to_string();
        dialog.focused_button = 1; // Cancel button
        app.show_dialog(dialog);

        // Press Enter on Cancel button
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let action = handle_multi_key_event(&mut app, key);

        assert_eq!(action, MultiKeyAction::DialogCancelled);
    }

    #[test]
    fn test_dialog_empty_passphrase_rejected() {
        use crate::chat::tui::multi_app::Dialog;
        let mut app = MultiApp::new();

        // Show a dialog with empty passphrase
        app.show_dialog(Dialog::initiate_chat("alice", "abc.onion"));

        // Press Enter with empty passphrase
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let action = handle_multi_key_event(&mut app, key);

        // Should not return initiate action, should show error dialog instead
        assert_eq!(action, MultiKeyAction::None);
        // Error dialog should be shown
        assert!(app.has_dialog());
    }

    #[test]
    fn test_incoming_request_accept_shows_passphrase_dialog() {
        use crate::chat::tui::multi_app::Dialog;
        let mut app = MultiApp::new();

        // Show incoming request dialog
        app.show_dialog(Dialog::incoming_request(1, "bob", "xyz.onion", false));

        // Press Enter to accept (focused_button == 0)
        let key = KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE);
        let action = handle_multi_key_event(&mut app, key);

        // Should return DialogAcceptRequest (which will show passphrase dialog)
        assert!(matches!(action, MultiKeyAction::DialogAcceptRequest { .. }));
    }
}
