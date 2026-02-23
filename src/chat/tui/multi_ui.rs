//! Multi-contact UI rendering for the TUI.
//!
//! Layout:
//! ```text
//! ┌─────────────────────────────────────────────┐
//! │ ⠿ anyhide                          v0.13.0  │
//! ├───────────┬─────────────────────────────────┤
//! │ Contacts  │ ┌───────┐───────────────────────│
//! │───────────│ │ alice │  bob    ~eph         ││
//! │ ● alice ▲ │ ├───────┴───────────────────────┤
//! │ ○ bob   █ │ │ Messages                      │
//! │ ◌ ~eph  ░ │ │                               │
//! │───────────│ ├───────────────────────────────┤
//! │ + Add     │ │ Input                  128/256│
//! │ ⚡ Quick  │ └───────────────────────────────┘
//! ├───────────┴─────────────────────────────────┤
//! │ 🔒 Tor ● | abc...xyz.onion | Tab: switch    │
//! └─────────────────────────────────────────────┘
//! ```

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    symbols::border,
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Scrollbar, ScrollbarOrientation, ScrollbarState, Tabs, Wrap},
    Frame,
};

use super::multi_app::{ConnectionStatus, Contact, ContactStatus, Dialog, DialogKind, FocusedPanel, MultiApp};

/// App version for title bar.
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Braille character for app icon (6 dots = all points filled).
const APP_ICON: &str = "⠿";

/// Main color theme for the app.
const THEME_COLOR: Color = Color::Cyan;

/// Main render function for multi-contact TUI.
pub fn render_multi(frame: &mut Frame, app: &mut MultiApp) {
    // Clear expired status messages
    app.clear_expired_status();

    // Outer frame with border around entire app
    let outer_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(THEME_COLOR))
        .border_set(border::ROUNDED);

    let inner_area = outer_block.inner(frame.area());
    frame.render_widget(outer_block, frame.area());

    // Level 1: Title bar (with separator) + main area + status bar
    let [title_area, main_area, status_area] = Layout::vertical([
        Constraint::Length(2),  // Title bar + separator line
        Constraint::Min(10),    // Main (sidebar + chat)
        Constraint::Length(1),  // Status bar
    ])
    .areas(inner_area);

    // Level 2: Sidebar + chat area
    let [sidebar_area, chat_area] = Layout::horizontal([
        Constraint::Length(16), // Sidebar (fixed width)
        Constraint::Min(40),    // Chat (flexible)
    ])
    .areas(main_area);

    render_title_bar(frame, title_area);
    render_sidebar(frame, app, sidebar_area);
    render_chat_area(frame, app, chat_area);
    render_status_bar(frame, app, status_area);

    // Render console overlay from top (Doom-style)
    if app.console_open {
        render_console_overlay(frame, app, inner_area);
    }

    // Render dialog on top of everything
    if let Some(dialog) = &app.active_dialog {
        render_dialog(frame, dialog, frame.area());
    }
}

/// Render the title bar with app branding and separator line.
fn render_title_bar(frame: &mut Frame, area: Rect) {
    // Split into title row and separator row
    if area.height < 2 {
        return;
    }

    let title_row = Rect::new(area.x, area.y, area.width, 1);
    let separator_row = Rect::new(area.x, area.y + 1, area.width, 1);

    // Title line
    let title = Line::from(vec![
        Span::styled(
            format!(" {} ", APP_ICON),
            Style::default().fg(THEME_COLOR).add_modifier(Modifier::BOLD),
        ),
        Span::styled(
            "anyhide",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        ),
    ]);

    let version = Span::styled(
        format!("v{} ", APP_VERSION),
        Style::default().fg(Color::DarkGray),
    );

    // Create a paragraph with left title and right version
    let title_bar = Paragraph::new(title);
    frame.render_widget(title_bar, title_row);

    // Render version on the right
    let version_width = APP_VERSION.len() + 2; // "v" + version + " "
    if title_row.width > version_width as u16 {
        let version_area = Rect::new(
            title_row.x + title_row.width - version_width as u16,
            title_row.y,
            version_width as u16,
            1,
        );
        let version_paragraph = Paragraph::new(version);
        frame.render_widget(version_paragraph, version_area);
    }

    // Separator line with small margins on each side
    // Format: "  ────────────────────────  "
    let sep_width = separator_row.width as usize;
    if sep_width > 4 {
        let margin = 1; // 1 space on each side
        let line_width = sep_width - (margin * 2);
        let separator = format!(
            "{}{}{}",
            " ".repeat(margin),
            "─".repeat(line_width),
            " ".repeat(margin)
        );
        let sep_line = Paragraph::new(Span::styled(separator, Style::default().fg(Color::DarkGray)));
        frame.render_widget(sep_line, separator_row);
    }
}

/// Render the contacts sidebar.
fn render_sidebar(frame: &mut Frame, app: &MultiApp, area: Rect) {
    // Sidebar: Contacts list + action buttons
    let [contacts_area, buttons_area] = Layout::vertical([
        Constraint::Min(5),     // Contacts list
        Constraint::Length(4),  // Buttons (2 lines + borders)
    ])
    .areas(area);

    render_contact_list(frame, app, contacts_area);
    render_sidebar_buttons(frame, app, buttons_area);
}

/// Render the contact list.
fn render_contact_list(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let is_focused = app.focused_panel == FocusedPanel::Sidebar;
    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Only highlight contact if focused and no button is selected
    let show_selection = is_focused && app.selected_sidebar_button.is_none();

    let items: Vec<ListItem> = app
        .contacts
        .iter()
        .enumerate()
        .map(|(i, contact)| {
            let style = if i == app.selected_contact && show_selection {
                Style::default()
                    .bg(Color::DarkGray)
                    .add_modifier(Modifier::BOLD)
            } else {
                get_contact_style(contact)
            };
            ListItem::new(contact.display_name()).style(style)
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Contacts ")
                .border_style(border_style),
        )
        .highlight_style(Style::default().bg(Color::DarkGray));

    // Create list state for selection
    let mut state = ListState::default();
    if show_selection {
        state.select(Some(app.selected_contact));
    }

    frame.render_stateful_widget(list, area, &mut state);
}

/// Get style for a contact based on status.
fn get_contact_style(contact: &Contact) -> Style {
    match contact.status {
        ContactStatus::Online => Style::default().fg(Color::Green),
        ContactStatus::Offline => Style::default().fg(Color::DarkGray),
        ContactStatus::Ephemeral => Style::default().fg(Color::Yellow),
        ContactStatus::Connecting => Style::default().fg(Color::Blue),
        ContactStatus::IncomingRequest => Style::default().fg(Color::Magenta),
        ContactStatus::PendingAccept => Style::default().fg(Color::Cyan),
    }
}

/// Render sidebar action buttons.
fn render_sidebar_buttons(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let is_focused = app.focused_panel == FocusedPanel::Sidebar;
    let border_style = if is_focused {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Determine which button is selected (if any)
    let add_style = if is_focused && app.selected_sidebar_button == Some(0) {
        Style::default().fg(Color::Black).bg(Color::Green).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };

    let quick_style = if is_focused && app.selected_sidebar_button == Some(1) {
        Style::default().fg(Color::Black).bg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Yellow)
    };

    let buttons = Paragraph::new(vec![
        Line::from(Span::styled(" + Add", add_style)),
        Line::from(Span::styled(" ⚡ Quick", quick_style)),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(border_style),
    );

    frame.render_widget(buttons, area);
}

/// Render the chat area (tabs + messages + input).
fn render_chat_area(frame: &mut Frame, app: &MultiApp, area: Rect) {
    if app.tabs.is_empty() {
        // No active conversations
        render_empty_chat(frame, area);
        return;
    }

    // Chat area: Tabs + Messages + Input
    let [tabs_area, messages_area, input_area] = Layout::vertical([
        Constraint::Length(1),  // Tabs row
        Constraint::Min(5),     // Messages
        Constraint::Length(5),  // Input (3 lines + borders)
    ])
    .areas(area);

    render_tabs(frame, app, tabs_area);
    render_messages(frame, app, messages_area);
    render_input(frame, app, input_area);
}

/// Render empty chat placeholder.
fn render_empty_chat(frame: &mut Frame, area: Rect) {
    let placeholder = Paragraph::new(vec![
        Line::from(""),
        Line::from(""),
        Line::from(Span::styled(
            "Select a contact to start chatting",
            Style::default().fg(Color::DarkGray),
        )),
        Line::from(""),
        Line::from(Span::styled(
            "↑/↓ Navigate | Enter: Open | Tab: Switch panel",
            Style::default().fg(Color::DarkGray),
        )),
    ])
    .block(
        Block::default()
            .borders(Borders::ALL)
            .title(" Chat ")
            .border_style(Style::default().fg(Color::DarkGray)),
    )
    .alignment(ratatui::layout::Alignment::Center);

    frame.render_widget(placeholder, area);
}

/// Render conversation tabs using ratatui's Tabs widget.
fn render_tabs(frame: &mut Frame, app: &MultiApp, area: Rect) {
    // Build tab titles from contact names
    let titles: Vec<Line> = app
        .tabs
        .iter()
        .map(|name| {
            let contact = app.contacts.iter().find(|c| &c.name == name);
            if let Some(c) = contact {
                if c.unread > 0 {
                    Line::from(format!(" {} ({}) ", c.name, c.unread))
                } else {
                    Line::from(format!(" {} ", c.name))
                }
            } else {
                Line::from(format!(" {} ", name))
            }
        })
        .collect();

    let tabs = Tabs::new(titles)
        .select(app.active_tab)
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(THEME_COLOR)
                .add_modifier(Modifier::BOLD),
        )
        .divider(" ");

    frame.render_widget(tabs, area);
}

/// Render messages for the active conversation.
fn render_messages(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let conversation = match app.active_conversation() {
        Some(conv) => conv,
        None => return,
    };

    let inner_height = area.height.saturating_sub(2) as usize; // Top and bottom borders
    let inner_width = area.width.saturating_sub(3) as usize; // Left border + right border + scrollbar

    // Build wrapped lines
    let mut all_lines: Vec<Line> = Vec::new();

    for msg in &conversation.messages {
        let (prefix, style) = match &msg.author {
            super::multi_app::MessageAuthor::You => (
                format!("[{}] you: ", msg.formatted_time()),
                Style::default().fg(Color::Green),
            ),
            super::multi_app::MessageAuthor::Peer(name) => (
                format!("[{}] {}: ", msg.formatted_time(), name),
                Style::default().fg(Color::Blue),
            ),
            super::multi_app::MessageAuthor::System => (
                format!("[{}] ", msg.formatted_time()),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::ITALIC),
            ),
        };

        let prefix_len = prefix.chars().count();
        let content_width = inner_width.saturating_sub(prefix_len);

        if content_width == 0 || msg.content.is_empty() {
            let line = Line::from(vec![
                Span::styled(prefix, style),
                Span::raw(&msg.content),
            ]);
            all_lines.push(line);
        } else {
            let wrapped = wrap_text(&msg.content, content_width);
            for (i, part) in wrapped.into_iter().enumerate() {
                if i == 0 {
                    let line = Line::from(vec![
                        Span::styled(prefix.clone(), style),
                        Span::raw(part),
                    ]);
                    all_lines.push(line);
                } else {
                    let indent = " ".repeat(prefix_len);
                    let line = Line::from(vec![Span::raw(indent), Span::raw(part)]);
                    all_lines.push(line);
                }
            }
        }
    }

    // Calculate visible lines with scroll
    let total_lines = all_lines.len();
    let start_index = if total_lines > inner_height {
        total_lines
            .saturating_sub(inner_height)
            .saturating_sub(conversation.scroll_offset)
    } else {
        0
    };
    let end_index = start_index.saturating_add(inner_height).min(total_lines);

    let items: Vec<ListItem> = all_lines[start_index..end_index]
        .iter()
        .map(|line| ListItem::new(line.clone()))
        .collect();

    let messages_block = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(THEME_COLOR));

    let messages_list = List::new(items).block(messages_block);

    frame.render_widget(messages_list, area);

    // Render scrollbar if there's content to scroll
    if total_lines > inner_height {
        // Calculate scroll position (inverted because we scroll from bottom)
        let max_scroll = total_lines.saturating_sub(inner_height);
        let scroll_position = max_scroll.saturating_sub(conversation.scroll_offset);

        let mut scrollbar_state = ScrollbarState::new(max_scroll)
            .position(scroll_position);

        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(Some("▲"))
            .end_symbol(Some("▼"))
            .track_symbol(Some("│"))
            .thumb_symbol("█");

        // Render scrollbar in the inner area (inside the block border)
        let scrollbar_area = Rect::new(
            area.x + area.width - 2,  // Inside right border
            area.y + 1,                // Below top border
            1,
            area.height.saturating_sub(2),  // Exclude borders
        );

        frame.render_stateful_widget(scrollbar, scrollbar_area, &mut scrollbar_state);
    }
}

/// Wrap text for display.
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_width = 0;

    for word in text.split_inclusive(|c: char| c.is_whitespace()) {
        let word_len = word.chars().count();

        if current_width + word_len <= max_width {
            current_line.push_str(word);
            current_width += word_len;
        } else if word_len > max_width {
            if !current_line.is_empty() {
                lines.push(current_line);
                current_line = String::new();
                current_width = 0;
            }
            for ch in word.chars() {
                if current_width >= max_width {
                    lines.push(current_line);
                    current_line = String::new();
                    current_width = 0;
                }
                current_line.push(ch);
                current_width += 1;
            }
        } else {
            if !current_line.is_empty() {
                lines.push(current_line);
            }
            current_line = word.to_string();
            current_width = word_len;
        }
    }

    if !current_line.is_empty() {
        lines.push(current_line);
    }

    if lines.is_empty() {
        lines.push(String::new());
    }

    lines
}

/// Render the input box.
fn render_input(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let is_active = app.focused_panel == FocusedPanel::Input && !app.tabs.is_empty();

    let border_style = if is_active {
        if app.remaining_chars() == 0 {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(THEME_COLOR)
        }
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let display_text = if app.input.is_empty() {
        if is_active {
            "Type a message..."
        } else {
            ""
        }
    } else {
        &app.input
    };

    // Character counter
    let remaining = app.remaining_chars();
    let counter_style = if remaining == 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if remaining <= 20 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };
    let counter = format!(" {}/{} ", app.input.chars().count(), app.max_message_len);

    let input = Paragraph::new(display_text)
        .style(if app.input.is_empty() {
            Style::default().fg(Color::DarkGray)
        } else {
            Style::default().fg(Color::White)
        })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Input ")
                .title_bottom(Line::from(Span::styled(counter, counter_style)).right_aligned())
                .border_style(border_style),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(input, area);

    // Cursor position with wrap support
    if is_active {
        let inner_width = area.width.saturating_sub(2) as usize;
        let inner_height = area.height.saturating_sub(2) as usize;
        let cursor = app.cursor_position;

        if inner_width > 0 {
            // Calculate which line and column the cursor is on
            let cursor_line = cursor / inner_width;
            let cursor_col = cursor % inner_width;

            // Clamp to visible area
            let visible_line = cursor_line.min(inner_height.saturating_sub(1));

            let cursor_x = area.x + 1 + cursor_col as u16;
            let cursor_y = area.y + 1 + visible_line as u16;
            frame.set_cursor_position((cursor_x.min(area.x + area.width - 2), cursor_y.min(area.y + area.height - 2)));
        }
    }
}

/// Render the console overlay (Doom-style, from top).
fn render_console_overlay(frame: &mut Frame, app: &MultiApp, area: Rect) {
    use ratatui::widgets::Clear;

    // Console takes ~40% of the screen from the top
    let console_height = (area.height * 40 / 100).max(8);
    let console_area = Rect::new(area.x, area.y, area.width, console_height);

    // Clear the area first
    frame.render_widget(Clear, console_area);

    // Console block with border
    let block = Block::default()
        .title(Line::from(vec![
            Span::styled(" ", Style::default()),
            Span::styled(APP_ICON, Style::default().fg(THEME_COLOR)),
            Span::styled(" Console ", Style::default().fg(THEME_COLOR).add_modifier(Modifier::BOLD)),
            Span::styled("(Esc to close, PgUp/PgDn to scroll) ", Style::default().fg(Color::DarkGray)),
        ]))
        .borders(Borders::ALL)
        .border_style(Style::default().fg(THEME_COLOR))
        .border_set(border::ROUNDED)
        .style(Style::default().bg(Color::Black));

    let inner = block.inner(console_area);
    frame.render_widget(block, console_area);

    // Split inner into output area and input line
    let output_height = inner.height.saturating_sub(1);
    let output_area = Rect::new(inner.x, inner.y, inner.width, output_height);
    let input_area = Rect::new(inner.x, inner.y + output_height, inner.width, 1);

    // Render output (scrollable)
    let total_lines = app.console_output.len();
    let visible_lines = output_area.height as usize;
    let start_idx = if total_lines > visible_lines {
        total_lines.saturating_sub(visible_lines).saturating_sub(app.console_scroll)
    } else {
        0
    };
    let end_idx = start_idx.saturating_add(visible_lines).min(total_lines);

    let output_lines: Vec<Line> = app.console_output[start_idx..end_idx]
        .iter()
        .map(|s| Line::from(Span::styled(s.as_str(), Style::default().fg(Color::Gray))))
        .collect();

    let output = Paragraph::new(output_lines);
    frame.render_widget(output, output_area);

    // Render input line with prompt
    let prompt = Span::styled("/ ", Style::default().fg(THEME_COLOR).add_modifier(Modifier::BOLD));
    let input_text = Span::styled(&app.console_input, Style::default().fg(Color::White));
    let input_line = Line::from(vec![prompt, input_text]);
    let input = Paragraph::new(input_line);
    frame.render_widget(input, input_area);

    // Set cursor position
    let cursor_x = input_area.x + 2 + app.console_cursor as u16;
    frame.set_cursor_position((cursor_x.min(input_area.x + input_area.width - 1), input_area.y));
}

/// Render the status bar.
fn render_status_bar(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let mut spans = Vec::new();

    // Tor status
    let tor_icon = match app.tor_status {
        ConnectionStatus::Connected => Span::styled("🔒 Tor ● ", Style::default().fg(Color::Green)),
        ConnectionStatus::Disconnected => Span::styled("⚠ Tor ○ ", Style::default().fg(Color::Red)),
        _ => Span::styled("◐ Tor... ", Style::default().fg(Color::Yellow)),
    };
    spans.push(tor_icon);

    // Chat/Hidden service status
    use super::multi_app::ChatServiceStatus;
    let chat_icon = match app.chat_status {
        ChatServiceStatus::Ready => Span::styled("Chat ● ", Style::default().fg(Color::Green)),
        ChatServiceStatus::Starting => Span::styled("Chat ◐ ", Style::default().fg(Color::Yellow)),
        ChatServiceStatus::Error => Span::styled("Chat ○ ", Style::default().fg(Color::Red)),
    };
    spans.push(chat_icon);

    // .onion address
    if let Some(ref onion) = app.my_onion {
        spans.push(Span::raw("| "));
        spans.push(Span::styled(
            truncate_onion(onion),
            Style::default().fg(Color::Cyan),
        ));
        spans.push(Span::raw(" "));
    }

    // Pending requests indicator
    let pending = app.pending_request_count();
    if pending > 0 {
        let known = app.pending_request_count_by_type(true);
        let unknown = app.pending_request_count_by_type(false);
        spans.push(Span::raw("| "));
        if known > 0 {
            spans.push(Span::styled(
                format!("👤{} ", known),
                Style::default().fg(Color::Green),
            ));
        }
        if unknown > 0 {
            spans.push(Span::styled(
                format!("👻{} ", unknown),
                Style::default().fg(Color::Yellow),
            ));
        }
    }

    // Unseen notifications indicator
    let unseen = app.unseen_notification_count();
    if unseen > 0 {
        spans.push(Span::raw("| "));
        spans.push(Span::styled(
            format!("🔔{} ", unseen),
            Style::default().fg(Color::Magenta),
        ));
    }

    // Keyboard hints based on focused panel
    spans.push(Span::raw("| "));
    let hints = match app.focused_panel {
        FocusedPanel::Sidebar => "↑↓: nav | Enter: open | /: console",
        FocusedPanel::Tabs => "←→: tabs | PgUp/Dn: scroll | /: console",
        FocusedPanel::Input => "Enter: send | PgUp/Dn: scroll | Ctrl+P: console",
    };
    spans.push(Span::styled(hints, Style::default().fg(Color::DarkGray)));

    // Status message (errors/warnings)
    if let Some((ref msg, _)) = app.status_message {
        spans.push(Span::raw(" | "));
        spans.push(Span::styled(msg, Style::default().fg(Color::Yellow)));
    }

    let status_line = Paragraph::new(Line::from(spans));
    frame.render_widget(status_line, area);
}

/// Truncate .onion address.
fn truncate_onion(onion: &str) -> String {
    if onion.len() > 20 {
        format!("{}...{}", &onion[..8], &onion[onion.len() - 10..])
    } else {
        onion.to_string()
    }
}

/// Render a dialog/modal on top of the UI.
fn render_dialog(frame: &mut Frame, dialog: &Dialog, area: Rect) {
    use ratatui::widgets::Clear;

    // Calculate centered dialog box
    let dialog_width = 50u16.min(area.width.saturating_sub(4));
    let dialog_height = match &dialog.kind {
        DialogKind::InitiateChat { .. } | DialogKind::AcceptChat { .. } => 10,
        DialogKind::IncomingRequest { .. } => 9,
        DialogKind::Error { .. } => 8,
        DialogKind::ViewNotification { message, source, .. } => {
            // Dynamic height based on wrapped message lines
            let wrapped_lines = wrap_text(message, 44).len();
            let source_lines = if source.is_some() { 2 } else { 0 };
            // 2 (border) + 1 (empty) + wrapped_lines + 1 (empty) + source_lines + 2 (buttons)
            (6 + wrapped_lines + source_lines).min(20) as u16
        }
        DialogKind::AddContact => {
            // 2 (border) + 4 fields * 2 lines each + 2 (buttons) + 1 padding = 13
            13
        }
        DialogKind::QuickEphemeral => {
            // 2 (border) + 1 field * 2 lines + 2 (buttons) + 2 padding = 8
            8
        }
    };

    let dialog_x = (area.width.saturating_sub(dialog_width)) / 2;
    let dialog_y = (area.height.saturating_sub(dialog_height)) / 2;

    let dialog_area = Rect::new(
        area.x + dialog_x,
        area.y + dialog_y,
        dialog_width,
        dialog_height,
    );

    // Clear the area behind the dialog
    frame.render_widget(Clear, dialog_area);

    // Build content based on dialog type
    let (content_lines, show_password) = match &dialog.kind {
        DialogKind::InitiateChat { contact_name, onion_address } => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("Start chat with {}?", contact_name),
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    truncate_onion(onion_address),
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(""),
                Line::from("Enter passphrase:"),
            ];
            (lines, true)
        }
        DialogKind::IncomingRequest { source_name, onion_address, is_known, .. } => {
            let source_style = if *is_known {
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
            };
            let lines = vec![
                Line::from(""),
                Line::from(vec![
                    Span::styled(source_name, source_style),
                    Span::raw(" wants to chat"),
                ]),
                Line::from(""),
                Line::from(Span::styled(
                    truncate_onion(onion_address),
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(""),
                Line::from(if *is_known {
                    "Known contact"
                } else {
                    "Unknown - ephemeral contact"
                }),
            ];
            (lines, false)
        }
        DialogKind::AcceptChat { source_name, onion_address, .. } => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    format!("Accept chat from {}", source_name),
                    Style::default().add_modifier(Modifier::BOLD),
                )),
                Line::from(""),
                Line::from(Span::styled(
                    truncate_onion(onion_address),
                    Style::default().fg(Color::Cyan),
                )),
                Line::from(""),
                Line::from("Enter passphrase:"),
            ];
            (lines, true)
        }
        DialogKind::Error { message, .. } => {
            let lines = vec![
                Line::from(""),
                Line::from(Span::styled(
                    message,
                    Style::default().fg(Color::Red),
                )),
                Line::from(""),
                Line::from("Press Enter or Esc to close"),
            ];
            (lines, false)
        }
        DialogKind::ViewNotification { icon, message, source, .. } => {
            // Wrap message text to fit dialog width (dialog is 50 chars, minus borders = ~46)
            let max_width = 44;
            let wrapped_message = wrap_text(message, max_width);

            let mut lines = vec![Line::from("")];

            // First line with icon
            if let Some((first, rest)) = wrapped_message.split_first() {
                lines.push(Line::from(vec![
                    Span::raw(icon.clone()),
                    Span::raw(" "),
                    Span::styled(first.clone(), Style::default().fg(Color::White)),
                ]));
                // Remaining lines (indented to align with first line)
                for line in rest {
                    lines.push(Line::from(Span::styled(
                        format!("  {}", line),
                        Style::default().fg(Color::White),
                    )));
                }
            }

            lines.push(Line::from(""));
            if let Some(src) = source {
                lines.push(Line::from(Span::styled(
                    truncate_onion(src),
                    Style::default().fg(Color::Cyan),
                )));
                lines.push(Line::from(""));
            }
            (lines, false)
        }
        DialogKind::AddContact | DialogKind::QuickEphemeral => {
            // Multi-field dialogs are rendered separately
            (vec![], false)
        }
    };

    // Handle multi-field dialogs separately
    if dialog.has_fields() {
        render_multi_field_dialog(frame, dialog, dialog_area);
        return;
    }

    // Render dialog box with border
    let dialog_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", dialog.title()))
        .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .border_style(Style::default().fg(Color::Cyan));

    let inner_area = dialog_block.inner(dialog_area);
    frame.render_widget(dialog_block, dialog_area);

    // Split inner area for content, password field (if any), and buttons
    if show_password {
        let [content_area, password_area, buttons_area] = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(1),
            Constraint::Length(2),
        ])
        .areas(inner_area);

        // Render content
        let content = Paragraph::new(content_lines)
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(content, content_area);

        // Render password field
        let password_display = "*".repeat(dialog.password_input.len());
        let password_style = Style::default().fg(Color::White).bg(Color::DarkGray);
        let password_field = Paragraph::new(Span::styled(
            format!(" {} ", password_display),
            password_style,
        ))
        .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(password_field, password_area);

        // Position cursor in password field
        let cursor_x = password_area.x + (password_area.width / 2) - (dialog.password_input.len() as u16 / 2) + dialog.password_cursor as u16 + 1;
        let cursor_y = password_area.y;
        frame.set_cursor_position((cursor_x.min(password_area.x + password_area.width - 2), cursor_y));

        // Render buttons
        render_dialog_buttons(frame, dialog, buttons_area);
    } else {
        let [content_area, buttons_area] = Layout::vertical([
            Constraint::Min(1),
            Constraint::Length(2),
        ])
        .areas(inner_area);

        // Render content
        let content = Paragraph::new(content_lines)
            .alignment(ratatui::layout::Alignment::Center);
        frame.render_widget(content, content_area);

        // Render buttons
        render_dialog_buttons(frame, dialog, buttons_area);
    }
}

/// Render a multi-field dialog (AddContact, QuickEphemeral).
fn render_multi_field_dialog(frame: &mut Frame, dialog: &Dialog, dialog_area: Rect) {
    use ratatui::widgets::Clear;

    // Clear the area behind the dialog
    frame.render_widget(Clear, dialog_area);

    // Render dialog box with border
    let dialog_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" {} ", dialog.title()))
        .title_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .border_style(Style::default().fg(Color::Cyan));

    let inner_area = dialog_block.inner(dialog_area);
    frame.render_widget(dialog_block, dialog_area);

    // Calculate layout: fields area + buttons area
    let fields_count = dialog.fields.len();
    let fields_height = (fields_count * 2) as u16; // label + input for each field

    let [fields_area, buttons_area] = Layout::vertical([
        Constraint::Length(fields_height + 1), // +1 for padding
        Constraint::Length(2),
    ])
    .areas(inner_area);

    // Render each field
    let mut cursor_position: Option<(u16, u16)> = None;

    for (idx, field) in dialog.fields.iter().enumerate() {
        let y_offset = (idx * 2) as u16;
        let is_focused = idx == dialog.focused_field;

        // Label
        let label_area = Rect::new(
            fields_area.x,
            fields_area.y + y_offset,
            fields_area.width,
            1,
        );
        let label_style = if is_focused {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        let label = Paragraph::new(Span::styled(
            format!(" {}:", field.label),
            label_style,
        ));
        frame.render_widget(label, label_area);

        // Input field
        let input_area = Rect::new(
            fields_area.x + 1,
            fields_area.y + y_offset + 1,
            fields_area.width.saturating_sub(2),
            1,
        );

        let display_value = if field.value.is_empty() {
            Span::styled(&field.placeholder, Style::default().fg(Color::DarkGray))
        } else {
            Span::styled(&field.value, Style::default().fg(Color::White))
        };

        let input_style = if is_focused {
            Style::default().bg(Color::DarkGray)
        } else {
            Style::default()
        };

        let input = Paragraph::new(display_value).style(input_style);
        frame.render_widget(input, input_area);

        // Track cursor position for focused field
        if is_focused {
            cursor_position = Some((
                input_area.x + field.cursor as u16,
                input_area.y,
            ));
        }
    }

    // Render buttons
    render_dialog_buttons(frame, dialog, buttons_area);

    // Set cursor position
    if let Some((x, y)) = cursor_position {
        frame.set_cursor_position((x, y));
    }
}

/// Render dialog buttons (OK/Cancel or Accept/Cancel).
fn render_dialog_buttons(frame: &mut Frame, dialog: &Dialog, area: Rect) {
    let (ok_label, cancel_label) = match &dialog.kind {
        DialogKind::IncomingRequest { .. } => ("Accept", "Cancel"),
        DialogKind::Error { .. } => ("OK", ""),
        _ => ("OK", "Cancel"),
    };

    let ok_style = if dialog.focused_button == 0 {
        Style::default().fg(Color::Black).bg(Color::Green)
    } else {
        Style::default().fg(Color::Green)
    };

    let cancel_style = if dialog.focused_button == 1 {
        Style::default().fg(Color::Black).bg(Color::Red)
    } else {
        Style::default().fg(Color::Red)
    };

    let buttons = if cancel_label.is_empty() {
        // Only OK button
        Line::from(Span::styled(format!(" {} ", ok_label), ok_style))
    } else {
        Line::from(vec![
            Span::styled(format!(" {} ", ok_label), ok_style),
            Span::raw("   "),
            Span::styled(format!(" {} ", cancel_label), cancel_style),
        ])
    };

    let buttons_paragraph = Paragraph::new(buttons)
        .alignment(ratatui::layout::Alignment::Center);
    frame.render_widget(buttons_paragraph, area);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_truncate_onion() {
        let short = "abc.onion";
        assert_eq!(truncate_onion(short), short);

        let long = "abcdefghijklmnopqrstuvwxyz1234567890.onion";
        let truncated = truncate_onion(long);
        assert!(truncated.contains("..."));
    }

    #[test]
    fn test_wrap_text() {
        let wrapped = wrap_text("Hello world this is a test", 10);
        assert!(wrapped.len() > 1);
    }
}
