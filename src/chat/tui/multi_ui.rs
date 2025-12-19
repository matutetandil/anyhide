//! Multi-contact UI rendering for the TUI.
//!
//! Layout:
//! ```text
//! ┌───────────┬───────────────────────────────┐
//! │ Contacts  │ [●alice] [bob] [~eph]  <- Tabs│
//! │───────────├───────────────────────────────┤
//! │ ● alice ▲ │ Messages                      │
//! │ ○ bob   █ │                               │
//! │ ◌ ~eph  ░ │                               │
//! │───────────├───────────────────────────────┤
//! │ + Add     │ Input                  128/256│
//! │ ⚡ Quick  │                               │
//! ├───────────┴───────────────────────────────┤
//! │ 🔒 Tor ● | abc...xyz.onion | Tab: switch  │
//! └───────────────────────────────────────────┘
//! ```

use ratatui::{
    layout::{Constraint, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Tabs, Wrap},
    Frame,
};

use super::multi_app::{ConnectionStatus, Contact, ContactStatus, FocusedPanel, MultiApp};

/// Main render function for multi-contact TUI.
pub fn render_multi(frame: &mut Frame, app: &mut MultiApp) {
    // Clear expired status messages
    app.clear_expired_status();

    // Level 1: Main area + status bar
    let [main_area, status_area] = Layout::vertical([
        Constraint::Min(10),    // Main (sidebar + chat)
        Constraint::Length(1),  // Status bar
    ])
    .areas(frame.area());

    // Level 2: Sidebar + chat area
    let [sidebar_area, chat_area] = Layout::horizontal([
        Constraint::Length(16), // Sidebar (fixed width)
        Constraint::Min(40),    // Chat (flexible)
    ])
    .areas(main_area);

    render_sidebar(frame, app, sidebar_area);
    render_chat_area(frame, app, chat_area);
    render_status_bar(frame, app, status_area);
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
    let border_style = if app.focused_panel == FocusedPanel::Sidebar {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let items: Vec<ListItem> = app
        .contacts
        .iter()
        .enumerate()
        .map(|(i, contact)| {
            let style = if i == app.selected_contact && app.focused_panel == FocusedPanel::Sidebar {
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
    if app.focused_panel == FocusedPanel::Sidebar {
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
    }
}

/// Render sidebar action buttons.
fn render_sidebar_buttons(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let border_style = if app.focused_panel == FocusedPanel::Sidebar {
        Style::default().fg(Color::Cyan)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let buttons = Paragraph::new(vec![
        Line::from(Span::styled(" + Add", Style::default().fg(Color::Green))),
        Line::from(Span::styled(" ⚡ Quick", Style::default().fg(Color::Yellow))),
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
        Constraint::Length(1),  // Tabs (no border, just tabs)
        Constraint::Min(5),     // Messages
        Constraint::Length(3),  // Input
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

/// Render conversation tabs.
fn render_tabs(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let tab_titles: Vec<Line> = app
        .tabs
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let contact = app.contacts.iter().find(|c| &c.name == name);
            let label = if let Some(c) = contact {
                c.tab_label()
            } else {
                format!("[{}]", name)
            };

            let style = if i == app.active_tab {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::White)
            };

            Line::from(Span::styled(label, style))
        })
        .collect();

    let tabs = Tabs::new(tab_titles)
        .select(app.active_tab)
        .style(Style::default().fg(Color::White))
        .highlight_style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD))
        .divider(Span::raw(" "));

    frame.render_widget(tabs, area);
}

/// Render messages for the active conversation.
fn render_messages(frame: &mut Frame, app: &MultiApp, area: Rect) {
    let conversation = match app.active_conversation() {
        Some(conv) => conv,
        None => return,
    };

    let inner_height = area.height.saturating_sub(2) as usize;
    let inner_width = area.width.saturating_sub(2) as usize;

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

    let scroll_indicator = if conversation.scroll_offset > 0 {
        format!(" [↑{}] ", conversation.scroll_offset)
    } else {
        String::new()
    };

    let messages_block = Block::default()
        .borders(Borders::ALL)
        .title(format!(" Messages{}", scroll_indicator))
        .border_style(Style::default().fg(Color::White));

    let messages_list = List::new(items).block(messages_block);

    frame.render_widget(messages_list, area);
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
            Style::default().fg(Color::Green)
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

    // Cursor position
    if is_active {
        let inner_width = area.width.saturating_sub(2) as usize;
        let cursor = app.cursor_position;
        let visible_cursor = if app.input.chars().count() <= inner_width {
            cursor
        } else {
            let start = if cursor >= inner_width {
                cursor.saturating_sub(inner_width - 1)
            } else {
                0
            };
            cursor - start
        };

        let cursor_x = area.x + 1 + visible_cursor as u16;
        let cursor_y = area.y + 1;
        frame.set_cursor_position((cursor_x.min(area.x + area.width - 2), cursor_y));
    }
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

    // .onion address
    if let Some(ref onion) = app.my_onion {
        spans.push(Span::raw("| "));
        spans.push(Span::styled(
            truncate_onion(onion),
            Style::default().fg(Color::Cyan),
        ));
        spans.push(Span::raw(" "));
    }

    // Keyboard hints
    spans.push(Span::raw("| "));
    spans.push(Span::styled(
        "Tab: panel | ←→: tabs | Enter: open | Ctrl+Q: quit",
        Style::default().fg(Color::DarkGray),
    ));

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
