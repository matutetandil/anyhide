//! UI rendering for the TUI.

use ratatui::{
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph, Wrap},
    Frame,
};

use super::app::{App, ConnectionStatus, MessageAuthor};

/// Main render function.
pub fn render(frame: &mut Frame, app: &App) {
    // Create main layout: header, messages, input
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // Header/status bar
            Constraint::Min(5),    // Messages area
            Constraint::Length(3), // Input area
        ])
        .split(frame.area());

    render_header(frame, app, chunks[0]);
    render_messages(frame, app, chunks[1]);
    render_input(frame, app, chunks[2]);
}

/// Render the header/status bar.
fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let status_color = match app.status {
        ConnectionStatus::Connected => Color::Green,
        ConnectionStatus::Error(_) => Color::Red,
        ConnectionStatus::Disconnected => Color::DarkGray,
        _ => Color::Yellow,
    };

    let status_text = match &app.status {
        ConnectionStatus::Error(e) => format!("Error: {}", e),
        other => other.display().to_string(),
    };

    // Build title with peer name
    let title = format!(" Anyhide Chat - {} ", app.peer_name);

    // Build status line
    let mut spans = vec![
        Span::styled(
            format!(" {} ", status_text),
            Style::default().fg(status_color).add_modifier(Modifier::BOLD),
        ),
    ];

    // Add .onion address if available
    if let Some(ref onion) = app.my_onion {
        spans.push(Span::raw(" | "));
        spans.push(Span::styled(
            format!("{}", truncate_onion(onion)),
            Style::default().fg(Color::Cyan),
        ));
    }

    // Add message counts
    spans.push(Span::raw(" | "));
    spans.push(Span::styled(
        format!("{}↑ {}↓", app.messages_sent, app.messages_received),
        Style::default().fg(Color::DarkGray),
    ));

    let status_line = Line::from(spans);

    let header = Paragraph::new(status_line)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Cyan)),
        );

    frame.render_widget(header, area);
}

/// Wrap text to fit within a given width (word-aware).
fn wrap_text(text: &str, max_width: usize) -> Vec<String> {
    if max_width == 0 {
        return vec![text.to_string()];
    }

    let mut lines = Vec::new();
    let mut current_line = String::new();
    let mut current_width = 0;

    for word in text.split_inclusive(|c: char| c.is_whitespace()) {
        let word_len = word.chars().count();

        // If word fits on current line
        if current_width + word_len <= max_width {
            current_line.push_str(word);
            current_width += word_len;
        } else if word_len > max_width {
            // Word is too long for any line - must break it
            if !current_line.is_empty() {
                lines.push(current_line);
                current_line = String::new();
                current_width = 0;
            }
            // Break the long word
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
            // Start new line with this word
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

/// Render the messages area.
fn render_messages(frame: &mut Frame, app: &App, area: Rect) {
    let inner_height = area.height.saturating_sub(2) as usize; // Account for borders
    let inner_width = area.width.saturating_sub(2) as usize; // Account for borders

    // Build wrapped lines from messages
    let mut all_lines: Vec<(Line, bool)> = Vec::new(); // (line, is_first_line_of_message)

    for msg in &app.messages {
        let (prefix, style) = match &msg.author {
            MessageAuthor::You => (
                format!("[{}] you: ", msg.formatted_time()),
                Style::default().fg(Color::Green),
            ),
            MessageAuthor::Peer(name) => (
                format!("[{}] {}: ", msg.formatted_time(), name),
                Style::default().fg(Color::Blue),
            ),
            MessageAuthor::System => (
                format!("[{}] ", msg.formatted_time()),
                Style::default().fg(Color::Yellow).add_modifier(Modifier::ITALIC),
            ),
        };

        let prefix_len = prefix.chars().count();
        let content_width = inner_width.saturating_sub(prefix_len);

        if content_width == 0 || msg.content.is_empty() {
            // Just show prefix
            let line = Line::from(vec![
                Span::styled(prefix.clone(), style),
                Span::styled(msg.content.clone(), Style::default()),
            ]);
            all_lines.push((line, true));
        } else {
            // Wrap content
            let wrapped = wrap_text(&msg.content, content_width);
            for (i, part) in wrapped.into_iter().enumerate() {
                if i == 0 {
                    // First line has prefix
                    let line = Line::from(vec![
                        Span::styled(prefix.clone(), style),
                        Span::styled(part, Style::default()),
                    ]);
                    all_lines.push((line, true));
                } else {
                    // Continuation lines are indented
                    let indent = " ".repeat(prefix_len);
                    let line = Line::from(vec![
                        Span::styled(indent, Style::default()),
                        Span::styled(part, Style::default()),
                    ]);
                    all_lines.push((line, false));
                }
            }
        }
    }

    // Calculate visible lines with scroll offset
    let total_lines = all_lines.len();
    let start_index = if total_lines > inner_height {
        total_lines
            .saturating_sub(inner_height)
            .saturating_sub(app.scroll_offset)
    } else {
        0
    };
    let end_index = start_index.saturating_add(inner_height).min(total_lines);

    let items: Vec<ListItem> = all_lines[start_index..end_index]
        .iter()
        .map(|(line, _)| ListItem::new(line.clone()))
        .collect();

    let scroll_indicator = if app.scroll_offset > 0 {
        format!(" [↑{}] ", app.scroll_offset)
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

/// Render the input area.
fn render_input(frame: &mut Frame, app: &App, area: Rect) {
    let input_style = if app.is_connected() {
        Style::default().fg(Color::White)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let placeholder = if app.is_connected() {
        if app.input.is_empty() {
            "Type a message... (Ctrl+C to quit)"
        } else {
            ""
        }
    } else {
        "Waiting for connection..."
    };

    // Calculate visible portion of input (keep cursor visible)
    let inner_width = area.width.saturating_sub(2) as usize; // Account for borders
    let display_text = if app.input.is_empty() {
        placeholder.to_string()
    } else {
        // Show portion of text that keeps cursor visible
        let cursor = app.cursor_position;
        let input_chars: Vec<char> = app.input.chars().collect();
        let input_len = input_chars.len();

        if input_len <= inner_width {
            // Fits entirely
            app.input.clone()
        } else {
            // Need to scroll - keep cursor visible
            let start = if cursor >= inner_width {
                cursor.saturating_sub(inner_width - 1)
            } else {
                0
            };
            let end = (start + inner_width).min(input_len);
            input_chars[start..end].iter().collect()
        }
    };

    // Calculate cursor position within visible area
    let visible_cursor = if app.input.is_empty() {
        0
    } else {
        let input_len = app.input.chars().count();
        if input_len <= inner_width {
            app.cursor_position
        } else {
            let start = if app.cursor_position >= inner_width {
                app.cursor_position.saturating_sub(inner_width - 1)
            } else {
                0
            };
            app.cursor_position - start
        }
    };

    // Character counter - show remaining chars
    let remaining = app.remaining_chars();
    let counter_style = if remaining == 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else if remaining <= 20 {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    // Build title with counter on right side
    let title_left = " Input ";
    let counter_text = format!(" {}/{} ", app.input.chars().count(), app.max_message_len);

    let input = Paragraph::new(display_text)
        .style(if app.input.is_empty() {
            Style::default().fg(Color::DarkGray)
        } else {
            input_style
        })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title_left)
                .title_bottom(Line::from(vec![
                    Span::styled(counter_text, counter_style),
                ]).right_aligned())
                .border_style(if app.is_connected() {
                    if remaining == 0 {
                        Style::default().fg(Color::Red)
                    } else {
                        Style::default().fg(Color::Green)
                    }
                } else {
                    Style::default().fg(Color::DarkGray)
                }),
        )
        .wrap(Wrap { trim: false });

    frame.render_widget(input, area);

    // Position cursor (using visible_cursor for scrolled input)
    if app.is_connected() {
        let cursor_x = area.x + 1 + visible_cursor as u16;
        let cursor_y = area.y + 1;
        frame.set_cursor_position((cursor_x.min(area.x + area.width - 2), cursor_y));
    }
}

/// Truncate .onion address for display.
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
        assert!(truncated.len() < long.len());
    }
}
