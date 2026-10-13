use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

use super::{short_record, App};

// Basic terminal colors keep escape sequences short on slow SSH links.
const MUTED: Color = Color::Gray;
const CYAN: Color = Color::Cyan;
const GREEN: Color = Color::Green;
const YELLOW: Color = Color::Yellow;
const RED: Color = Color::Red;

pub(super) fn render(frame: &mut Frame, app: &App) {
    let terminal_area = frame.area();
    if terminal_area.width < 40 || terminal_area.height < 10 {
        frame.render_widget(
            Paragraph::new("Tarnet needs at least 40 columns and 10 rows. Resize the terminal, or press <q> to quit.")
                .style(Style::default().fg(YELLOW))
                .wrap(Wrap { trim: true }),
            terminal_area,
        );
        return;
    }
    // Keep controls near the data in a large terminal and avoid painting unused
    // rows and columns over an SSH connection.
    let area = Rect {
        width: terminal_area.width.min(120),
        height: terminal_area.height.min(32),
        ..terminal_area
    };

    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);
    render_header(frame, app, sections[0]);
    render_body(frame, app, sections[1]);
    render_footer(frame, app, sections[2]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let zone = app.identity_name();
    let title = Line::from(vec![
        Span::styled(
            "  tarnet",
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ),
        Span::styled(format!("    zone: {zone}"), Style::default().fg(MUTED)),
    ]);
    frame.render_widget(Paragraph::new(title), Rect { height: 1, ..area });
    let tabs = ["<1> Node", "<2> Services", "<3> TNS records", "<4> Lookup"];
    let mut spans = vec![Span::raw("  ")];
    for (idx, label) in tabs.iter().enumerate() {
        let style = if idx == app.tab {
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(MUTED)
        };
        spans.push(Span::styled(format!(" {label} "), style));
        spans.push(Span::raw("  "));
    }
    frame.render_widget(
        Paragraph::new(Line::from(spans)),
        Rect {
            y: area.y + 1,
            height: 1,
            ..area
        },
    );
}

fn render_body(frame: &mut Frame, app: &App, area: Rect) {
    let (left, right) = panel_areas(area);
    let (list_title, detail_title) = match app.tab {
        0 => ("IDENTITIES", "NODE STATUS"),
        1 => ("SERVICE FILES", "DEPLOYMENT DETAILS"),
        2 => ("LOCAL LABELS", "RECORD DETAILS"),
        _ => ("LOOKUP CONTEXT", "RESOLUTION"),
    };
    render_left(frame, app, left, list_title);
    render_right(frame, app, right, detail_title);
}

fn panel_areas(area: Rect) -> (Rect, Rect) {
    if area.width >= 88 {
        let parts = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([
                Constraint::Percentage(38),
                Constraint::Length(1),
                Constraint::Min(0),
            ])
            .split(area);
        (parts[0], parts[2])
    } else {
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Percentage(30),
                Constraint::Length(1),
                Constraint::Min(0),
            ])
            .split(area);
        (parts[0], parts[2])
    }
}

fn pane(title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::TOP)
        .border_style(Style::default().fg(MUTED))
}

fn render_left(frame: &mut Frame, app: &App, area: Rect, title: &str) {
    if app.tab == 3 {
        let mut lines = vec![kv("Starting zone", app.identity_name())];
        if let Some((_, sid)) = app.identities.get(app.identity) {
            lines.push(Line::styled(sid.to_string(), Style::default().fg(MUTED)));
        }
        lines.push(Line::raw(""));
        if let Some((name, _)) = &app.lookup {
            lines.push(kv("Queried name", name));
            if let Some(root) = name.rsplit('.').next() {
                if let Some((_, records, public)) = app.labels.iter().find(|(n, _, _)| n == root) {
                    lines.push(Line::raw(""));
                    lines.push(kv("Local root", root));
                    lines.push(Line::styled(
                        if *public { "published" } else { "private" },
                        Style::default().fg(if *public { GREEN } else { YELLOW }),
                    ));
                    for record in records {
                        lines.push(Line::raw(short_record(record)));
                    }
                }
            }
        } else {
            lines.push(Line::styled(
                "Press </> to enter a name.",
                Style::default().fg(MUTED),
            ));
        }
        render_paragraph(frame, area, title, lines, app.detail_scroll);
        return;
    }

    let items: Vec<ListItem> = match app.tab {
        0 => app
            .identities
            .iter()
            .map(|(name, sid)| {
                let color = if name == app.identity_name() {
                    CYAN
                } else {
                    Color::Reset
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!(" {name}"),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        format!("  {}…", &sid.to_string()[..10]),
                        Style::default().fg(MUTED),
                    ),
                ]))
            })
            .collect(),
        1 => app
            .services
            .iter()
            .map(|file| {
                let (badge, color) = match &file.config {
                    Err(_) => ("INVALID", RED),
                    Ok(c) if c.publish => ("PUBLIC", GREEN),
                    Ok(_) => ("LOCAL", YELLOW),
                };
                ListItem::new(Line::from(vec![
                    Span::raw(format!(" {:<18}", file.name)),
                    Span::styled(badge, Style::default().fg(color)),
                ]))
            })
            .collect(),
        _ => app
            .labels
            .iter()
            .map(|(name, records, public)| {
                ListItem::new(Line::from(vec![
                    Span::raw(format!(" {name:<18}")),
                    Span::styled(
                        if *public { "PUBLIC" } else { "PRIVATE" },
                        Style::default().fg(if *public { GREEN } else { YELLOW }),
                    ),
                    Span::styled(format!("  {}", records.len()), Style::default().fg(MUTED)),
                ]))
            })
            .collect(),
    };
    let empty = items.is_empty();
    let list = List::new(items)
        .block(pane(title))
        .highlight_symbol("> ")
        .highlight_style(Style::default().fg(CYAN).add_modifier(Modifier::BOLD));
    let mut state =
        ListState::default().with_selected(if empty { None } else { Some(app.selected) });
    frame.render_stateful_widget(list, area, &mut state);
    if empty && area.height > 3 {
        frame.render_widget(
            Paragraph::new("  Nothing here yet.").style(Style::default().fg(MUTED)),
            Rect {
                x: area.x + 1,
                y: area.y + 1,
                width: area.width.saturating_sub(2),
                height: 1,
            },
        );
    }
}

fn render_right(frame: &mut Frame, app: &App, area: Rect, title: &str) {
    let mut lines = Vec::new();
    match app.tab {
        0 => {
            if let Some((name, sid)) = app.identities.get(app.selected) {
                lines.push(section("SELECTED IDENTITY"));
                lines.push(kv("Name", name));
                lines.push(kv("Service ID", sid.to_string()));
                lines.push(Line::raw(""));
            }
            if let Some(s) = &app.status {
                lines.push(section("DAEMON"));
                lines.push(kv("Peer ID", s.peer_id.to_string()));
                lines.push(kv("Uptime", format!("{} seconds", s.uptime_secs)));
                lines.push(kv("Connected peers", s.peers.len().to_string()));
                lines.push(kv("Routes", s.routes.len().to_string()));
                lines.push(Line::raw(""));
                lines.push(section("NETWORK"));
                lines.push(kv("DHT records", s.dht.stored_records.to_string()));
                lines.push(kv("DHT keys", s.dht.stored_keys.to_string()));
                lines.push(kv(
                    "Outbound circuits",
                    s.circuits.outbound_circuits.to_string(),
                ));
                if !s.peers.is_empty() {
                    lines.push(Line::raw(""));
                    lines.push(section("PEERS"));
                    for peer in &s.peers {
                        lines.push(Line::raw(peer.peer_id.to_string()));
                        lines.push(kv("Links", peer.links.len().to_string()));
                    }
                }
            }
        }
        1 => {
            if let Some(file) = app.services.get(app.selected) {
                match &file.config {
                    Err(e) => {
                        lines.push(kv("File", file.path.display().to_string()));
                        lines.push(Line::styled(
                            format!("INVALID TOML: {e}"),
                            Style::default().fg(RED),
                        ));
                    }
                    Ok(c) => {
                        lines.push(section("NAME & DESTINATION"));
                        lines.push(kv(
                            "Identity zone",
                            c.identity.as_deref().unwrap_or("default"),
                        ));
                        lines.push(kv(
                            "TNS label",
                            c.subdomain.as_deref().unwrap_or("@ (apex)"),
                        ));
                        lines.push(kv(
                            "Record",
                            if c.subdomain.is_none() {
                                "identity"
                            } else {
                                c.record.as_deref().unwrap_or("vhost")
                            },
                        ));
                        lines.push(kv(
                            "Destination",
                            c.target.as_deref().unwrap_or("own identity"),
                        ));
                        lines.push(Line::styled(
                            if c.publish {
                                "Published to TNS"
                            } else {
                                "TNS publication disabled"
                            },
                            Style::default().fg(if c.publish { GREEN } else { YELLOW }),
                        ));
                        lines.push(Line::raw(""));
                        lines.push(section("EXPOSURE"));
                        lines.push(kv("Local target", &c.local));
                        lines.push(kv("Protocol", &c.protocol));
                        lines.push(kv(
                            "Port",
                            c.port
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "from local address".into()),
                        ));
                        if let Some(pool) = &c.pool {
                            lines.push(kv("Pool", pool));
                        }
                        lines.push(Line::raw(""));
                        lines.push(kv("File", file.path.display().to_string()));
                        lines.push(Line::styled(
                            "<enter>: compare configured target with live TNS",
                            Style::default().fg(MUTED),
                        ));
                    }
                }
            }
        }
        2 => {
            if let Some((name, records, public)) = app.labels.get(app.selected) {
                lines.push(kv("Label", name));
                lines.push(Line::styled(
                    if *public {
                        "PUBLIC · published to DHT"
                    } else {
                        "PRIVATE · local only"
                    },
                    Style::default().fg(if *public { GREEN } else { YELLOW }),
                ));
                lines.push(Line::raw(""));
                lines.push(section("RECORDS"));
                for record in records {
                    lines.push(Line::raw(short_record(record)));
                }
                lines.push(Line::raw(""));
                lines.push(Line::styled(
                    "<enter>: resolve this label from the active zone",
                    Style::default().fg(MUTED),
                ));
            } else {
                lines.push(Line::styled(
                    "Service publications can exist in the DHT without a local label here.",
                    Style::default().fg(MUTED),
                ));
            }
        }
        _ => {
            if let Some((name, result)) = &app.lookup {
                lines.push(kv("Name", name));
                lines.push(Line::raw(""));
                lines.push(section("ANSWER"));
                for line in result.lines() {
                    let color = if line.starts_with("MATCH:") {
                        GREEN
                    } else if line.starts_with("MISMATCH:")
                        || line.contains("Not found")
                        || line.contains("failed")
                    {
                        RED
                    } else if line.starts_with("Expected:") || line.starts_with("Note:") {
                        YELLOW
                    } else {
                        Color::Reset
                    };
                    lines.push(Line::styled(line.to_string(), Style::default().fg(color)));
                }
            } else {
                lines.push(Line::styled(
                    "No lookup yet. Press </> and enter a TNS name.",
                    Style::default().fg(MUTED),
                ));
            }
        }
    }
    render_paragraph(frame, area, title, lines, app.detail_scroll);
}

fn render_paragraph(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    scroll: u16,
) {
    frame.render_widget(
        Paragraph::new(lines)
            .block(pane(title))
            .scroll((scroll, 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn kv(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(MUTED)),
        Span::raw(value.into()),
    ])
}

fn section(label: &str) -> Line<'static> {
    Line::styled(
        label.to_string(),
        Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
    )
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let contextual = match app.tab {
        0 => "<i> change zone",
        1 => "<enter> check TNS  <e> edit file  <R> reload daemon",
        2 => "<enter> resolve  <a> add record  <d> remove record",
        _ => "</> new lookup  <i> change zone",
    };
    let keys = format!("  {contextual}");
    frame.render_widget(
        Paragraph::new(keys).style(Style::default().fg(MUTED)),
        Rect { height: 1, ..area },
    );
    frame.render_widget(
        Paragraph::new(
            "  <1>-<4> views  <up>/<down> select  <pgup>/<pgdn> scroll  <r> refresh  <q> quit",
        )
        .style(Style::default().fg(MUTED)),
        Rect {
            y: area.y + 1,
            height: 1,
            ..area
        },
    );
    let (message, style) = if let Some(input) = &app.input {
        (
            format!(
                "  {}: {}_     <enter> confirm · <esc> cancel",
                input.label(),
                super::input_text(input)
            ),
            Style::default().fg(CYAN),
        )
    } else {
        let color = if app.message.is_empty() {
            MUTED
        } else if app.message.contains("failed")
            || app.message.contains("Invalid")
            || app.message.contains("not found")
        {
            RED
        } else {
            GREEN
        };
        (
            if app.message.is_empty() {
                "  Ready".to_string()
            } else {
                format!("  {}", app.message)
            },
            Style::default().fg(color),
        )
    };
    frame.render_widget(
        Paragraph::new(message).style(style),
        Rect {
            y: area.y + 2,
            height: 1,
            ..area
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn panel_layout_uses_columns_when_wide_and_rows_when_narrow() {
        let (a, b) = panel_areas(Rect::new(0, 0, 100, 20));
        assert_eq!(a.y, b.y);
        assert!(a.x < b.x);
        let (a, b) = panel_areas(Rect::new(0, 0, 60, 20));
        assert_eq!(a.x, b.x);
        assert!(a.y < b.y);
    }
}
