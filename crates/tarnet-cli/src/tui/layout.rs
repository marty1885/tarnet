use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;
use tarnet_api::types::LinkStatus;

use super::{short_record, App, DHT, LOOKUP, NODE, ROUTING, SERVICES, TNS};

// Basic terminal colors keep escape sequences short on slow SSH links.
const MUTED: Color = Color::Gray;
const CYAN: Color = Color::Cyan;
const GREEN: Color = Color::Green;
const YELLOW: Color = Color::Yellow;
const RED: Color = Color::Red;

pub(super) fn render(frame: &mut Frame, app: &App) {
    let area = frame.area();
    if area.width < 30 || area.height < 8 {
        frame.render_widget(
            Paragraph::new(format!(
                "Terminal too small ({}x{}). Need 30x8; resize or press <q> to quit.",
                area.width, area.height
            ))
            .style(Style::default().fg(YELLOW))
            .wrap(Wrap { trim: true }),
            area,
        );
        return;
    }
    // Two footer rows on short terminals (hints + status), three when there
    // is room to separate contextual keys from global ones.
    let footer_height = if area.height >= 20 { 3 } else { 2 };
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(3),
            Constraint::Length(footer_height),
        ])
        .split(area);
    render_header(frame, app, sections[0]);
    render_body(frame, app, sections[1]);
    render_footer(frame, app, sections[2]);
}

fn render_header(frame: &mut Frame, app: &App, area: Rect) {
    let top = Rect { height: 1, ..area };
    let title = Line::from(vec![
        Span::styled(
            " tarnet ",
            Style::default()
                .fg(Color::Black)
                .bg(CYAN)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled("  zone ", Style::default().fg(MUTED)),
        Span::styled(
            app.identity_name().to_string(),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ]);
    frame.render_widget(Paragraph::new(title), top);
    if let (Some(s), true) = (&app.status, area.width >= 56) {
        let (color, text) = if s.peers.is_empty() {
            (YELLOW, "no peers".to_string())
        } else {
            (
                GREEN,
                format!("{} peers · {} routes", s.peers.len(), s.routes.len()),
            )
        };
        frame.render_widget(
            Paragraph::new(Line::from(vec![
                Span::styled("● ", Style::default().fg(color)),
                Span::styled(format!("{text} "), Style::default().fg(MUTED)),
            ]))
            .alignment(Alignment::Right),
            top,
        );
    }

    let full = [
        "Node",
        "Routing",
        "Services",
        "TNS records",
        "Lookup",
        "DHT",
    ];
    let short = ["Node", "Route", "Svcs", "TNS", "Find", "DHT"];
    let width_of =
        |names: &[&str; 6]| -> usize { names.iter().map(|n| n.len() + 5).sum::<usize>() + 1 };
    let names = if width_of(&full) <= area.width as usize {
        Some(&full)
    } else if width_of(&short) <= area.width as usize {
        Some(&short)
    } else {
        None
    };
    let mut spans = vec![Span::raw(" ")];
    for idx in 0..full.len() {
        let active = idx == app.tab;
        let style = if active {
            Style::default()
                .fg(Color::Black)
                .bg(CYAN)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(MUTED)
        };
        let label = match names {
            Some(n) => format!(" {} {} ", idx + 1, n[idx]),
            // Very narrow: only the active tab keeps its name.
            None if active => format!(" {} {} ", idx + 1, full[idx]),
            None => format!(" {} ", idx + 1),
        };
        spans.push(Span::styled(label, style));
        spans.push(Span::raw(" "));
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
        NODE => ("Identities".to_string(), "Node status".to_string()),
        ROUTING => (
            format!("Routes ({})", app.item_count()),
            format!(
                "Route details · live, updated {}s ago",
                app.last_refresh.elapsed().as_secs()
            ),
        ),
        SERVICES => (
            "Service files".to_string(),
            "Deployment details".to_string(),
        ),
        TNS => ("Local labels".to_string(), "Record details".to_string()),
        LOOKUP => ("Lookup context".to_string(), "Resolution".to_string()),
        _ => (
            format!("Operations ({})", app.item_count()),
            "Content".to_string(),
        ),
    };
    render_left(frame, app, left, &list_title);
    render_right(frame, app, right, &detail_title);
}

fn panel_areas(area: Rect) -> (Rect, Rect) {
    if area.width >= 88 {
        let left = (area.width * 2 / 5).clamp(34, 56);
        let parts = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Length(left), Constraint::Min(0)])
            .split(area);
        (parts[0], parts[1])
    } else {
        // Stacked: the list gets roughly a third of the height, but always
        // enough rows for a border pair plus a few entries.
        let top = (area.height / 3)
            .clamp(4, 10)
            .min(area.height.saturating_sub(4));
        let parts = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(top), Constraint::Min(0)])
            .split(area);
        (parts[0], parts[1])
    }
}

fn pane(title: &str) -> Block<'_> {
    Block::default()
        .title(Span::styled(
            format!(" {title} "),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        ))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(MUTED))
}

/// Shorten `s` to at most `max` characters, marking the cut with an ellipsis.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max.saturating_sub(1)).collect();
        out.push('…');
        out
    }
}

fn format_uptime(secs: u64) -> String {
    let (d, h, m, s) = (secs / 86400, secs / 3600 % 24, secs / 60 % 60, secs % 60);
    if d > 0 {
        format!("{d}d {h}h {m}m")
    } else if h > 0 {
        format!("{h}h {m}m {s}s")
    } else if m > 0 {
        format!("{m}m {s}s")
    } else {
        format!("{s}s")
    }
}

fn render_left(frame: &mut Frame, app: &App, area: Rect, title: &str) {
    if app.tab == LOOKUP {
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

    // Columns inside the border and the 2-char highlight symbol.
    let inner = (area.width as usize).saturating_sub(4);
    let items: Vec<ListItem> = match app.tab {
        NODE => {
            let show_id = inner >= 30;
            let name_w = if show_id {
                inner - 14
            } else {
                inner.saturating_sub(2)
            };
            app.identities
                .iter()
                .map(|(name, sid)| {
                    let active = name == app.identity_name();
                    let mut spans = vec![
                        Span::styled(if active { "● " } else { "  " }, Style::default().fg(GREEN)),
                        Span::styled(
                            format!("{:<w$}", truncate(name, name_w), w = name_w),
                            Style::default().add_modifier(Modifier::BOLD),
                        ),
                    ];
                    if show_id {
                        spans.push(Span::styled(
                            format!(" {}…", &sid.to_string()[..10]),
                            Style::default().fg(MUTED),
                        ));
                    }
                    ListItem::new(Line::from(spans))
                })
                .collect()
        }
        ROUTING => route_items(app, inner),
        DHT => app
            .dht_ops
            .iter()
            .map(|op| {
                let color = if op.ok { GREEN } else { RED };
                let id = if op.handle.is_empty() {
                    "-".to_string()
                } else {
                    // The first half of a handle is the secret key; list the
                    // blob-hash half, which identifies the record.
                    let hash = &op.handle[64..];
                    format!(
                        "{}…",
                        &hash[..hash.len().min(inner.saturating_sub(8)).min(12)]
                    )
                };
                ListItem::new(Line::from(vec![
                    Span::styled(
                        format!("{} ", op.kind),
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        if op.ok { "ok  " } else { "FAIL" },
                        Style::default().fg(color),
                    ),
                    Span::styled(format!(" {id}"), Style::default().fg(MUTED)),
                ]))
            })
            .collect(),
        SERVICES => {
            let name_w = inner.saturating_sub(9).max(4);
            app.services
                .iter()
                .map(|file| {
                    let (badge, color) = match &file.config {
                        Err(_) => ("INVALID", RED),
                        Ok(c) if c.publish => ("PUBLIC ", GREEN),
                        Ok(_) => ("LOCAL  ", YELLOW),
                    };
                    ListItem::new(Line::from(vec![
                        Span::raw(format!("{:<w$} ", truncate(&file.name, name_w), w = name_w)),
                        Span::styled(badge, Style::default().fg(color)),
                    ]))
                })
                .collect()
        }
        _ => {
            let name_w = inner.saturating_sub(12).max(4);
            app.labels
                .iter()
                .map(|(name, records, public)| {
                    ListItem::new(Line::from(vec![
                        Span::raw(format!("{:<w$} ", truncate(name, name_w), w = name_w)),
                        Span::styled(
                            if *public { "PUBLIC " } else { "PRIVATE" },
                            Style::default().fg(if *public { GREEN } else { YELLOW }),
                        ),
                        Span::styled(format!(" {}", records.len()), Style::default().fg(MUTED)),
                    ]))
                })
                .collect()
        }
    };
    let empty = items.is_empty();
    let list = List::new(items)
        .block(pane(title))
        .highlight_symbol("> ")
        .highlight_style(
            Style::default()
                .fg(Color::Black)
                .bg(CYAN)
                .add_modifier(Modifier::BOLD),
        );
    let mut state =
        ListState::default().with_selected(if empty { None } else { Some(app.selected) });
    frame.render_stateful_widget(list, area, &mut state);
    if empty && area.height > 2 {
        frame.render_widget(
            Paragraph::new("Nothing here yet.").style(Style::default().fg(MUTED)),
            Rect {
                x: area.x + 2,
                y: area.y + 1,
                width: area.width.saturating_sub(4),
                height: 1,
            },
        );
    }
}

fn render_right(frame: &mut Frame, app: &App, area: Rect, title: &str) {
    let mut lines = Vec::new();
    match app.tab {
        ROUTING => routing_details(app, &mut lines),
        DHT => dht_details(app, &mut lines),
        NODE => {
            if let Some((name, sid)) = app.identities.get(app.selected) {
                lines.push(section("SELECTED IDENTITY"));
                lines.push(kv("Name", name));
                lines.push(kv("Service ID", sid.to_string()));
                lines.push(Line::raw(""));
            }
            if let Some(s) = &app.status {
                lines.push(section("DAEMON"));
                lines.push(kv("Peer ID", s.peer_id.to_string()));
                lines.push(kv("Uptime", format_uptime(s.uptime_secs)));
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
                        lines.push(Line::from(vec![
                            Span::raw(peer.peer_id.to_string()),
                            Span::styled(
                                format!("  {} link(s)", peer.links.len()),
                                Style::default().fg(MUTED),
                            ),
                        ]));
                    }
                }
            }
        }
        SERVICES => {
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
        TNS => {
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

fn short_id(id: &impl std::fmt::Display, len: usize) -> String {
    id.to_string().chars().take(len).collect()
}

fn format_rtt(rtt_us: u64) -> String {
    match rtt_us {
        0 => "-".into(),
        us if us < 1_000 => format!("{us}us"),
        us if us < 1_000_000 => format!("{:.1}ms", us as f64 / 1_000.0),
        us => format!("{:.1}s", us as f64 / 1_000_000.0),
    }
}

fn format_secs(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s}s"),
        s if s < 3600 => format!("{}m{}s", s / 60, s % 60),
        s if s < 86400 => format!("{}h{}m", s / 3600, s / 60 % 60),
        s => format!("{}d{}h", s / 86400, s / 3600 % 24),
    }
}

fn route_items(app: &App, inner: usize) -> Vec<ListItem<'static>> {
    let compact = inner < 30;
    let dest_w = if compact { 8 } else { 12 };
    let show_transport = inner >= 44;
    app.sorted_routes()
        .into_iter()
        .map(|(dest, next_hop, cost)| {
            let (via, via_color) = match (dest == next_hop, compact) {
                (true, _) => ("direct".to_string(), GREEN),
                (false, true) => ("relay".to_string(), YELLOW),
                (false, false) => (format!("via {}", short_id(next_hop, 8)), YELLOW),
            };
            let via_w = if compact { 6 } else { 12 };
            let mut spans = vec![
                Span::raw(format!("{} ", short_id(dest, dest_w))),
                Span::styled(format!("{via:<via_w$} "), Style::default().fg(via_color)),
                Span::styled(format!("{cost:>3}"), Style::default().fg(MUTED)),
            ];
            if show_transport {
                let transport = app
                    .link_to(next_hop)
                    .map(|l| l.transport.clone())
                    .unwrap_or_else(|| "-".into());
                spans.push(Span::styled(
                    format!("  {}", truncate(&transport, inner.saturating_sub(34))),
                    Style::default().fg(CYAN),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect()
}

fn link_lines(link: &LinkStatus, lines: &mut Vec<Line<'static>>) {
    lines.push(kv("Transport", &link.transport));
    lines.push(kv("State", &link.state));
    lines.push(kv("Direction", &link.direction));
    lines.push(kv("RTT", format_rtt(link.rtt_us)));
    lines.push(kv("Idle", format_secs(link.idle_secs)));
    lines.push(kv("Link age", format_secs(link.age_secs)));
}

fn routing_details(app: &App, lines: &mut Vec<Line<'static>>) {
    let Some(status) = &app.status else {
        lines.push(Line::styled(
            "Waiting for daemon status…",
            Style::default().fg(MUTED),
        ));
        return;
    };
    let routes = app.sorted_routes();
    if let Some((dest, next_hop, cost)) = routes.get(app.selected) {
        lines.push(section("SELECTED ROUTE"));
        lines.push(kv("Destination", dest.to_string()));
        if dest == next_hop {
            lines.push(Line::styled("Direct neighbour", Style::default().fg(GREEN)));
        } else {
            lines.push(kv("Next hop", next_hop.to_string()));
        }
        lines.push(kv("Cost", cost.to_string()));
        lines.push(Line::raw(""));
        lines.push(section("FIRST-HOP TRANSPORT"));
        match status.peers.iter().find(|p| p.peer_id == *next_hop) {
            Some(peer) => {
                let mut links: Vec<_> = peer.links.iter().collect();
                links.sort_by_key(|l| l.state != "active");
                for (i, link) in links.into_iter().enumerate() {
                    if i > 0 {
                        lines.push(Line::styled("· other link", Style::default().fg(MUTED)));
                    }
                    link_lines(link, lines);
                }
            }
            None => lines.push(Line::styled(
                "Next hop is not a connected peer (route may be stale)",
                Style::default().fg(YELLOW),
            )),
        }
        lines.push(Line::raw(""));
    } else {
        lines.push(Line::styled(
            "No routes yet. Routes appear as the node learns of other peers.",
            Style::default().fg(MUTED),
        ));
        lines.push(Line::raw(""));
    }

    let direct = status.routes.iter().filter(|(d, n, _)| d == n).count();
    lines.push(section("TABLE"));
    lines.push(kv("Routes", status.routes.len().to_string()));
    lines.push(kv("Direct", direct.to_string()));
    lines.push(kv("Via relay", (status.routes.len() - direct).to_string()));
    lines.push(kv("Neighbours", status.peers.len().to_string()));
    let mut by_transport: std::collections::BTreeMap<&str, (usize, usize)> = Default::default();
    for link in status.peers.iter().flat_map(|p| &p.links) {
        let entry = by_transport.entry(link.transport.as_str()).or_default();
        if link.state == "active" {
            entry.0 += 1;
        } else {
            entry.1 += 1;
        }
    }
    if !by_transport.is_empty() {
        lines.push(Line::raw(""));
        lines.push(section("TRANSPORTS"));
        for (name, (active, standby)) in by_transport {
            lines.push(Line::from(vec![
                Span::styled(format!("{name}: "), Style::default().fg(MUTED)),
                Span::styled(
                    format!("{active} active"),
                    Style::default().add_modifier(Modifier::BOLD),
                ),
                Span::styled(format!(", {standby} standby"), Style::default().fg(MUTED)),
            ]));
        }
    }
}

/// Render at most this many bytes of retrieved content.
const DHT_PREVIEW_BYTES: usize = 4096;

fn dht_details(app: &App, lines: &mut Vec<Line<'static>>) {
    let Some(op) = app.dht_ops.get(app.selected) else {
        lines.push(section("DHT PLAYGROUND"));
        lines.push(Line::raw(
            "Store and fetch content-addressed records in the DHT.",
        ));
        lines.push(Line::raw(""));
        lines.push(kv("p", "put text, or @path to put a file"));
        lines.push(kv("g", "get content by its 128-char handle"));
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "A handle is the decryption key plus the blob hash: whoever holds it can read the content.",
            Style::default().fg(MUTED),
        ));
        return;
    };
    lines.push(section(op.kind));
    lines.push(Line::styled(
        op.note.clone(),
        Style::default().fg(if op.ok { GREEN } else { RED }),
    ));
    if !op.handle.is_empty() {
        lines.push(Line::raw(""));
        lines.push(Line::styled(
            "Handle (select to copy):",
            Style::default().fg(MUTED),
        ));
        lines.push(Line::styled(
            op.handle.clone(),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::styled(
            "<enter> fetch this handle again from the network",
            Style::default().fg(MUTED),
        ));
    }
    let Some(data) = &op.data else { return };
    lines.push(Line::raw(""));
    lines.push(section("CONTENT"));
    lines.push(kv("Size", format!("{} bytes", data.len())));
    lines.push(Line::raw(""));
    let shown = &data[..data.len().min(DHT_PREVIEW_BYTES)];
    let text_len = match std::str::from_utf8(shown) {
        Ok(_) => Some(shown.len()),
        // A preview cut inside a multi-byte char is still text.
        Err(e) if e.error_len().is_none() && e.valid_up_to() > 0 => Some(e.valid_up_to()),
        Err(_) => None,
    };
    match text_len {
        Some(n) => lines.extend(
            String::from_utf8_lossy(&shown[..n])
                .lines()
                .map(|l| Line::raw(l.to_string())),
        ),
        None => {
            lines.push(Line::styled(
                "binary · hex dump",
                Style::default().fg(MUTED),
            ));
            for (i, chunk) in shown.chunks(16).enumerate() {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{b:02x}")).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if (0x20..0x7f).contains(&b) {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                lines.push(Line::raw(format!(
                    "{:04x}  {:<47}  {ascii}",
                    i * 16,
                    hex.join(" ")
                )));
            }
        }
    }
    if data.len() > shown.len() {
        lines.push(Line::styled(
            format!("… {} more bytes not shown", data.len() - shown.len()),
            Style::default().fg(MUTED),
        ));
    }
}

fn render_paragraph(
    frame: &mut Frame,
    area: Rect,
    title: &str,
    lines: Vec<Line<'static>>,
    scroll: u16,
) {
    let lines_len = u16::try_from(lines.len()).unwrap_or(u16::MAX);
    frame.render_widget(
        Paragraph::new(lines)
            .block(pane(title))
            .scroll((scroll.min(lines_len.saturating_sub(1)), 0))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn kv(label: &str, value: impl Into<String>) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{label}: "), Style::default().fg(MUTED)),
        Span::styled(value.into(), Style::default().add_modifier(Modifier::BOLD)),
    ])
}

fn section(label: &str) -> Line<'static> {
    Line::styled(
        format!("─ {label} ─"),
        Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
    )
}

/// Pack as many `<key> description` hints as fit in `width` columns, dropping
/// from the end so the most important hints come first in `items`.
fn hint_line(items: &[(&str, &str)], width: u16) -> Line<'static> {
    let mut spans = vec![Span::raw(" ")];
    let mut used = 1usize;
    for (key, desc) in items {
        let need = key.chars().count() + desc.chars().count() + 4;
        if used + need > width as usize {
            break;
        }
        used += need;
        spans.push(Span::styled(
            format!(" {key} "),
            Style::default().fg(Color::Black).bg(MUTED),
        ));
        spans.push(Span::styled(
            format!(" {desc} "),
            Style::default().fg(MUTED),
        ));
    }
    Line::from(spans)
}

fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    let contextual: &[(&str, &str)] = match app.tab {
        NODE => &[("i", "zone")],
        ROUTING => &[("↑↓", "select route")],
        SERVICES => &[("enter", "check"), ("e", "edit"), ("R", "reload")],
        TNS => &[("enter", "resolve"), ("a", "add"), ("d", "remove")],
        DHT => &[("p", "put"), ("g", "get"), ("enter", "re-get")],
        _ => &[("/", "lookup"), ("i", "zone")],
    };
    let global: &[(&str, &str)] = &[
        ("q", "quit"),
        ("r", "refresh"),
        ("←→", "tabs"),
        ("1-6", "jump"),
        ("↑↓", "select"),
        ("PgUp/Dn", "scroll"),
    ];
    let row = |n: u16| Rect {
        y: area.y + n,
        height: 1,
        ..area
    };
    if area.height >= 3 {
        frame.render_widget(Paragraph::new(hint_line(contextual, area.width)), row(0));
        frame.render_widget(Paragraph::new(hint_line(global, area.width)), row(1));
    } else {
        let all: Vec<_> = contextual.iter().chain(global).copied().collect();
        frame.render_widget(Paragraph::new(hint_line(&all, area.width)), row(0));
    }
    let (message, style) = if let Some(input) = &app.input {
        let prefix = format!(" {}: ", input.label());
        let suffix = "█";
        let help = "   enter confirm · esc cancel";
        let text = super::input_text(input);
        // Keep the cursor visible: show the tail of long input (e.g. a
        // pasted 128-char handle) and drop the help text if it won't fit.
        let room = (area.width as usize).saturating_sub(prefix.chars().count() + suffix.len() + 1);
        let help = if room > text.chars().count() + help.chars().count() {
            help
        } else {
            ""
        };
        let room = room.saturating_sub(help.chars().count());
        let skip = text.chars().count().saturating_sub(room);
        let shown: String = text.chars().skip(skip).collect();
        (
            format!("{prefix}{shown}{suffix}{help}"),
            Style::default().fg(CYAN).add_modifier(Modifier::BOLD),
        )
    } else if app.message.is_empty() {
        (" Ready".to_string(), Style::default().fg(MUTED))
    } else {
        let bad = app.message.contains("failed")
            || app.message.contains("Invalid")
            || app.message.contains("not found");
        (
            format!(" {}", app.message),
            Style::default().fg(if bad { RED } else { GREEN }),
        )
    };
    frame.render_widget(Paragraph::new(message).style(style), row(area.height - 1));
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
