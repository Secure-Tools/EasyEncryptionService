use std::io;
use crossterm::{
    event::{self, Event, KeyCode},
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
    ExecutableCommand,
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use cli_clipboard::set_contents;

use crate::key_generator::{fetch_key_from_file, generate_rsa_key, save_key_to_file};
use crate::helper::{u8_to_string, check_priv_key_format};
use crate::hybrid_encryption::{decrypt_hybrid, encrypt_hybrid_name};
use crate::packer::{pack_message, pack_public_key, pack_signed_message, unpack_message, unpack_signed_message};
use crate::key_store::{delete_contact, list_contacts_vector, store, store_pub_priv_pair};
use crate::signature::{create_signature, verify_signature_name};

#[derive(PartialEq, Clone)]
enum Screen {
    Menu,
    Input,
    ContactList,
}

#[derive(Clone)]
enum Action {
    Generate,
    Encrypt,
    Decrypt,
    Store,
    Delete,
    List,
}

struct InputField {
    label: String,
    value: String,
}

pub struct App {
    menu_items: Vec<(String, Action)>,
    list_state: ListState,
    screen: Screen,
    input_fields: Vec<InputField>,
    active_field: usize,
    current_action: Option<Action>,
    output: String,
    should_quit: bool,
    contacts: Vec<(String, String)>,  // (name, pub_key)
    contact_state: ListState,
}

impl App {
    pub fn new() -> Self {
        let menu_items = vec![
            ("Generate RSA Keys".into(), Action::Generate),
            ("Encrypt Message".into(), Action::Encrypt),
            ("Decrypt Message".into(), Action::Decrypt),
            ("Store Public Key".into(), Action::Store),
            ("Delete Contact".into(), Action::Delete),
            ("List Contacts".into(), Action::List),
        ];
        let mut list_state = ListState::default();
        list_state.select(Some(0));

        Self {
            menu_items,
            list_state,
            screen: Screen::Menu,
            input_fields: vec![],
            active_field: 0,
            current_action: None,
            output: "Select an operation and press Enter.".into(),
            should_quit: false,
            contacts: vec![],
            contact_state: ListState::default(),
        }
    }

    fn selected(&self) -> usize {
        self.list_state.selected().unwrap_or(0)
    }

    fn next_menu(&mut self) {
        let i = (self.selected() + 1).min(self.menu_items.len() - 1);
        self.list_state.select(Some(i));
    }

    fn prev_menu(&mut self) {
        let i = self.selected().saturating_sub(1);
        self.list_state.select(Some(i));
    }

    fn select_action(&mut self) {
        let action = self.menu_items[self.selected()].1.clone();
        match action {
            // These need no input, run immediately
            Action::Generate => self.run_generate(),
            Action::List => self.run_list(),
            // These need input fields
            Action::Encrypt => {
                self.input_fields = vec![
                    InputField { label: "Message".into(), value: String::new() },
                    InputField { label: "Recipient name".into(), value: String::new() },
                    InputField { label: "Key file (.pkcs8)".into(), value: "private_key.pkcs8".into() },
                ];
                self.active_field = 0;
                self.current_action = Some(Action::Encrypt);
                self.screen = Screen::Input;
            }
            Action::Decrypt => {
                self.input_fields = vec![
                    InputField { label: "Encrypted text".into(), value: String::new() },
                    InputField { label: "Sender name".into(), value: String::new() },
                    InputField { label: "Key file (.pkcs8)".into(), value: "private_key.pkcs8".into() },
                ];
                self.active_field = 0;
                self.current_action = Some(Action::Decrypt);
                self.screen = Screen::Input;
            }
            Action::Store => {
                self.input_fields = vec![
                    InputField { label: "Contact name".into(), value: String::new() },
                    InputField { label: "Public key (base62)".into(), value: String::new() },
                ];
                self.active_field = 0;
                self.current_action = Some(Action::Store);
                self.screen = Screen::Input;
            }
            Action::Delete => {
                self.input_fields = vec![
                    InputField { label: "Contact name".into(), value: String::new() },
                ];
                self.active_field = 0;
                self.current_action = Some(Action::Delete);
                self.screen = Screen::Input;
            }
        }
    }

    fn submit_input(&mut self) {
        let result = match &self.current_action {
            Some(Action::Encrypt) => self.run_encrypt(),
            Some(Action::Decrypt) => self.run_decrypt(),
            Some(Action::Store) => self.run_store(),
            Some(Action::Delete) => self.run_delete(),
            _ => Ok("Unknown action".into()),
        };

        self.output = match result {
            Ok(msg) => msg,
            Err(e) => format!("Error: {e}"),
        };
        self.screen = Screen::Menu;
        self.input_fields.clear();
        self.current_action = None;
    }

    // --- Wired-up operations ---

    fn run_generate(&mut self) {
        let result = (|| -> anyhow::Result<String> {
            let priv_key_path = "private_key.pkcs8";
            let (pub_key, priv_key) = generate_rsa_key()?;
            save_key_to_file(priv_key_path, &priv_key)?;
            store_pub_priv_pair(&pack_public_key(&pub_key)?, priv_key_path);
            Ok("RSA key generation successful!\nPrivate key saved to private_key.pkcs8\nPublic key saved to keyring_yours.json".into())
        })();
        self.output = result.unwrap_or_else(|e| format!("Error: {e}"));
    }

    fn run_encrypt(&self) -> anyhow::Result<String> {
        let text = &self.input_fields[0].value;
        let name = &self.input_fields[1].value;
        let key_file = self.input_fields[2].value.trim();

        if !check_priv_key_format(key_file)? {
            anyhow::bail!("Invalid key file format");
        }
        let priv_key = fetch_key_from_file(key_file)?;
        let (cipher_text, nonce, enc_key) = encrypt_hybrid_name(text.as_bytes(), name.trim())?;
        let packed = pack_message(&cipher_text, nonce, &enc_key);
        let signature = create_signature(&packed, &priv_key)
            .map_err(|e| anyhow::anyhow!("Could not create signature: {e}"))?;
        let result = pack_signed_message(&packed, &signature);

        set_contents(result.clone()).ok();
        Ok(format!("Encrypted message:\n{result}"))
    }

    fn run_decrypt(&self) -> anyhow::Result<String> {
        let text = self.input_fields[0].value.trim();
        let name = &self.input_fields[1].value;
        let key_file = self.input_fields[2].value.trim();

        if !check_priv_key_format(key_file)? {
            anyhow::bail!("Invalid key file format");
        }
        let (unpacked, sig_bytes) = unpack_signed_message(text)?;
        let (cipher_text, nonce, enc_key) = unpack_message(&unpacked)?;
        verify_signature_name(&unpacked, &sig_bytes, name.trim())
            .map_err(|e| anyhow::anyhow!("Signature verification failed: {e}"))?;
        let decrypted = decrypt_hybrid(&cipher_text, nonce, &enc_key, &fetch_key_from_file(key_file)?)?;
        let plain = u8_to_string(decrypted)?;
        Ok(format!("Decrypted message: {plain}\nSignature verified ✓"))
    }

    fn run_store(&self) -> anyhow::Result<String> {
        let name = &self.input_fields[0].value;
        let pub_key = &self.input_fields[1].value;
        store(name.clone(), pub_key.clone(), "keyring.json");
        Ok(format!("Public key for '{name}' stored!"))
    }

    fn run_delete(&self) -> anyhow::Result<String> {
        let name = self.input_fields[0].value.trim();
        if delete_contact(name, "keyring.json") {
            Ok(format!("Contact '{name}' deleted!"))
        } else {
            Ok(format!("'{name}' not found in keyring"))
        }
    }

    fn run_list(&mut self) {
        // Your list_contacts_string should return Vec<(String, String)>
        // i.e. vec of (name, public_key) pairs
        let contacts = list_contacts_vector("keyring.json");
        if contacts.is_empty() {
            self.output = "No contacts in keyring.".into();
        } else {
            self.contacts = contacts;
            self.contact_state.select(Some(0));
            self.screen = Screen::ContactList;
        }
    }

    fn handle_key(&mut self, code: KeyCode) {
        match &self.screen {
            Screen::Menu => match code {
                KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
                KeyCode::Down | KeyCode::Char('j') => self.next_menu(),
                KeyCode::Up | KeyCode::Char('k') => self.prev_menu(),
                KeyCode::Enter => self.select_action(),
                _ => {}
            },
            Screen::Input => match code {
                KeyCode::Esc => {
                    self.screen = Screen::Menu;
                    self.input_fields.clear();
                }
                KeyCode::Tab => {
                    self.active_field = (self.active_field + 1) % self.input_fields.len();
                }
                KeyCode::BackTab => {
                    self.active_field = if self.active_field == 0 {
                        self.input_fields.len() - 1
                    } else {
                        self.active_field - 1
                    };
                }
                KeyCode::Enter => self.submit_input(),
                KeyCode::Backspace => {
                    self.input_fields[self.active_field].value.pop();
                }
                KeyCode::Char(c) => {
                    self.input_fields[self.active_field].value.push(c);
                }
                _ => {}
            },
            Screen::ContactList => match code {
                KeyCode::Esc | KeyCode::Char('q') => {
                    self.screen = Screen::Menu;
                    self.contacts.clear();
                }
                KeyCode::Down | KeyCode::Char('j') => {
                    let i = self.contact_state.selected().unwrap_or(0);
                    let next = (i + 1).min(self.contacts.len() - 1);
                    self.contact_state.select(Some(next));
                }
                KeyCode::Up | KeyCode::Char('k') => {
                    let i = self.contact_state.selected().unwrap_or(0);
                    self.contact_state.select(Some(i.saturating_sub(1)));
                }
                KeyCode::Enter => {
                    if let Some(i) = self.contact_state.selected() {
                        let pub_key = &self.contacts[i].1;
                        match set_contents(pub_key.clone()) {
                            Ok(_) => self.output = format!("Copied {}'s public key to clipboard ✓", self.contacts[i].0),
                            Err(_) => self.output = "⚠ Could not copy to clipboard".into(),
                        }
                        self.screen = Screen::Menu;
                        self.contacts.clear();
                    }
                }
                _ => {}
            },
        }
    }
}

fn draw(frame: &mut Frame, app: &mut App) {
    let outer = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(0), Constraint::Length(1)])
        .split(frame.area());

    let main_area = outer[0];
    let footer_area = outer[1];

    match app.screen {
        Screen::Menu => draw_menu(frame, app, main_area),
        Screen::Input => draw_input(frame, app, main_area),
        Screen::ContactList => draw_contacts(frame, app, main_area),
    }

    // Footer
    let hint = match app.screen {
        Screen::Menu => " ↑/↓ navigate │ Enter select │ q quit",
        Screen::Input => " Tab next field │ Shift+Tab prev │ Enter submit │ Esc back",
        Screen::ContactList => " ↑/↓ navigate │ Enter copy key │ Esc back",
    };
    let footer = Paragraph::new(hint).style(Style::default().fg(Color::DarkGray));
    frame.render_widget(footer, footer_area);
}

fn draw_contacts(frame: &mut Frame, app: &mut App, area: Rect) {
    let items: Vec<ListItem> = app
        .contacts
        .iter()
        .map(|(name, key)| {
            let preview = if key.len() > 40 {
                format!("{}...", &key[..40])
            } else {
                key.clone()
            };
            ListItem::new(format!("{name}  │  {preview}"))
        })
        .collect();

    let list = List::new(items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Contacts (Enter to copy key) "),
        )
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(list, area, &mut app.contact_state);
}

fn draw_menu(frame: &mut Frame, app: &mut App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
        .split(area);

    // Menu
    let items: Vec<ListItem> = app
        .menu_items
        .iter()
        .map(|(label, _)| ListItem::new(label.as_str()))
        .collect();

    let menu = List::new(items)
        .block(Block::default().borders(Borders::ALL).title(" EasyEncryptionService "))
        .highlight_style(
            Style::default()
                .bg(Color::DarkGray)
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
        )
        .highlight_symbol("▶ ");

    frame.render_stateful_widget(menu, chunks[0], &mut app.list_state);

    // Output
    let output = Paragraph::new(app.output.as_str())
        .block(Block::default().borders(Borders::ALL).title(" Output "))
        .wrap(Wrap { trim: true });

    frame.render_widget(output, chunks[1]);
}

fn draw_input(frame: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(
            app.input_fields
                .iter()
                .map(|_| Constraint::Length(3))
                .chain(std::iter::once(Constraint::Min(0)))
                .collect::<Vec<_>>(),
        )
        .split(area);

    for (i, field) in app.input_fields.iter().enumerate() {
        let style = if i == app.active_field {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default().fg(Color::White)
        };

        let border_style = if i == app.active_field {
            Style::default().fg(Color::Yellow)
        } else {
            Style::default()
        };

        let input = Paragraph::new(field.value.as_str())
            .style(style)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(border_style)
                    .title(format!(" {} ", field.label)),
            );

        frame.render_widget(input, chunks[i]);
    }
}

pub fn run() -> io::Result<()> {
    enable_raw_mode()?;
    io::stdout().execute(EnterAlternateScreen)?;

    let mut terminal = Terminal::new(CrosstermBackend::new(io::stdout()))?;
    let mut app = App::new();

    while !app.should_quit {
        terminal.draw(|frame| draw(frame, &mut app))?;

        if let Event::Key(key) = event::read()? {
            if key.kind == event::KeyEventKind::Press {
                app.handle_key(key.code);
            }
        }
    }

    disable_raw_mode()?;
    io::stdout().execute(LeaveAlternateScreen)?;
    Ok(())
}