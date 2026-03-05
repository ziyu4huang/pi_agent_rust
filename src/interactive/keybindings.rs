use super::commands::model_entry_matches;
use super::*;

impl PiApp {
    /// Format keyboard shortcuts for /hotkeys display.
    ///
    /// Groups actions by category and shows their key bindings.
    pub(super) fn format_hotkeys(&self) -> String {
        use crate::keybindings::ActionCategory;
        use std::fmt::Write;

        let mut output = String::new();
        let _ = writeln!(output, "Keyboard Shortcuts");
        let _ = writeln!(output, "==================");
        let _ = writeln!(output);
        let _ = writeln!(
            output,
            "Config: {}",
            KeyBindings::user_config_path().display()
        );
        let _ = writeln!(output);

        for category in ActionCategory::all() {
            let actions: Vec<_> = self.keybindings.iter_category(*category).collect();

            // Skip empty categories
            if actions.iter().all(|(_, bindings)| bindings.is_empty()) {
                continue;
            }

            let _ = writeln!(output, "## {}", category.display_name());
            let _ = writeln!(output);

            for (action, bindings) in actions {
                if bindings.is_empty() {
                    continue;
                }

                // Format bindings as comma-separated list
                let keys: Vec<_> = bindings
                    .iter()
                    .map(std::string::ToString::to_string)
                    .collect();
                let keys_str = keys.join(", ");

                let _ = writeln!(output, "  {:20} {}", keys_str, action.display_name());
            }
            let _ = writeln!(output);
        }

        output
    }

    pub(super) fn resolve_action(&self, candidates: &[AppAction]) -> Option<AppAction> {
        let &first = candidates.first()?;

        // Some bindings are ambiguous and depend on UI state.
        // Example: `ctrl+d` can mean "delete forward" while editing, but "exit" when the editor
        // is empty (legacy behavior).
        if candidates.contains(&AppAction::Exit)
            && self.agent_state == AgentState::Idle
            && self.input.value().is_empty()
        {
            return Some(AppAction::Exit);
        }

        Some(first)
    }

    pub(super) fn handle_capability_prompt_key(&mut self, key: &KeyMsg) -> Option<Cmd> {
        let prompt = self.capability_prompt.as_mut()?;

        match key.key_type {
            // Navigate between buttons.
            KeyType::Right | KeyType::Tab => prompt.focus_next(),
            KeyType::Left => prompt.focus_prev(),
            KeyType::Runes if key.runes == ['l'] => prompt.focus_next(),
            KeyType::Runes if key.runes == ['h'] => prompt.focus_prev(),

            // Confirm selection.
            KeyType::Enter => {
                let action = prompt.selected_action();
                let response = ExtensionUiResponse {
                    id: prompt.request.id.clone(),
                    value: Some(Value::Bool(action.is_allow())),
                    cancelled: false,
                };
                // Record persistent decisions for "Always" choices.
                if action.is_persistent() {
                    if let Ok(mut store) = crate::permissions::PermissionStore::open_default() {
                        let _ = store.record(
                            &prompt.extension_id,
                            &prompt.capability,
                            action.is_allow(),
                        );
                    }
                }
                self.capability_prompt = None;
                self.send_extension_ui_response(response);
            }

            // Escape = deny once.
            KeyType::Esc => {
                let response = ExtensionUiResponse {
                    id: prompt.request.id.clone(),
                    value: Some(Value::Bool(false)),
                    cancelled: true,
                };
                self.capability_prompt = None;
                self.send_extension_ui_response(response);
            }

            _ => {}
        }

        None
    }

    pub(super) fn handle_paste_event(&mut self, key: &KeyMsg) -> bool {
        if key.key_type != KeyType::Runes || key.runes.is_empty() {
            return false;
        }

        let pasted: String = key.runes.iter().collect();
        let Some((insert, count)) = self.normalize_pasted_paths(&pasted) else {
            return false;
        };

        self.input.insert_string(&insert);
        if count > 0 {
            self.status_message = Some(format!(
                "Attached {} file{}",
                count,
                if count == 1 { "" } else { "s" }
            ));
        }
        true
    }

    fn normalize_pasted_paths(&self, pasted: &str) -> Option<(String, usize)> {
        let mut refs = Vec::new();
        for line in pasted.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let path = self.normalize_pasted_path(trimmed)?;
            refs.push(path);
        }

        if refs.is_empty() {
            return None;
        }

        let mut insert = refs
            .iter()
            .map(|path| format_file_ref(path))
            .collect::<Vec<_>>()
            .join(" ");
        if !insert.ends_with(' ') {
            insert.push(' ');
        }

        Some((insert, refs.len()))
    }

    fn normalize_pasted_path(&self, raw: &str) -> Option<String> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.starts_with('@') {
            return None;
        }

        let unquoted = strip_wrapping_quotes(trimmed);
        let unescaped = unescape_dragged_path(unquoted);
        let path = file_url_to_path(&unescaped).unwrap_or_else(|| PathBuf::from(&unescaped));
        let resolved = resolve_read_path(path.to_string_lossy().as_ref(), &self.cwd);
        if !resolved.exists() {
            return None;
        }

        Some(path_for_display(&resolved, &self.cwd))
    }

    pub(super) fn insert_file_ref_path(&mut self, path: &Path) {
        let display = path_for_display(path, &self.cwd);
        let mut insert_text = format_file_ref(&display);
        if !insert_text.ends_with(' ') {
            insert_text.push(' ');
        }
        self.input.insert_string(&insert_text);
    }

    #[allow(clippy::missing_const_for_fn)]
    pub(super) fn paste_image_from_clipboard() -> Option<PathBuf> {
        #[cfg(all(feature = "clipboard", feature = "image-resize"))]
        {
            use image::ImageEncoder;

            let mut clipboard = ArboardClipboard::new().ok()?;
            let image = clipboard.get_image().ok()?;

            let width = u32::try_from(image.width).ok()?;
            let height = u32::try_from(image.height).ok()?;
            let bytes = image.bytes.into_owned();
            let width_usize = usize::try_from(width).ok()?;
            let height_usize = usize::try_from(height).ok()?;
            let expected = width_usize.checked_mul(height_usize)?.checked_mul(4)?;
            if bytes.len() != expected {
                return None;
            }

            let mut temp_file = tempfile::Builder::new()
                .prefix("pi-paste-")
                .suffix(".png")
                .tempfile()
                .ok()?;
            let encoder = image::codecs::png::PngEncoder::new(&mut temp_file);
            if encoder
                .write_image(&bytes, width, height, image::ExtendedColorType::Rgba8)
                .is_err()
            {
                return None;
            }
            let (_file, path) = temp_file.keep().ok()?;
            Some(path)
        }

        #[cfg(not(all(feature = "clipboard", feature = "image-resize")))]
        {
            None
        }
    }

    /// Open external editor with current input text.
    ///
    /// Uses $VISUAL if set, otherwise $EDITOR, otherwise "vi".
    /// Supports editors with arguments like "code --wait" or "vim -u NONE".
    pub(super) fn open_external_editor(&self) -> std::io::Result<String> {
        use std::io::Write;

        // Determine editor command
        let editor = std::env::var("VISUAL")
            .or_else(|_| std::env::var("EDITOR"))
            .unwrap_or_else(|_| "vi".to_string());

        // Create temp file with current editor content
        let mut temp_file = tempfile::NamedTempFile::new()?;
        let current_text = self.input.value();
        temp_file.write_all(current_text.as_bytes())?;
        temp_file.flush()?;

        let temp_path = temp_file.path().to_path_buf();

        // Pause terminal UI so the external editor can use the terminal correctly
        let _ = crossterm::terminal::disable_raw_mode();
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::LeaveAlternateScreen);

        // Spawn editor via shell to handle EDITOR with arguments (e.g., "code --wait")
        // The shell properly handles quoting, arguments, and PATH lookup
        #[cfg(unix)]
        let status = std::process::Command::new("sh")
            .args(["-c", &format!("{editor} \"$1\"")])
            .arg("--") // separator for positional args
            .arg(&temp_path)
            .status();

        #[cfg(not(unix))]
        let status = std::process::Command::new("cmd")
            .args(["/c", &format!("{} \"{}\"", editor, temp_path.display())])
            .status();

        // Resume terminal UI
        let _ = crossterm::execute!(std::io::stdout(), crossterm::terminal::EnterAlternateScreen);
        let _ = crossterm::terminal::enable_raw_mode();
        let _ = crossterm::execute!(
            std::io::stdout(),
            crossterm::terminal::Clear(crossterm::terminal::ClearType::All)
        );

        let status = status?;

        if !status.success() {
            return Err(std::io::Error::other(format!(
                "Editor exited with status: {status}"
            )));
        }

        // Read back the edited content
        let new_text = std::fs::read_to_string(&temp_path)?;
        Ok(new_text)
    }

    /// Navigate to previous history entry.
    fn navigate_history_back(&mut self) {
        if !self.history.has_entries() {
            return;
        }

        self.history.cursor_up();
        self.apply_history_selection();
    }

    /// Navigate to next history entry.
    fn navigate_history_forward(&mut self) {
        // Avoid clearing the editor when the user hasn't entered history navigation.
        if self.history.cursor_is_empty() {
            return;
        }

        self.history.cursor_down();
        self.apply_history_selection();
    }

    fn apply_history_selection(&mut self) {
        let selected = self.history.selected_value();
        if selected.is_empty() {
            self.input.reset();
        } else {
            self.input.set_value(selected);
        }
    }

    fn handle_double_escape_action(&mut self) -> (bool, Option<Cmd>) {
        let now = std::time::Instant::now();
        if let Some(last_time) = self.last_escape_time {
            if now.duration_since(last_time) < std::time::Duration::from_millis(500) {
                self.last_escape_time = None;
                return (true, self.trigger_double_escape_action());
            }
        }
        self.last_escape_time = Some(now);
        (false, None)
    }

    fn trigger_double_escape_action(&mut self) -> Option<Cmd> {
        let raw_action = self
            .config
            .double_escape_action
            .as_deref()
            .unwrap_or("tree")
            .trim();
        let action = raw_action.to_ascii_lowercase();
        match action.as_str() {
            "tree" => self.handle_slash_command(SlashCommand::Tree, ""),
            "fork" => self.handle_slash_command(SlashCommand::Fork, ""),
            _ => {
                self.status_message = Some(format!(
                    "Unknown doubleEscapeAction: {raw_action} (expected tree or fork)"
                ));
                self.handle_slash_command(SlashCommand::Tree, "")
            }
        }
    }

    #[allow(clippy::too_many_lines)]
    pub fn cycle_model(&mut self, delta: i32) {
        if self.agent_state != AgentState::Idle {
            self.status_message = Some("Cannot switch models while processing".to_string());
            return;
        }

        let scope_configured = self
            .config
            .enabled_models
            .as_ref()
            .is_some_and(|patterns| !patterns.is_empty());
        let use_scope = scope_configured || !self.model_scope.is_empty();
        let mut fell_back_to_available = false;
        let mut candidates = if use_scope {
            self.model_scope.clone()
        } else {
            self.available_models.clone()
        };
        if use_scope && candidates.is_empty() {
            candidates.clone_from(&self.available_models);
            fell_back_to_available = true;
        }

        candidates.sort_by(|a, b| {
            let left = format!("{}/{}", a.model.provider, a.model.id);
            let right = format!("{}/{}", b.model.provider, b.model.id);
            left.cmp(&right)
        });
        candidates.dedup_by(|left, right| model_entry_matches(left, right));

        if candidates.is_empty() {
            self.status_message = Some("No models available".to_string());
            return;
        }

        let current_index = candidates
            .iter()
            .position(|entry| model_entry_matches(entry, &self.model_entry));

        let next_index = current_index.map_or_else(
            || {
                if delta >= 0 { 0 } else { candidates.len() - 1 }
            },
            |idx| {
                if delta >= 0 {
                    (idx + 1) % candidates.len()
                } else {
                    idx.checked_sub(1).unwrap_or(candidates.len() - 1)
                }
            },
        );

        let next = candidates[next_index].clone();

        if model_entry_matches(&next, &self.model_entry) {
            self.status_message = Some(if use_scope && !fell_back_to_available {
                "Only one model in scope".to_string()
            } else {
                "Only one model available".to_string()
            });
            return;
        }

        let provider_impl = match providers::create_provider(&next, self.extensions.as_ref()) {
            Ok(provider_impl) => provider_impl,
            Err(err) => {
                self.status_message = Some(err.to_string());
                return;
            }
        };
        let resolved_key_opt = super::commands::resolve_model_key_from_default_auth(&next);
        if super::commands::model_requires_configured_credential(&next)
            && resolved_key_opt.is_none()
        {
            self.status_message = Some(format!(
                "Missing credentials for provider {}. Run /login {}.",
                next.model.provider, next.model.provider
            ));
            return;
        }

        let Ok(mut agent_guard) = self.agent.try_lock() else {
            self.status_message = Some("Agent busy; try again".to_string());
            return;
        };
        agent_guard.set_provider(provider_impl);
        agent_guard
            .stream_options_mut()
            .api_key
            .clone_from(&resolved_key_opt);
        agent_guard
            .stream_options_mut()
            .headers
            .clone_from(&next.headers);
        drop(agent_guard);

        let Ok(mut session_guard) = self.session.try_lock() else {
            self.status_message = Some("Session busy; try again".to_string());
            return;
        };
        session_guard.header.provider = Some(next.model.provider.clone());
        session_guard.header.model_id = Some(next.model.id.clone());
        session_guard.append_model_change(next.model.provider.clone(), next.model.id.clone());
        drop(session_guard);
        self.spawn_save_session();

        self.model_entry = next.clone();
        if let Ok(mut guard) = self.model_entry_shared.lock() {
            *guard = next;
        }
        self.model = format!(
            "{}/{}",
            self.model_entry.model.provider, self.model_entry.model.id
        );
        self.status_message = Some(if fell_back_to_available {
            format!(
                "No scoped models matched; cycling all available models. Switched model: {}",
                self.model
            )
        } else {
            format!("Switched model: {}", self.model)
        });
    }

    pub(super) fn quit_cmd(&mut self) -> Cmd {
        if let Some(manager) = &self.extensions {
            manager.clear_ui_sender();
        }

        // Drop the async → bubbletea bridge sender so bubbletea can shut down cleanly.
        // Without this, bubbletea's external forwarder thread can block on `recv()` during quit.
        let _ = self.event_tx.try_send(PiMsg::UiShutdown);
        let (tx, _rx) = mpsc::channel::<PiMsg>(1);
        drop(std::mem::replace(&mut self.event_tx, tx));
        quit()
    }

    /// Handle an action dispatched from the keybindings layer.
    ///
    /// Returns `Some(Cmd)` if a command should be executed,
    /// `None` if the action was handled without a command.
    #[allow(clippy::too_many_lines)]
    pub(super) fn handle_action(&mut self, action: AppAction, key: &KeyMsg) -> Option<Cmd> {
        match action {
            // =========================================================
            // Application actions
            // =========================================================
            AppAction::Interrupt => {
                // Escape: Abort if processing, otherwise context-dependent
                if self.agent_state != AgentState::Idle {
                    self.last_escape_time = None;
                    let restored = self.restore_queued_messages_to_editor(true);
                    if restored > 0 {
                        self.status_message = Some(format!(
                            "Restored {restored} queued message{}",
                            if restored == 1 { "" } else { "s" }
                        ));
                    } else {
                        self.status_message = Some("Aborting request...".to_string());
                    }
                    return None;
                }
                if key.key_type == KeyType::Esc {
                    let (triggered, cmd) = self.handle_double_escape_action();
                    if triggered {
                        return cmd;
                    }
                }
                // When idle, Escape exits multi-line mode (but does NOT quit)
                if key.key_type == KeyType::Esc && self.input_mode == InputMode::MultiLine {
                    self.input_mode = InputMode::SingleLine;
                    self.set_input_height(3);
                    self.status_message = Some("Single-line mode".to_string());
                }
                // Legacy behavior: Escape when idle does nothing (no quit)
                None
            }
            AppAction::Clear | AppAction::Copy => {
                // Ctrl+C: abort if processing, clear editor if has text, or quit on double-tap
                // Note: Copy and Clear both bound to Ctrl+C - Copy takes precedence in lookup
                // When selection is implemented, Copy should only trigger with active selection
                if self.agent_state != AgentState::Idle {
                    if let Some(handle) = &self.abort_handle {
                        handle.abort();
                    }
                    self.status_message = Some("Aborting request...".to_string());
                    return None;
                }

                // If editor has text, clear it
                let editor_text = self.input.value();
                if !editor_text.is_empty() {
                    self.input.reset();
                    self.last_ctrlc_time = Some(std::time::Instant::now());
                    self.status_message = Some("Input cleared".to_string());
                    return None;
                }

                // Editor is empty - check for double-tap to quit
                let now = std::time::Instant::now();
                if let Some(last_time) = self.last_ctrlc_time {
                    // Double-tap within 500ms quits
                    if now.duration_since(last_time) < std::time::Duration::from_millis(500) {
                        return Some(self.quit_cmd());
                    }
                }
                // Record this Ctrl+C and show hint
                self.last_ctrlc_time = Some(now);
                self.status_message = Some("Press Ctrl+C again to quit".to_string());
                None
            }
            AppAction::PasteImage => {
                if let Some(path) = Self::paste_image_from_clipboard() {
                    self.insert_file_ref_path(&path);
                    self.status_message = Some("Image attached".to_string());
                }
                None
            }
            AppAction::Exit => {
                // Ctrl+D: Exit only when editor is empty (legacy behavior)
                if self.agent_state == AgentState::Idle && self.input.value().is_empty() {
                    return Some(self.quit_cmd());
                }
                // Editor has text - don't consume, let TextArea handle as delete char forward
                None
            }
            AppAction::Suspend => {
                // Ctrl+Z: Suspend to background (Unix only)
                #[cfg(unix)]
                {
                    use std::process::Command;
                    // Send SIGTSTP to our process. When resumed via `fg`, status() returns
                    // and we show the resumed message.
                    let pid = std::process::id().to_string();
                    let _ = Command::new("kill").args(["-TSTP", &pid]).status();
                    self.status_message = Some("Resumed from background".to_string());
                }
                #[cfg(not(unix))]
                {
                    self.status_message =
                        Some("Suspend not supported on this platform".to_string());
                }
                None
            }
            AppAction::ExternalEditor => {
                // Ctrl+G: Open external editor with current input
                if self.agent_state != AgentState::Idle {
                    self.status_message = Some("Cannot open editor while processing".to_string());
                    return None;
                }
                match self.open_external_editor() {
                    Ok(new_text) => {
                        self.input.set_value(&new_text);
                        self.status_message = Some("Editor content loaded".to_string());
                    }
                    Err(e) => {
                        self.status_message = Some(format!("Editor error: {e}"));
                    }
                }
                None
            }
            AppAction::Help => self.handle_slash_command(SlashCommand::Help, ""),
            AppAction::OpenSettings => self.handle_slash_command(SlashCommand::Settings, ""),

            // =========================================================
            // Models & thinking
            // =========================================================
            AppAction::CycleModelForward => {
                self.cycle_model(1);
                None
            }
            AppAction::CycleModelBackward => {
                self.cycle_model(-1);
                None
            }
            AppAction::SelectModel => {
                self.open_model_selector_configured_only();
                None
            }

            // =========================================================
            // Text input actions
            // =========================================================
            AppAction::Submit => {
                // Enter: Submit when idle, queue steering when busy
                if self.agent_state != AgentState::Idle {
                    self.queue_input(QueuedMessageKind::Steering);
                    return None;
                }
                if self.input_mode == InputMode::MultiLine {
                    // In multi-line mode, Enter inserts a newline (Alt+Enter submits).
                    self.input.insert_rune('\n');
                    return None;
                }
                let value = self.input.value();
                if !value.trim().is_empty() {
                    return self.submit_message(value.trim());
                }
                // Don't consume - let TextArea handle Enter if needed
                None
            }
            AppAction::FollowUp => {
                // Alt+Enter: queue follow-up when busy. When idle, toggles multi-line mode if the
                // editor is empty; otherwise it submits like Enter.
                if self.agent_state != AgentState::Idle {
                    self.queue_input(QueuedMessageKind::FollowUp);
                    return None;
                }
                let value = self.input.value();
                if self.input_mode == InputMode::SingleLine && value.trim().is_empty() {
                    self.input_mode = InputMode::MultiLine;
                    self.set_input_height(6);
                    self.status_message = Some("Multi-line mode".to_string());
                    return None;
                }
                if !value.trim().is_empty() {
                    return self.submit_message(value.trim());
                }
                None
            }
            AppAction::NewLine => {
                self.input.insert_rune('\n');
                self.input_mode = InputMode::MultiLine;
                self.set_input_height(6);
                None
            }

            // =========================================================
            // Cursor movement (history navigation in single-line mode)
            // =========================================================
            AppAction::CursorUp => {
                if self.agent_state == AgentState::Idle && self.input_mode == InputMode::SingleLine
                {
                    self.navigate_history_back();
                }
                // In multi-line mode, let TextArea handle cursor movement
                None
            }
            AppAction::CursorDown => {
                if self.agent_state == AgentState::Idle && self.input_mode == InputMode::SingleLine
                {
                    self.navigate_history_forward();
                }
                None
            }

            // =========================================================
            // Viewport scrolling
            // =========================================================
            AppAction::PageUp => {
                // Sync viewport content and height so page_up() has correct
                // line count and page size.  Save/restore y_offset across
                // set_content() which can clamp or reset the offset.
                let saved_offset = self.conversation_viewport.y_offset();
                let content = self.build_conversation_content();
                let effective = self.view_effective_conversation_height().max(1);
                self.conversation_viewport.height = effective;
                self.conversation_viewport.set_content(content.trim_end());
                self.conversation_viewport.set_y_offset(saved_offset);
                self.conversation_viewport.page_up();
                self.follow_stream_tail = false;
                None
            }
            AppAction::PageDown => {
                // Sync viewport content and height so page_down() has correct
                // line count and page size.  Save/restore y_offset across
                // set_content() which can clamp or reset the offset.
                let saved_offset = self.conversation_viewport.y_offset();
                let content = self.build_conversation_content();
                let effective = self.view_effective_conversation_height().max(1);
                self.conversation_viewport.height = effective;
                self.conversation_viewport.set_content(content.trim_end());
                self.conversation_viewport.set_y_offset(saved_offset);
                self.conversation_viewport.page_down();
                // Re-enable auto-follow if the user scrolled back to the bottom.
                if self.is_at_bottom() {
                    self.follow_stream_tail = true;
                }
                None
            }

            // =========================================================
            // Autocomplete
            // =========================================================
            AppAction::Tab => {
                if self.agent_state != AgentState::Idle || self.session_picker.is_some() {
                    return None;
                }

                let text = self.input.value();
                if text.trim().is_empty() {
                    self.autocomplete.close();
                    return None;
                }

                let cursor = self.input.cursor_byte_offset();
                let response = self.autocomplete.provider.suggest(&text, cursor);

                if response.items.is_empty() {
                    self.autocomplete.close();
                    return None;
                }

                if response.items.len() == 1
                    && response
                        .items
                        .first()
                        .is_some_and(|item| item.kind == AutocompleteItemKind::Path)
                {
                    let item = response.items[0].clone();
                    self.autocomplete.replace_range = response.replace;
                    self.accept_autocomplete(&item);
                    self.autocomplete.close();
                    return None;
                }

                self.autocomplete.open_with(response);
                None
            }

            // =========================================================
            // Message queue actions
            // =========================================================
            AppAction::Dequeue => {
                let restored = self.restore_queued_messages_to_editor(false);
                if restored == 0 {
                    self.status_message = Some("No queued messages to restore".to_string());
                } else {
                    self.status_message = Some(format!(
                        "Restored {restored} queued message{}",
                        if restored == 1 { "" } else { "s" }
                    ));
                }
                None
            }

            // =========================================================
            // Display actions
            // =========================================================
            AppAction::ToggleThinking => {
                self.thinking_visible = !self.thinking_visible;
                self.message_render_cache.invalidate_all();
                let content = self.build_conversation_content();
                let effective = self.view_effective_conversation_height().max(1);
                self.conversation_viewport.height = effective;
                self.conversation_viewport.set_content(content.trim_end());
                self.status_message = Some(if self.thinking_visible {
                    "Thinking shown".to_string()
                } else {
                    "Thinking hidden".to_string()
                });
                None
            }
            AppAction::ExpandTools => {
                self.tools_expanded = !self.tools_expanded;
                // When expanding globally, also reset per-message collapse for
                // all tools so they show expanded. When collapsing globally,
                // the global flag is enough (render checks both).
                if self.tools_expanded {
                    for msg in &mut self.messages {
                        if msg.role == MessageRole::Tool {
                            msg.collapsed = false;
                        }
                    }
                }
                self.message_render_cache.invalidate_all();
                let content = self.build_conversation_content();
                let effective = self.view_effective_conversation_height().max(1);
                self.conversation_viewport.height = effective;
                self.conversation_viewport.set_content(content.trim_end());
                self.status_message = Some(if self.tools_expanded {
                    "Tool output expanded".to_string()
                } else {
                    "Tool output collapsed".to_string()
                });
                None
            }

            // =========================================================
            // Branch navigation
            // =========================================================
            AppAction::BranchPicker => {
                self.open_branch_picker();
                None
            }
            AppAction::BranchNextSibling => {
                self.cycle_sibling_branch(true);
                None
            }
            AppAction::BranchPrevSibling => {
                self.cycle_sibling_branch(false);
                None
            }

            // =========================================================
            // Actions not yet implemented - let through to component
            // =========================================================
            _ => {
                // Many actions (editor operations, model cycling, etc.) will be
                // implemented in future PRs. For now, don't consume them.
                None
            }
        }
    }

    /// Determine if an action should be consumed (not forwarded to TextArea).
    ///
    /// Some actions need to be consumed even when `handle_action` returns `None`,
    /// to prevent the TextArea from also handling the key.
    pub(super) fn should_consume_action(&self, action: AppAction) -> bool {
        match action {
            // History navigation and Submit consume in single-line mode (otherwise TextArea
            // handles arrow keys or inserts a newline on Enter)
            AppAction::CursorUp | AppAction::CursorDown => {
                self.agent_state == AgentState::Idle && self.input_mode == InputMode::SingleLine
            }

            // Exit (Ctrl+D) only consumed when editor is empty (otherwise deleteCharForward)
            AppAction::Exit => {
                self.agent_state == AgentState::Idle && self.input.value().is_empty()
            }

            // Viewport scrolling should always be consumed.
            // FollowUp (Alt+Enter) should be consumed so TextArea doesn't insert text.
            // NewLine is handled directly (Shift+Enter / Ctrl+Enter).
            // Interrupt/Clear/Copy are always consumed.
            // Suspend/ExternalEditor are always consumed.
            // Tab is consumed (autocomplete).
            AppAction::PageUp
            | AppAction::PageDown
            | AppAction::CycleModelForward
            | AppAction::CycleModelBackward
            | AppAction::ToggleThinking
            | AppAction::ExpandTools
            | AppAction::FollowUp
            | AppAction::NewLine
            | AppAction::Submit
            | AppAction::Dequeue
            | AppAction::Interrupt
            | AppAction::Clear
            | AppAction::Copy
            | AppAction::PasteImage
            | AppAction::Suspend
            | AppAction::ExternalEditor
            | AppAction::Help
            | AppAction::OpenSettings
            | AppAction::Tab
            | AppAction::BranchPicker
            | AppAction::BranchNextSibling
            | AppAction::BranchPrevSibling
            | AppAction::SelectModel => true,

            // Other actions pass through to TextArea
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{Agent, AgentConfig};
    use crate::config::Config;
    use crate::model::{StreamEvent, Usage};
    use crate::models::ModelEntry;
    use crate::provider::{Context, InputType, Model, ModelCost, Provider, StreamOptions};
    use crate::resources::{ResourceCliOptions, ResourceLoader};
    use crate::session::Session;
    use crate::tools::ToolRegistry;
    use asupersync::channel::mpsc;
    use asupersync::runtime::RuntimeBuilder;
    use futures::stream;
    use std::collections::HashMap;
    use std::path::Path;
    use std::pin::Pin;
    use std::sync::Arc;
    use std::sync::OnceLock;

    struct DummyProvider;

    #[async_trait::async_trait]
    impl Provider for DummyProvider {
        fn name(&self) -> &'static str {
            "dummy"
        }

        fn api(&self) -> &'static str {
            "dummy"
        }

        fn model_id(&self) -> &'static str {
            "dummy-model"
        }

        async fn stream(
            &self,
            _context: &Context<'_>,
            _options: &StreamOptions,
        ) -> crate::error::Result<
            Pin<Box<dyn futures::Stream<Item = crate::error::Result<StreamEvent>> + Send>>,
        > {
            Ok(Box::pin(stream::empty()))
        }
    }

    fn runtime_handle() -> asupersync::runtime::RuntimeHandle {
        static RT: OnceLock<asupersync::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            RuntimeBuilder::multi_thread()
                .blocking_threads(1, 8)
                .build()
                .expect("build runtime")
        })
        .handle()
    }

    fn model_entry(
        provider: &str,
        id: &str,
        api_key: Option<&str>,
        headers: HashMap<String, String>,
    ) -> ModelEntry {
        ModelEntry {
            model: Model {
                id: id.to_string(),
                name: id.to_string(),
                api: "openai-completions".to_string(),
                provider: provider.to_string(),
                base_url: "https://example.invalid".to_string(),
                reasoning: true,
                input: vec![InputType::Text],
                cost: ModelCost {
                    input: 0.0,
                    output: 0.0,
                    cache_read: 0.0,
                    cache_write: 0.0,
                },
                context_window: 128_000,
                max_tokens: 8_192,
                headers: HashMap::new(),
            },
            api_key: api_key.map(str::to_string),
            headers,
            auth_header: true,
            compat: None,
            oauth_config: None,
        }
    }

    fn build_test_app(current: ModelEntry, available: Vec<ModelEntry>) -> PiApp {
        let provider: Arc<dyn Provider> = Arc::new(DummyProvider);
        let agent = Agent::new(
            provider,
            ToolRegistry::new(&[], Path::new("."), None),
            AgentConfig::default(),
        );
        let session = Arc::new(asupersync::sync::Mutex::new(Session::in_memory()));
        let resources = ResourceLoader::empty(false);
        let resource_cli = ResourceCliOptions {
            no_skills: false,
            no_prompt_templates: false,
            no_extensions: false,
            no_themes: false,
            skill_paths: Vec::new(),
            prompt_paths: Vec::new(),
            extension_paths: Vec::new(),
            theme_paths: Vec::new(),
        };
        let (event_tx, _event_rx) = mpsc::channel(64);
        PiApp::new(
            agent,
            session,
            Config::default(),
            resources,
            resource_cli,
            Path::new(".").to_path_buf(),
            current,
            Vec::new(),
            available,
            Vec::new(),
            event_tx,
            runtime_handle(),
            true,
            None,
            Some(KeyBindings::new()),
            Vec::new(),
            Usage::default(),
        )
    }

    #[test]
    fn cycle_model_replaces_stream_options_api_key_and_headers() {
        let mut current_headers = HashMap::new();
        current_headers.insert("x-stale".to_string(), "old".to_string());
        let current = model_entry("openai", "gpt-4o-mini", Some("old-key"), current_headers);

        let mut next_headers = HashMap::new();
        next_headers.insert("x-provider-header".to_string(), "next".to_string());
        let next = model_entry(
            "openrouter",
            "openai/gpt-4o-mini",
            Some("next-key"),
            next_headers,
        );

        let mut app = build_test_app(current.clone(), vec![current, next]);
        {
            let mut guard = app.agent.try_lock().expect("agent lock");
            guard.stream_options_mut().api_key = Some("stale-key".to_string());
            guard
                .stream_options_mut()
                .headers
                .insert("x-stale".to_string(), "stale".to_string());
        }

        app.cycle_model(1);

        let mut guard = app.agent.try_lock().expect("agent lock");
        assert_eq!(
            guard.stream_options_mut().api_key.as_deref(),
            Some("next-key")
        );
        assert_eq!(
            guard
                .stream_options_mut()
                .headers
                .get("x-provider-header")
                .map(String::as_str),
            Some("next")
        );
        assert!(
            !guard.stream_options_mut().headers.contains_key("x-stale"),
            "cycling models must replace stale provider headers"
        );
    }

    #[test]
    fn cycle_model_clears_stale_api_key_when_next_model_has_no_key() {
        let current = model_entry("openai", "gpt-4o-mini", Some("old-key"), HashMap::new());
        let mut next = model_entry("ollama", "llama3.2", None, HashMap::new());
        next.auth_header = false;
        let mut app = build_test_app(current.clone(), vec![current, next]);
        {
            let mut guard = app.agent.try_lock().expect("agent lock");
            guard.stream_options_mut().api_key = Some("stale-key".to_string());
            guard
                .stream_options_mut()
                .headers
                .insert("x-stale".to_string(), "stale".to_string());
        }

        app.cycle_model(1);

        let mut guard = app.agent.try_lock().expect("agent lock");
        assert!(
            guard.stream_options_mut().api_key.is_none(),
            "cycling to a keyless model must clear stale API key"
        );
        assert!(
            guard.stream_options_mut().headers.is_empty(),
            "cycling to keyless model with no headers must clear stale headers"
        );
    }

    #[test]
    fn slash_model_allows_switch_to_keyless_provider_without_api_key() {
        let current = model_entry("openai", "gpt-4o-mini", Some("old-key"), HashMap::new());
        let mut keyless = model_entry("ollama", "llama3.2", None, HashMap::new());
        keyless.auth_header = false;
        let mut app = build_test_app(current.clone(), vec![current, keyless]);

        let _ = app.handle_slash_command(SlashCommand::Model, "ollama/llama3.2");

        assert_eq!(app.model, "ollama/llama3.2");
        let mut guard = app.agent.try_lock().expect("agent lock");
        assert!(
            guard.stream_options_mut().api_key.is_none(),
            "keyless model switch must not keep stale API key"
        );
    }

    #[test]
    fn slash_model_rejects_missing_credentials_for_required_provider() {
        let current = model_entry("openai", "gpt-4o-mini", Some("old-key"), HashMap::new());
        let mut requires_creds = model_entry("acme-remote", "cloud-model", None, HashMap::new());
        requires_creds.auth_header = true;
        let mut app = build_test_app(current.clone(), vec![current, requires_creds]);

        let _ = app.handle_slash_command(SlashCommand::Model, "acme-remote/cloud-model");

        assert_eq!(app.model, "openai/gpt-4o-mini");
        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|msg| msg.contains("Missing credentials for provider acme-remote")),
            "switch should fail fast when selected provider still lacks credentials"
        );
    }

    #[test]
    fn slash_model_treats_blank_inline_key_as_missing_credentials() {
        let current = model_entry("openai", "gpt-4o-mini", Some("old-key"), HashMap::new());
        let mut blank_key = model_entry("acme-remote", "cloud-model", Some("   "), HashMap::new());
        blank_key.auth_header = true;
        let mut app = build_test_app(current.clone(), vec![current, blank_key]);

        let _ = app.handle_slash_command(SlashCommand::Model, "acme-remote/cloud-model");

        assert_eq!(app.model, "openai/gpt-4o-mini");
        assert!(
            app.status_message
                .as_deref()
                .is_some_and(|msg| msg.contains("Missing credentials for provider acme-remote")),
            "blank inline keys must not bypass credential checks"
        );
    }
}
