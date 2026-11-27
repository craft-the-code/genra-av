//! Tray icon and the window's life: with "Canh gác" on, closing the window hides it and Genra keeps
//! guarding from the tray (menu: open, quit); with it off, closing quits as before. "Mở cùng máy"
//! starts Genra hidden at login (`--hidden`), so the guard runs without anyone opening it.

use std::sync::atomic::{AtomicBool, Ordering};
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Manager, Wry};

/// The argument the login item passes: start in the tray, window hidden.
pub const HIDDEN_ARG: &str = "--hidden";

/// The tray menu's items, kept to relabel them when the window's language changes.
pub struct Items {
    open: MenuItem<Wry>,
    quit: MenuItem<Wry>,
    /// The "still guarding in the tray" note was shown this session.
    told: AtomicBool,
}

fn labels(lang: &str) -> (&'static str, &'static str) {
    if lang == "en" {
        ("Open Genra AV", "Quit Genra AV")
    } else {
        ("Mở Genra AV", "Thoát Genra AV")
    }
}

/// Shows, unminimizes and focuses the main window.
pub fn show(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.unminimize();
        let _ = w.show();
        let _ = w.set_focus();
    }
}

pub fn setup(app: &AppHandle) -> tauri::Result<()> {
    let (o, q) = labels("vi");
    let open = MenuItem::with_id(app, "open", o, true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", q, true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &quit])?;
    let mut b = TrayIconBuilder::with_id("main")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .tooltip("Genra AV")
        .on_menu_event(|app, e| match e.id().as_ref() {
            "open" => show(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, e| {
            if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = e {
                show(tray.app_handle());
            }
        });
    // The menu bar wants a black template image that macOS tints; elsewhere the app icon.
    if cfg!(target_os = "macos") {
        b = b.icon(tauri::include_image!("icons/tray-template.png")).icon_as_template(true);
    } else if let Some(i) = app.default_window_icon() {
        b = b.icon(i.clone());
    }
    b.build(app)?;
    app.manage(Items { open, quit, told: AtomicBool::new(false) });
    Ok(())
}

/// Relabels the tray menu in the window's language.
pub fn relabel(app: &AppHandle, lang: &str) {
    if let Some(items) = app.try_state::<Items>() {
        let (o, q) = labels(lang);
        let _ = items.open.set_text(o);
        let _ = items.quit.set_text(q);
    }
}

/// The window's close button: hidden to the tray while the guard is on (once per session a
/// notification says so), closed for real otherwise.
pub fn on_close(window: &tauri::Window, api: &tauri::CloseRequestApi) {
    let app = window.app_handle();
    let guarding = app.try_state::<crate::AppState>().is_some_and(|s| s.guard_on.load(Ordering::SeqCst));
    if !guarding {
        return;
    }
    api.prevent_close();
    let _ = window.hide();
    if let Some(items) = app.try_state::<Items>() {
        if !items.told.swap(true, Ordering::SeqCst) {
            let lang = app.state::<crate::AppState>().lang();
            let (title, body) = if lang == "en" {
                ("Genra AV is still guarding", "It keeps checking new files in Downloads, Zalo and USB sticks. Quit from the tray icon.")
            } else {
                ("Genra AV vẫn đang canh gác", "Genra tiếp tục kiểm tra tệp mới trong Downloads, Zalo và USB. Thoát từ biểu tượng ở khay.")
            };
            use tauri_plugin_notification::NotificationExt;
            let _ = app.notification().builder().title(title).body(body).show();
        }
    }
}

/// Started by the login item: stay in the tray.
pub fn started_hidden() -> bool {
    std::env::args().any(|a| a == HIDDEN_ARG)
}

/// "Mở cùng máy": the OS login item follows the setting. Release builds only, so a development
/// build never registers itself.
pub fn sync_autostart(app: &AppHandle, on: bool) -> Result<bool, String> {
    if cfg!(debug_assertions) {
        return Ok(false);
    }
    use tauri_plugin_autostart::ManagerExt;
    let l = app.autolaunch();
    let now = l.is_enabled().map_err(|e| e.to_string())?;
    match (on, now) {
        (true, false) => l.enable().map_err(|e| e.to_string())?,
        (false, true) => l.disable().map_err(|e| e.to_string())?,
        _ => {}
    }
    l.is_enabled().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    #[test]
    fn labels() {
        assert_eq!(super::labels("vi"), ("Mở Genra AV", "Thoát Genra AV"));
        assert_eq!(super::labels("en").0, "Open Genra AV");
    }
}
