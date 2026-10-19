// Presentation-layer exceptions, each intentional:
// - float casts: progress fractions and human-readable sizes never approach
//   precision boundaries for realistic archive dimensions.
// - too_many_lines: dialog builders are flat widget sequences; splitting them
//   would scatter one form across helpers.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::too_many_lines
)]
//! Cinder GUI - a focused, friendly desktop archiver.
//!
//! Two modes, WinRAR-shaped but stripped down:
//! * **Browse** - the local filesystem; pick what to compress.
//! * **Archive** - an opened archive's members; select, extract, verify.
//!
//! All heavy work runs on background threads feeding a single UI job slot;
//! the native `.cnd` path streams real progress, foreign containers show a
//! busy indicator until done.

#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::collections::HashSet;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;

use eframe::egui;
use egui::{Color32, CornerRadius};
use egui_extras::{Column, TableBuilder};

use cinder_core::{
    extract_archive, extract_file, ArchiveReader, CompressOptions, ExtractOptions, Profile,
    ProgressEvent, SymlinkPolicy,
};

// ------------------------------------------------------------------ theme

const BG_PANEL: Color32 = Color32::from_rgb(0x12, 0x14, 0x19);
const BG_ELEVATED: Color32 = Color32::from_rgb(0x1A, 0x1D, 0x24);
const BG_CARD: Color32 = Color32::from_rgb(0x1D, 0x21, 0x29);
const EMBER: Color32 = Color32::from_rgb(0xE2, 0x58, 0x22);
const EMBER_SOFT: Color32 = Color32::from_rgb(0xFF, 0xB4, 0x8C);
const GREEN: Color32 = Color32::from_rgb(0x6F, 0xD6, 0x9A);
const TEXT_DIM: Color32 = Color32::from_rgb(0x9A, 0xA1, 0xAD);
const ERROR_TEXT: Color32 = Color32::from_rgb(0xF2, 0x7B, 0x68);

// Painted vector icons keep the UI stable across platforms and font packs.
// Unicode symbols looked acceptable on one machine but were inconsistent on
// Linux, Windows high-contrast mode, and mobile font fallbacks.
#[derive(Clone, Copy)]
enum UiIcon {
    Add,
    Open,
    Extract,
    Verify,
    Close,
    Tips,
    Search,
    Folder,
    File,
    Up,
    Lock,
}

fn apply_theme(ctx: &egui::Context) {
    ctx.all_styles_mut(|style| {
        let v = &mut style.visuals;
        *v = egui::Visuals::dark();
        v.panel_fill = BG_PANEL;
        v.window_fill = BG_ELEVATED;
        v.widgets.noninteractive.bg_fill = BG_CARD;
        v.extreme_bg_color = Color32::from_rgb(0x0C, 0x0E, 0x12);
        v.faint_bg_color = Color32::from_rgb(0x18, 0x1B, 0x21);
        v.selection.bg_fill = EMBER.gamma_multiply(0.45);
        v.selection.stroke = egui::Stroke::new(1.0, EMBER);
        v.widgets.hovered.bg_fill = Color32::from_rgb(0x22, 0x26, 0x2F);
        v.widgets.active.bg_fill = EMBER.gamma_multiply(0.55);
        v.widgets.inactive.bg_fill = Color32::from_rgb(0x1E, 0x21, 0x28);
        v.override_text_color = Some(Color32::from_rgb(0xDD, 0xE1, 0xE8));
        v.hyperlink_color = EMBER;
        v.window_stroke = egui::Stroke::new(1.0, Color32::from_rgb(0x2A, 0x2E, 0x37));
        v.window_corner_radius = CornerRadius::same(10);
        v.menu_corner_radius = CornerRadius::same(6);
        style.spacing.item_spacing = egui::vec2(9.0, 7.0);
        style.spacing.button_padding = egui::vec2(11.0, 6.0);
        style.spacing.window_margin = egui::Margin::same(18);
    });
}

fn ember_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    ui.add(
        egui::Button::new(egui::RichText::new(label).strong())
            .fill(EMBER)
            .corner_radius(CornerRadius::same(6)),
    )
}

fn paint_icon(painter: &egui::Painter, rect: egui::Rect, icon: UiIcon, color: Color32) {
    let stroke = egui::Stroke::new(1.7, color);
    let c = rect.center();
    let l = rect.left() + 2.0;
    let r = rect.right() - 2.0;
    let t = rect.top() + 2.0;
    let b = rect.bottom() - 2.0;
    match icon {
        UiIcon::Add => {
            painter.line_segment([egui::pos2(c.x, t), egui::pos2(c.x, b)], stroke);
            painter.line_segment([egui::pos2(l, c.y), egui::pos2(r, c.y)], stroke);
        }
        UiIcon::Open => {
            painter.line_segment([egui::pos2(l, b - 2.0), egui::pos2(l + 3.0, b)], stroke);
            painter.line_segment([egui::pos2(l + 3.0, b), egui::pos2(r, t + 2.0)], stroke);
            painter.line_segment(
                [egui::pos2(r, t + 2.0), egui::pos2(r - 5.0, t + 2.0)],
                stroke,
            );
            painter.line_segment([egui::pos2(r, t + 2.0), egui::pos2(r, t + 7.0)], stroke);
        }
        UiIcon::Extract => {
            painter.line_segment([egui::pos2(c.x, t), egui::pos2(c.x, b - 4.0)], stroke);
            painter.line_segment(
                [egui::pos2(c.x, b - 4.0), egui::pos2(c.x - 4.0, b - 8.0)],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(c.x, b - 4.0), egui::pos2(c.x + 4.0, b - 8.0)],
                stroke,
            );
            painter.line_segment([egui::pos2(l, b), egui::pos2(r, b)], stroke);
        }
        UiIcon::Verify => {
            painter.circle_stroke(c, 7.0, stroke);
            painter.line_segment(
                [egui::pos2(c.x - 3.5, c.y), egui::pos2(c.x - 1.0, c.y + 3.0)],
                stroke,
            );
            painter.line_segment(
                [
                    egui::pos2(c.x - 1.0, c.y + 3.0),
                    egui::pos2(c.x + 4.0, c.y - 3.0),
                ],
                stroke,
            );
        }
        UiIcon::Close => {
            painter.line_segment([egui::pos2(l, t), egui::pos2(r, b)], stroke);
            painter.line_segment([egui::pos2(r, t), egui::pos2(l, b)], stroke);
        }
        UiIcon::Tips => {
            painter.circle_stroke(c, 7.0, stroke);
            painter.text(
                c,
                egui::Align2::CENTER_CENTER,
                "?",
                egui::FontId::proportional(11.0),
                color,
            );
        }
        UiIcon::Search => {
            painter.circle_stroke(egui::pos2(c.x - 2.0, c.y - 2.0), 5.0, stroke);
            painter.line_segment([egui::pos2(c.x + 2.0, c.y + 2.0), egui::pos2(r, b)], stroke);
        }
        UiIcon::Folder => {
            painter.line_segment(
                [egui::pos2(l, t + 3.0), egui::pos2(l + 5.0, t + 3.0)],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(l + 5.0, t + 3.0), egui::pos2(l + 7.0, t + 5.0)],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(l + 7.0, t + 5.0), egui::pos2(r, t + 5.0)],
                stroke,
            );
            painter.line_segment([egui::pos2(r, t + 5.0), egui::pos2(r - 2.0, b)], stroke);
            painter.line_segment([egui::pos2(r - 2.0, b), egui::pos2(l, b)], stroke);
            painter.line_segment([egui::pos2(l, b), egui::pos2(l, t + 3.0)], stroke);
        }
        UiIcon::File => {
            painter.line_segment([egui::pos2(l + 2.0, t), egui::pos2(r - 3.0, t)], stroke);
            painter.line_segment([egui::pos2(r - 3.0, t), egui::pos2(r, t + 3.0)], stroke);
            painter.line_segment([egui::pos2(r, t + 3.0), egui::pos2(r, b)], stroke);
            painter.line_segment([egui::pos2(r, b), egui::pos2(l + 2.0, b)], stroke);
            painter.line_segment([egui::pos2(l + 2.0, b), egui::pos2(l + 2.0, t)], stroke);
            painter.line_segment(
                [egui::pos2(r - 3.0, t), egui::pos2(r - 3.0, t + 3.0)],
                stroke,
            );
        }
        UiIcon::Up => {
            painter.line_segment([egui::pos2(c.x, b), egui::pos2(c.x, t)], stroke);
            painter.line_segment([egui::pos2(c.x, t), egui::pos2(c.x - 4.0, t + 4.0)], stroke);
            painter.line_segment([egui::pos2(c.x, t), egui::pos2(c.x + 4.0, t + 4.0)], stroke);
        }
        UiIcon::Lock => {
            painter.rect_stroke(
                egui::Rect::from_min_max(egui::pos2(l, c.y), egui::pos2(r, b)),
                egui::CornerRadius::same(2),
                stroke,
                egui::StrokeKind::Inside,
            );
            painter.circle_stroke(egui::pos2(c.x, c.y), 5.0, stroke);
            painter.line_segment(
                [egui::pos2(c.x - 5.0, c.y), egui::pos2(c.x - 5.0, c.y - 4.0)],
                stroke,
            );
            painter.line_segment(
                [egui::pos2(c.x + 5.0, c.y), egui::pos2(c.x + 5.0, c.y - 4.0)],
                stroke,
            );
        }
    }
}

fn icon_slot(ui: &mut egui::Ui, icon: UiIcon, color: Color32) {
    let (rect, _) = ui.allocate_exact_size(egui::vec2(18.0, 18.0), egui::Sense::hover());
    paint_icon(ui.painter(), rect, icon, color);
}

fn icon_selectable_label(
    ui: &mut egui::Ui,
    selected: bool,
    icon: UiIcon,
    label: String,
    help: &str,
) -> egui::Response {
    ui.horizontal(|ui| {
        icon_slot(ui, icon, if selected { EMBER_SOFT } else { TEXT_DIM });
        ui.selectable_label(selected, label).on_hover_text(help)
    })
    .inner
}

fn action_button(
    ui: &mut egui::Ui,
    icon: UiIcon,
    label: &str,
    help: &str,
    primary: bool,
) -> egui::Response {
    let width = (label.chars().count() as f32 * 7.2 + 45.0).max(72.0);
    let enabled = ui.is_enabled();
    let fill = if primary { EMBER } else { BG_CARD };
    let fill = if enabled {
        fill
    } else {
        fill.gamma_multiply(0.45)
    };
    let icon_color = if primary { Color32::WHITE } else { EMBER_SOFT };
    let text_color = if enabled {
        Color32::from_rgb(0xEF, 0xF1, 0xF5)
    } else {
        TEXT_DIM
    };
    // Keep a native Button widget underneath the custom visuals. This gives
    // AccessKit/UI Automation a real button role and preserves keyboard
    // navigation while the painter supplies the consistent vector icon.
    let response = ui.add_sized(
        egui::vec2(width, 30.0),
        egui::Button::new(egui::RichText::new(label).color(Color32::TRANSPARENT))
            .fill(fill)
            .stroke(egui::Stroke::new(1.0, Color32::from_rgb(0x34, 0x39, 0x44)))
            .corner_radius(CornerRadius::same(7)),
    );
    let rect = response.rect;
    paint_icon(
        ui.painter(),
        egui::Rect::from_min_size(
            rect.left_top() + egui::vec2(8.0, 6.0),
            egui::vec2(18.0, 18.0),
        ),
        icon,
        if enabled { icon_color } else { TEXT_DIM },
    );
    ui.painter().text(
        rect.left_center() + egui::vec2(32.0, 0.0),
        egui::Align2::LEFT_CENTER,
        label,
        egui::FontId::proportional(13.0),
        text_color,
    );
    response.on_hover_text(help)
}

fn stat_card(ui: &mut egui::Ui, label: &str, value: &str, accent: Color32) {
    egui::Frame::new()
        .fill(BG_CARD)
        .corner_radius(CornerRadius::same(7))
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(label.to_uppercase())
                    .small()
                    .color(TEXT_DIM),
            );
            ui.label(egui::RichText::new(value).strong().color(accent));
        });
}

fn section_heading(ui: &mut egui::Ui, eyebrow: &str, title: &str, detail: &str) {
    ui.label(
        egui::RichText::new(eyebrow.to_uppercase())
            .small()
            .strong()
            .color(EMBER),
    );
    ui.heading(title);
    ui.label(egui::RichText::new(detail).color(TEXT_DIM));
}

fn tip(ui: &mut egui::Ui, title: &str, body: &str) {
    egui::Frame::group(ui.style())
        .fill(BG_CARD)
        .corner_radius(CornerRadius::same(8))
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.label(
                egui::RichText::new(format!("?  {title}"))
                    .strong()
                    .color(EMBER_SOFT),
            );
            ui.add_space(2.0);
            ui.label(egui::RichText::new(body).small().color(TEXT_DIM));
        });
}

// ------------------------------------------------------------------- jobs

enum JobEvent {
    Progress { fraction: f32, msg: String },
    Done(Result<String, String>),
}

struct Job {
    label: String,
    rx: Receiver<JobEvent>,
    progress: Option<(f32, String)>,
}

fn spawn_job(label: &str, work: impl FnOnce(Sender<JobEvent>) + Send + 'static) -> Job {
    let (tx, rx) = channel();
    std::thread::Builder::new()
        .name(format!("cinder-{label}"))
        .spawn(move || work(tx))
        .expect("job thread spawn");
    Job {
        label: label.to_string(),
        rx,
        progress: None,
    }
}

// --------------------------------------------------------------- dialogs

const OUT_FORMATS: [(&str, &str); 8] = [
    ("Cinder (.cnd)", ".cnd"),
    ("7-Zip", ".7z"),
    ("RAR", ".rar"),
    ("Zip", ".zip"),
    ("Tar", ".tar"),
    ("Tar + Gzip", ".tar.gz"),
    ("Tar + Zstandard", ".tar.zst"),
    ("Tar + XZ", ".tar.xz"),
];
const RAR_VERSIONS: [(&str, cinder_formats::RarVersion); 9] = [
    ("RAR 1.3", cinder_formats::RarVersion::Rar13),
    ("RAR 1.4", cinder_formats::RarVersion::Rar14),
    ("RAR 1.5", cinder_formats::RarVersion::Rar15),
    ("RAR 2.0", cinder_formats::RarVersion::Rar20),
    ("RAR 2.9", cinder_formats::RarVersion::Rar29),
    ("RAR 3.0", cinder_formats::RarVersion::Rar30),
    ("RAR 4.0", cinder_formats::RarVersion::Rar40),
    ("RAR 5.0", cinder_formats::RarVersion::Rar50),
    ("RAR 7.0", cinder_formats::RarVersion::Rar70),
];
const TIERS: [&str; 3] = ["fast", "balanced", "max"];

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn pick_archive_file(cwd: &Path) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .add_filter(
            "Archives",
            &[
                "cnd", "7z", "rar", "r00", "001", "zip", "tar", "gz", "tgz", "zst", "tzst", "xz",
                "txz",
            ],
        )
        .set_directory(cwd)
        .pick_file()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn pick_archive_file(_cwd: &Path) -> Option<PathBuf> {
    None
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn pick_source_files() -> Option<Vec<PathBuf>> {
    rfd::FileDialog::new().pick_files()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn pick_source_files() -> Option<Vec<PathBuf>> {
    None
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn pick_folder() -> Option<PathBuf> {
    rfd::FileDialog::new().pick_folder()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn pick_folder() -> Option<PathBuf> {
    None
}

#[cfg(not(any(target_os = "android", target_os = "ios")))]
fn save_archive_file(source: &str, ext: &str) -> Option<PathBuf> {
    rfd::FileDialog::new()
        .set_file_name(suggest_name(Path::new(source), ext))
        .save_file()
}

#[cfg(any(target_os = "android", target_os = "ios"))]
fn save_archive_file(_source: &str, _ext: &str) -> Option<PathBuf> {
    None
}

fn format_tooltips(idx: usize) -> &'static str {
    match idx {
        0 => "Cinder native format with dedup, encryption, and progress tracking",
        1 => "7-Zip archive with LZMA2 compression, solid grouping, and optional AES encryption",
        2 => "Choose RAR 1.3 through RAR 7. RAR 5/7 can also be split into portable volume sets.",
        3 => "Standard ZIP archive for wide compatibility",
        4 => "TAR archive - streaming extraction, no compression by default",
        5 => "TAR + Gzip - compressed TAR with gzip algorithm",
        6 => "TAR + Zstandard - compressed TAR with zstd algorithm (fast)",
        _ => "TAR + XZ - compact compressed TAR for long-term storage",
    }
}

#[derive(Clone)]
struct NewDialog {
    show: bool,
    source: String,
    sources: Vec<PathBuf>,
    dest: String,
    format_idx: usize,
    rar_version_idx: usize,
    rar_volume_size_mb: String,
    tier_idx: usize,
    solid: bool,
    encrypt: bool,
    replace_output: bool,
    pass1: String,
    pass2: String,
}

impl Default for NewDialog {
    fn default() -> Self {
        Self {
            show: false,
            source: String::new(),
            sources: Vec::new(),
            dest: String::new(),
            format_idx: 0,
            rar_version_idx: 7,
            rar_volume_size_mb: String::new(),
            tier_idx: 1,
            solid: true,
            encrypt: false,
            replace_output: false,
            pass1: String::new(),
            pass2: String::new(),
        }
    }
}

#[derive(Clone)]
struct ExtractDialog {
    show: bool,
    dest: String,
    overwrite: bool,
    scope_all: bool,
}

#[derive(Clone, Default)]
struct BatchExtractDialog {
    show: bool,
    archives: Vec<PathBuf>,
    destination: String,
    separate_folders: bool,
    overwrite: bool,
    passphrase: String,
}

#[derive(Clone, Default)]
struct MixedDropDialog {
    show: bool,
    archives: Vec<PathBuf>,
    sources: Vec<PathBuf>,
}

enum ShellRequest {
    Open(Vec<PathBuf>),
    Create(Vec<PathBuf>, usize),
    Extract(Vec<PathBuf>),
    ExtractHere(Vec<PathBuf>),
    ExtractTo(Vec<PathBuf>),
    Test(Vec<PathBuf>),
}

enum FileAction {
    Browse(PathBuf),
    Open(PathBuf),
    Create(Vec<PathBuf>, usize),
    ExtractHere(Vec<PathBuf>, bool),
    ExtractTo(Vec<PathBuf>),
    ExtractDialog(Vec<PathBuf>),
    Test(Vec<PathBuf>),
    Copy(String),
}

enum SelectionChange {
    Add(String),
    Remove(String),
    Replace(String),
}

enum MemberAction {
    Extract(HashSet<String>),
    ExtractAll,
    Test,
    Copy(String),
}

// ------------------------------------------------------------- app state

#[derive(Clone)]
struct Member {
    dir: bool,
    name: String,
    size: Option<u64>,
    packed: Option<u64>,
    modified: Option<String>,
}

struct ArchiveState {
    path: PathBuf,
    is_cinder: bool,
    encrypted: bool,
    members: Vec<Member>,
    selected: HashSet<String>,
}

pub struct CinderApp {
    cwd: PathBuf,
    address: String,
    filter: String,
    fs_rows: Vec<(bool, String, u64)>, // is_dir, name, size
    fs_selected: HashSet<String>,
    archive: Option<ArchiveState>,
    sort_col: usize, // 0 name, 1 size, 2 packed, 3 modified
    sort_desc: bool,
    status: String,
    status_is_error: bool,
    job: Option<Job>,
    new_dlg: NewDialog,
    xdlg: ExtractDialog,
    batch_dlg: BatchExtractDialog,
    mixed_drop: MixedDropDialog,
    error_popup: Option<String>,
    seen_drops: HashSet<PathBuf>,
    /// Set while an "open" job runs: (path, kind-label).
    pending_open: Option<(PathBuf, String)>,
    open_payload: String,
    arc_pass: String,
    show_tips: bool,
    startup_request: Option<ShellRequest>,
    startup_error: Option<String>,
}

impl Default for CinderApp {
    fn default() -> Self {
        Self::new()
    }
}

impl CinderApp {
    fn new() -> Self {
        let cwd = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
        let mut app = Self {
            address: cwd.display().to_string(),
            filter: String::new(),
            cwd,
            fs_rows: Vec::new(),
            fs_selected: HashSet::new(),
            archive: None,
            sort_col: 0,
            sort_desc: false,
            status: "Ready.".into(),
            status_is_error: false,
            job: None,
            new_dlg: NewDialog::default(),
            xdlg: ExtractDialog {
                show: false,
                dest: String::new(),
                overwrite: false,
                scope_all: true,
            },
            batch_dlg: BatchExtractDialog::default(),
            mixed_drop: MixedDropDialog::default(),
            error_popup: None,
            seen_drops: HashSet::new(),
            pending_open: None,
            open_payload: String::new(),
            arc_pass: String::new(),
            show_tips: true,
            startup_request: None,
            startup_error: None,
        };
        app.reload_fs();
        app
    }

    fn with_startup(request: Option<ShellRequest>, error: Option<String>) -> Self {
        let mut app = Self::new();
        app.startup_request = request;
        app.startup_error = error;
        app
    }

    fn reload_fs(&mut self) {
        self.fs_rows.clear();
        let Ok(rd) = fs::read_dir(&self.cwd) else {
            self.set_status_error(format!("Cannot read {}", self.cwd.display()));
            return;
        };
        for e in rd.flatten() {
            let Ok(md) = e.metadata() else { continue };
            self.fs_rows.push((
                md.is_dir(),
                e.file_name().to_string_lossy().into_owned(),
                if md.is_dir() { 0 } else { md.len() },
            ));
        }
        self.fs_rows
            .sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
        self.address = self.cwd.display().to_string();
    }

    fn navigate(&mut self, target: &Path) {
        if target.is_dir() {
            self.cwd = target.to_path_buf();
            self.fs_selected.clear();
            self.filter.clear();
            self.reload_fs();
            self.status_is_error = false;
            self.status = format!("Browsing {}", self.cwd.display());
        } else {
            self.set_status_error(format!("Not a directory: {}", target.display()));
        }
    }

    fn set_status_error(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_is_error = true;
    }

    fn set_status_ok(&mut self, msg: impl Into<String>) {
        self.status = msg.into();
        self.status_is_error = false;
    }

    // ---- archive lifecycle ----------------------------------------------

    fn open_archive(&mut self, path: &Path, passphrase: String) {
        let is_cinder = looks_like_cinder(path);
        let kind = if is_cinder {
            "Cinder".to_string()
        } else {
            cinder_formats::detect(path)
                .map_or_else(|| "unknown".to_string(), |f| f.label().to_string())
        };
        let path_buf = path.to_path_buf();

        self.arc_pass.clone_from(&passphrase);
        self.pending_open = Some((path_buf.clone(), kind));
        let job = spawn_job("open", move |tx| {
            let res = load_archive(&path_buf, &passphrase, is_cinder);
            let _ = tx.send(JobEvent::Done(res.map(|m| serialize_members(&m))));
        });
        self.job = Some(job);
    }

    fn poll_job(&mut self) {
        let Some(job) = self.job.as_mut() else { return };
        loop {
            match job.rx.try_recv() {
                Ok(JobEvent::Progress { fraction, msg }) => {
                    job.progress = Some((fraction.clamp(0.0, 1.0), msg));
                }
                Ok(JobEvent::Done(res)) => {
                    let label = job.label.clone();
                    self.job = None;
                    self.complete_job(&label, res);
                    return;
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => return,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                    self.job = None;
                    self.set_status_error("Worker vanished without a report.");
                    return;
                }
            }
        }
    }

    fn complete_job(&mut self, label: &str, res: Result<String, String>) {
        match res {
            Ok(msg) => {
                if label.starts_with("open") {
                    self.open_payload = msg;
                    self.finish_open();
                } else {
                    self.set_status_ok(msg);
                    let refresh_filesystem = label.starts_with("create")
                        || label.starts_with("compress")
                        || ((label.starts_with("extract") || label == "batch-extract")
                            && self.archive.is_none());
                    if refresh_filesystem {
                        self.reload_fs();
                    }
                }
            }
            Err(e) => {
                if e.trim() == "ENCRYPTED" {
                    let Some((path, kind)) = self.pending_open.take().or_else(|| {
                        self.archive.as_ref().map(|a| {
                            (
                                a.path.clone(),
                                if a.is_cinder {
                                    "Cinder".into()
                                } else {
                                    "other".into()
                                },
                            )
                        })
                    }) else {
                        return;
                    };
                    let is_cinder = kind == "Cinder";
                    self.archive = Some(ArchiveState {
                        path,
                        is_cinder,
                        encrypted: true,
                        members: Vec::new(),
                        selected: HashSet::new(),
                    });
                    self.open_payload.clear();
                    self.set_status_ok("Passphrase required - type it above and press Unlock.");
                } else {
                    self.pending_open = None;
                    self.error_popup = Some(e.clone());
                    self.set_status_error(e);
                }
            }
        }
    }

    fn finish_open(&mut self) {
        let payload = std::mem::take(&mut self.open_payload);
        let Some(members) = deserialize_members(&payload) else {
            self.set_status_error("Internal: member list arrived garbled.");
            return;
        };
        let Some((path, kind)) = self.pending_open.take() else {
            return;
        };
        self.archive = Some(ArchiveState {
            path,
            is_cinder: kind == "Cinder",
            encrypted: false,
            members,
            selected: HashSet::new(),
        });
        self.sort_col = 0;
        self.sort_desc = false;
        self.filter.clear();
        self.apply_sort();
        let n = self
            .archive
            .as_ref()
            .map_or(0, |a| a.members.iter().filter(|m| !m.dir).count());
        self.set_status_ok(format!("Opened - {n} members."));
    }

    fn apply_sort(&mut self) {
        let col = self.sort_col;
        let desc = self.sort_desc;
        if let Some(a) = self.archive.as_mut() {
            a.members.sort_by(|x, y| {
                x.dir.cmp(&y.dir).reverse().then_with(|| {
                    let ord = match col {
                        1 => x.size.unwrap_or(0).cmp(&y.size.unwrap_or(0)),
                        2 => x.packed.unwrap_or(0).cmp(&y.packed.unwrap_or(0)),
                        3 => x.modified.as_deref().cmp(&y.modified.as_deref()),
                        _ => x.name.cmp(&y.name),
                    };
                    if desc {
                        ord.reverse()
                    } else {
                        ord
                    }
                })
            });
        }
    }

    fn archive_path(&self) -> PathBuf {
        self.archive
            .as_ref()
            .map_or_else(PathBuf::new, |a| a.path.clone())
    }

    fn prepare_create(&mut self, mut sources: Vec<PathBuf>, format_idx: usize) {
        sources.retain(|path| path.exists());
        sources = unique_paths(sources);
        sources.sort_by_key(|path| path_identity(path));
        if sources.is_empty() {
            self.set_status_error("No readable files or folders were selected.");
            return;
        }
        self.new_dlg.sources = if sources.len() > 1 {
            sources.clone()
        } else {
            Vec::new()
        };
        self.new_dlg.source = sources[0].display().to_string();
        self.new_dlg.dest = suggest_dest_paths(&sources, format_idx);
        self.new_dlg.format_idx = format_idx;
        self.new_dlg.show = true;
    }

    fn prepare_batch_extract(&mut self, archives: Vec<PathBuf>, separate_folders: bool) {
        let archives = unique_archive_sets(archives);
        if archives.is_empty() {
            self.set_status_error("No supported archive files were found in that selection.");
            return;
        }
        let destination = common_parent(&archives).unwrap_or_else(|| self.cwd.clone());
        self.batch_dlg = BatchExtractDialog {
            show: true,
            archives,
            destination: destination.display().to_string(),
            separate_folders,
            overwrite: false,
            passphrase: String::new(),
        };
    }

    // ---- drag & drop ------------------------------------------------------

    fn handle_drops(&mut self, ctx: &egui::Context) {
        let dropped: Vec<PathBuf> = ctx
            .input(|i| i.raw.dropped_files.clone())
            .iter()
            .filter_map(|f| f.path.clone())
            .collect();
        if dropped.is_empty() {
            self.seen_drops.clear();
            return;
        }
        let dropped: Vec<PathBuf> = unique_paths(
            dropped
                .into_iter()
                .filter(|path| self.seen_drops.insert(path.clone()))
                .filter(|path| path.is_dir() || path.is_file())
                .collect(),
        );
        if dropped.is_empty() {
            return;
        }
        if self.job.is_some() {
            self.set_status_error(
                "Cinder is busy. Wait for the current job before dropping more files.",
            );
            return;
        }

        let mut archives = Vec::new();
        let mut sources = Vec::new();
        for path in dropped {
            if path.is_dir() || !is_supported_archive(&path) {
                sources.push(path);
            } else {
                archives.push(path);
            }
        }
        match (archives.len(), sources.is_empty()) {
            (0, _) => self.prepare_create(sources, 0),
            (1, true) => {
                self.arc_pass.clear();
                self.open_archive(&archives[0], String::new());
            }
            (_, true) => self.prepare_batch_extract(archives, true),
            (_, false) => {
                self.mixed_drop = MixedDropDialog {
                    show: true,
                    archives,
                    sources,
                };
            }
        }
    }

    fn handle_startup(&mut self) {
        if let Some(error) = self.startup_error.take() {
            self.error_popup = Some(error.clone());
            self.set_status_error(error);
        }
        let Some(request) = self.startup_request.take() else {
            return;
        };
        match request {
            ShellRequest::Open(paths) => {
                let paths = unique_paths(paths);
                if paths.len() == 1 {
                    self.arc_pass.clear();
                    self.open_archive(&paths[0], String::new());
                } else {
                    self.prepare_batch_extract(paths, true);
                }
            }
            ShellRequest::Create(paths, format) => self.prepare_create(paths, format),
            ShellRequest::Extract(paths) => self.prepare_batch_extract(paths, true),
            ShellRequest::ExtractHere(paths) => {
                let separate = unique_archive_sets(paths.clone()).len() > 1;
                self.start_batch_extract(paths, separate, false);
            }
            ShellRequest::ExtractTo(paths) => self.start_batch_extract(paths, true, false),
            ShellRequest::Test(paths) => self.start_batch_test(paths),
        }
    }

    fn handle_shortcuts(&mut self, ctx: &egui::Context) {
        let (new, open, extract, test, select_all, escape) = ctx.input(|i| {
            (
                i.key_pressed(egui::Key::N) && i.modifiers.command,
                i.key_pressed(egui::Key::O) && i.modifiers.command,
                i.key_pressed(egui::Key::E) && i.modifiers.command,
                i.key_pressed(egui::Key::T) && i.modifiers.command,
                i.key_pressed(egui::Key::A) && i.modifiers.command,
                i.key_pressed(egui::Key::Escape),
            )
        });
        if escape {
            self.new_dlg.show = false;
            self.xdlg.show = false;
            self.batch_dlg.show = false;
            self.mixed_drop.show = false;
            self.error_popup = None;
        }
        if self.job.is_some() {
            return;
        }
        if select_all && self.archive.is_none() {
            let query = self.filter.trim().to_lowercase();
            self.fs_selected.extend(
                self.fs_rows
                    .iter()
                    .filter(|(_, name, _)| query.is_empty() || name.to_lowercase().contains(&query))
                    .map(|(_, name, _)| name.clone()),
            );
        } else if new {
            let sources: Vec<PathBuf> = if self.fs_selected.is_empty() {
                vec![self.cwd.clone()]
            } else {
                self.fs_selected
                    .iter()
                    .map(|name| self.cwd.join(name))
                    .collect()
            };
            self.prepare_create(sources, 0);
        } else if open {
            if let Some(p) = pick_archive_file(&self.cwd) {
                self.arc_pass.clear();
                self.open_archive(&p, String::new());
            }
        } else if extract && self.archive.is_some() {
            self.xdlg.dest = default_extract_dest(&self.archive_path());
            self.xdlg.scope_all = true;
            self.xdlg.show = true;
        } else if test && self.archive.is_some() {
            self.start_test();
        }
    }
}

// ================================================================= app

impl eframe::App for CinderApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_job();
        self.handle_drops(ctx);
        self.handle_startup();
        self.handle_shortcuts(ctx);
        if self.job.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(60));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.add_space(4.0);
            self.toolbar(ui);
            ui.add_space(4.0);
        });

        egui::Panel::bottom("statusbar").show(ui, |ui| {
            ui.add_space(4.0);
            self.status_bar(ui);
            ui.add_space(4.0);
        });

        if self.show_tips {
            egui::Panel::right("tips")
                .resizable(true)
                .default_size(270.0)
                .min_size(220.0)
                .max_size(340.0)
                .show(ui, |ui| self.tips_panel(ui));
        }

        egui::CentralPanel::default().show(ui, |ui| {
            self.workspace_header(ui);
            if self.archive.is_some() {
                let ctx = ui.ctx().clone();
                self.members_table(&ctx, ui);
            } else {
                self.fs_table(ui);
            }
        });

        self.new_dialog(ui.ctx());
        self.extract_dialog(ui.ctx());
        self.batch_extract_dialog(ui.ctx());
        self.mixed_drop_dialog(ui.ctx());
        self.error_dialog(ui.ctx());
        self.drop_overlay(ui.ctx());
    }
}

impl CinderApp {
    fn drop_overlay(&self, ctx: &egui::Context) {
        if ctx.input(|input| input.raw.hovered_files.is_empty()) {
            return;
        }
        egui::Area::new("drop-overlay".into())
            .order(egui::Order::Foreground)
            .anchor(egui::Align2::CENTER_CENTER, egui::vec2(0.0, 0.0))
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(BG_ELEVATED)
                    .stroke(egui::Stroke::new(1.5, EMBER))
                    .corner_radius(CornerRadius::same(14))
                    .inner_margin(egui::Margin::symmetric(32, 24))
                    .show(ui, |ui| {
                        ui.vertical_centered(|ui| {
                            icon_slot(ui, UiIcon::Open, EMBER_SOFT);
                            ui.add_space(6.0);
                            ui.label(egui::RichText::new(if self.job.is_some() {
                                "Finish the current task before dropping more items"
                            } else {
                                "Drop to open, extract, or create an archive"
                            })
                            .size(18.0)
                            .strong());
                            ui.label(egui::RichText::new("Archives are detected automatically; multiple items can be grouped.").color(TEXT_DIM));
                        });
                    });
            });
    }

    fn workspace_header(&mut self, ui: &mut egui::Ui) {
        let (eyebrow, title, detail) = if let Some(a) = &self.archive {
            let kind = if a.is_cinder {
                "Cinder archive"
            } else {
                "Compatible archive"
            };
            (
                kind,
                a.path
                    .file_name()
                    .map_or("Archive", |n| n.to_str().unwrap_or("Archive")),
                "Select items to extract only what you need",
            )
        } else {
            (
                "File browser",
                "Choose something to compress",
                "Double-click folders to browse, archives to open, or files to compress",
            )
        };
        let (stat_a, stat_b, stat_c) = if let Some(a) = &self.archive {
            let files = a.members.iter().filter(|m| !m.dir).count();
            let logical: u64 = a.members.iter().filter_map(|m| m.size).sum();
            (
                ("MEMBERS", files.to_string()),
                ("LOGICAL SIZE", human(logical)),
                ("SELECTED", a.selected.len().to_string()),
            )
        } else {
            let folders = self.fs_rows.iter().filter(|r| r.0).count();
            let files = self.fs_rows.len().saturating_sub(folders);
            (
                ("FOLDERS", folders.to_string()),
                ("FILES", files.to_string()),
                ("SHORTCUT", "Ctrl/Cmd+N".to_string()),
            )
        };
        egui::Frame::group(ui.style())
            .fill(BG_ELEVATED)
            .corner_radius(CornerRadius::same(12))
            .inner_margin(egui::Margin::symmetric(16, 14))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::Image::new(egui::include_image!("../../assets/Cinder-Logo.png"))
                            .fit_to_exact_size(egui::vec2(42.0, 42.0)),
                    )
                    .on_hover_text("Cinder — lossless, deduplicating archive workspace");
                    ui.add_space(4.0);
                    ui.vertical(|ui| {
                        ui.horizontal(|ui| {
                            ui.label(
                                egui::RichText::new(if self.archive.is_some() {
                                    "ARCHIVE"
                                } else {
                                    "BROWSE"
                                })
                                .small()
                                .strong()
                                .color(EMBER),
                            );
                            ui.label(egui::RichText::new("•").color(TEXT_DIM));
                            ui.label(egui::RichText::new(eyebrow).small().color(TEXT_DIM));
                        });
                        ui.label(egui::RichText::new(title).size(23.0).strong());
                        ui.label(egui::RichText::new(detail).color(TEXT_DIM));
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::TOP), |ui| {
                        if action_button(
                            ui,
                            UiIcon::Tips,
                            "Tips",
                            "Show or hide the live guidance rail",
                            false,
                        )
                        .clicked()
                        {
                            self.show_tips = !self.show_tips;
                        }
                    });
                });
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    stat_card(ui, stat_a.0, &stat_a.1, EMBER_SOFT);
                    stat_card(ui, stat_b.0, &stat_b.1, GREEN);
                    stat_card(ui, stat_c.0, &stat_c.1, TEXT_DIM);
                });
            });
        ui.add_space(10.0);
    }

    fn tips_panel(&mut self, ui: &mut egui::Ui) {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(14, 12))
            .show(ui, |ui| {
        ui.horizontal(|ui| {
            icon_slot(ui, UiIcon::Tips, EMBER);
            ui.vertical(|ui| {
                ui.label(egui::RichText::new("Tips & guidance").size(17.0).strong());
                ui.label(egui::RichText::new("Helpful context, right when you need it").small().color(TEXT_DIM));
            });
        });
        ui.add_space(12.0);
        section_heading(
            ui,
            "Quick guide",
            "Tips for a smooth run",
            "Everything important is one click away.",
        );
        ui.add_space(12.0);
        if self.archive.is_some() {
            tip(ui, "Select precisely", "Click a file to select it. Hold Ctrl/Cmd to build a selection, then use Selected to extract only those files.");
            ui.add_space(8.0);
            tip(ui, "Check before sharing", "Test verifies every native chunk or fully decodes a compatible archive without writing files.");
            ui.add_space(8.0);
            tip(ui, "Encrypted archives", "If the archive is locked, enter its passphrase in the main panel. The key is never written to disk.");
        } else {
            tip(ui, "Fastest start", "Drop a folder here or double-click it to browse. Double-click a file to open the archive setup with a smart output name.");
            ui.add_space(8.0);
            tip(ui, "Pick the right format", "Cinder adds deduplication and encryption. 7z and RAR5 bring strong compression; ZIP and TAR work well when another tool needs to open the archive.");
            ui.add_space(8.0);
            tip(ui, "Shortcuts", "Ctrl/Cmd+N new archive, Ctrl/Cmd+O open, Ctrl/Cmd+E extract, Ctrl/Cmd+T test. Escape closes dialogs.");
        }
        ui.add_space(14.0);
        ui.separator();
        ui.label(
            egui::RichText::new("WORKFLOW")
                .small()
                .strong()
                .color(EMBER),
        );
        ui.label(egui::RichText::new("1  Choose a source\n2  Review the options\n3  Create or extract\n4  Test when you need confidence").color(TEXT_DIM));
        ui.add_space(12.0);
        ui.label(egui::RichText::new("SAFE BY DEFAULT").small().strong().color(EMBER));
        ui.label(egui::RichText::new("Cinder never overwrites files during extraction unless you explicitly enable it.").small().color(TEXT_DIM));
            });
    }

    fn toolbar(&mut self, ui: &mut egui::Ui) {
        let busy = self.job.is_some();
        egui::Frame::new()
            .fill(BG_ELEVATED)
            .corner_radius(CornerRadius::same(9))
            .inner_margin(egui::Margin::symmetric(10, 7))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.add_enabled_ui(!busy, |ui| {
                        if action_button(
                            ui,
                            UiIcon::Add,
                            "New",
                            "Create a new archive (Ctrl/Cmd+N)",
                            true,
                        )
                        .clicked()
                        {
                            let sources: Vec<PathBuf> = if self.fs_selected.is_empty() {
                                vec![self.cwd.clone()]
                            } else {
                                self.fs_selected
                                    .iter()
                                    .map(|name| self.cwd.join(name))
                                    .collect()
                            };
                            self.prepare_create(sources, 0);
                        }
                        if action_button(
                            ui,
                            UiIcon::Open,
                            "Open",
                            "Open a Cinder, 7z, RAR, ZIP, TAR, Gzip, XZ, or Zstandard archive (Ctrl/Cmd+O)",
                            false,
                        )
                        .clicked()
                        {
                            if let Some(p) = pick_archive_file(&self.cwd) {
                                self.arc_pass.clear();
                                self.open_archive(&p, String::new());
                            }
                        }

                        ui.separator();
                        ui.add_enabled_ui(self.archive.is_some(), |ui| {
                            if action_button(
                                ui,
                                UiIcon::Extract,
                                "Extract",
                                "Extract every member into a new folder (Ctrl/Cmd+E)",
                                false,
                            )
                            .clicked()
                            {
                                self.xdlg.dest = default_extract_dest(&self.archive_path());
                                self.xdlg.scope_all = true;
                                self.xdlg.show = true;
                            }
                            let sel_count = self.archive.as_ref().map_or(0, |a| a.selected.len());
                            let selected_label = format!("Selected ({sel_count})");
                            let selected_clicked = ui
                                .add_enabled_ui(sel_count > 0, |ui| {
                                    action_button(
                                        ui,
                                        UiIcon::Extract,
                                        &selected_label,
                                        "Extract only the selected members",
                                        false,
                                    )
                                })
                                .inner
                                .clicked();
                            if selected_clicked {
                                self.xdlg.dest = default_extract_dest(&self.archive_path());
                                self.xdlg.scope_all = false;
                                self.xdlg.show = true;
                            }
                            if action_button(
                                ui,
                                UiIcon::Verify,
                                "Test",
                                "Verify the archive without extracting files (Ctrl/Cmd+T)",
                                false,
                            )
                            .clicked()
                            {
                                self.start_test();
                            }
                            if action_button(
                                ui,
                                UiIcon::Close,
                                "Close",
                                "Return to the file browser",
                                false,
                            )
                            .clicked()
                            {
                                self.archive = None;
                                self.pending_open = None;
                                self.arc_pass.clear();
                            }
                        });
                    });
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        let mode = if busy {
                            "WORKING"
                        } else if self.archive.is_some() {
                            "ARCHIVE"
                        } else {
                            "READY"
                        };
                        ui.label(egui::RichText::new(mode).small().strong().color(if busy {
                            EMBER_SOFT
                        } else {
                            TEXT_DIM
                        }));
                    });
                });
            });
    }

    fn status_bar(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let text = if self.status_is_error {
                egui::RichText::new(&self.status).color(ERROR_TEXT)
            } else {
                egui::RichText::new(&self.status).color(GREEN)
            };
            ui.label(text);
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if let Some(job) = &self.job {
                    match job.progress {
                        Some((frac, ref msg)) if frac > 0.0 && frac < 1.0 => {
                            ui.small(msg.clone());
                            ui.add(
                                egui::ProgressBar::new(frac)
                                    .desired_width(220.0)
                                    .show_percentage(),
                            );
                        }
                        _ => {
                            ui.small(
                                job.progress
                                    .as_ref()
                                    .map_or_else(|| job.label.clone(), |(_, msg)| msg.clone()),
                            );
                            ui.add(egui::Spinner::new());
                        }
                    }
                } else if let Some(a) = &self.archive {
                    let logical: u64 = a.members.iter().filter_map(|m| m.size).sum();
                    let files = a.members.iter().filter(|m| !m.dir).count();
                    let sel_count = a.selected.len();
                    if !a.encrypted || sel_count == 0 {
                        ui.small(format!("{files} members - {} logical", human(logical)));
                    } else {
                        ui.small(format!(
                            "{} members - {} logical (select to extract)",
                            files,
                            human(logical)
                        ));
                    }
                } else {
                    let files = self.fs_rows.iter().filter(|r| !r.0).count();
                    ui.small(format!(
                        "{} folders - {} files",
                        self.fs_rows.len() - files,
                        files
                    ));
                }
            });
        });
    }

    // ---- filesystem view -----------------------------------------------

    fn fs_table(&mut self, ui: &mut egui::Ui) {
        let cwd = self.cwd.clone();
        ui.horizontal(|ui| {
            icon_slot(ui, UiIcon::Search, TEXT_DIM);
            ui.label(egui::RichText::new("Filter this folder").strong());
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(260.0)
                    .hint_text("Type a file or folder name..."),
            );
            if !self.filter.is_empty()
                && action_button(ui, UiIcon::Close, "Clear", "Clear the folder filter", false)
                    .clicked()
            {
                self.filter.clear();
            }
        });
        ui.add_space(5.0);
        let query = self.filter.trim().to_lowercase();
        let rows: Vec<_> = self
            .fs_rows
            .iter()
            .filter(|(_, name, _)| query.is_empty() || name.to_lowercase().contains(&query))
            .cloned()
            .collect();
        let selected_names = self.fs_selected.clone();
        let mut selection_changes = Vec::new();
        let mut action: Option<FileAction> = None;
        let busy = self.job.is_some();

        if rows.is_empty() {
            egui::Frame::group(ui.style())
                .fill(BG_CARD)
                .corner_radius(CornerRadius::same(12))
                .inner_margin(egui::Margin::symmetric(24, 30))
                .show(ui, |ui| {
                    ui.vertical_centered(|ui| {
                        ui.horizontal(|ui| {
                            icon_slot(ui, UiIcon::Folder, EMBER_SOFT);
                            ui.label(
                                egui::RichText::new(if query.is_empty() {
                                    "Nothing here yet"
                                } else {
                                    "No matching items"
                                })
                                .size(20.0)
                                .strong()
                                .color(EMBER_SOFT),
                            );
                        });
                        ui.label(
                            egui::RichText::new(if query.is_empty() {
                                    "Drop files, folders, or archives here, or use New archive to get started."
                            } else {
                                "Try another name or clear the filter."
                            })
                            .color(TEXT_DIM),
                        );
                        ui.add_space(8.0);
                        if action_button(
                            ui,
                            UiIcon::Add,
                            "Create an archive",
                            "Open the archive setup for this folder",
                            true,
                        )
                        .clicked()
                        {
                            self.prepare_create(vec![self.cwd.clone()], 0);
                        }
                    });
                });
            ui.add_space(12.0);
        }

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::remainder().clip(true).at_least(200.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(80.0))
            .header(22.0, |mut h| {
                h.col(|ui| {
                    ui.horizontal(|ui| {
                        icon_slot(ui, UiIcon::File, TEXT_DIM);
                        ui.strong("Name");
                    });
                });
                h.col(|ui| {
                    ui.strong("Size");
                });
                h.col(|ui| {
                    ui.strong("Kind");
                });
            })
            .body(|body| {
                body.rows(18.0, rows.len(), |mut row| {
                    let (is_dir, name, size) = &rows[row.index()];
                    let path = cwd.join(name);
                    let is_selected = selected_names.contains(name);
                    let target_names: Vec<String> = if is_selected {
                        selected_names.iter().cloned().collect()
                    } else {
                        vec![name.clone()]
                    };
                    let targets: Vec<PathBuf> = target_names
                        .iter()
                        .map(|selected| cwd.join(selected))
                        .collect();
                    let archives: Vec<PathBuf> = targets
                        .iter()
                        .filter(|path| is_supported_archive(path))
                        .cloned()
                        .collect();
                    row.set_selected(is_selected);
                    row.col(|ui| {
                        let resp = icon_selectable_label(
                            ui,
                            is_selected,
                            if *is_dir {
                                UiIcon::Folder
                            } else {
                                UiIcon::File
                            },
                            name.clone(),
                            if *is_dir {
                                "Double-click to open this folder"
                            } else {
                                "Double-click to open a supported archive or prepare a file for compression"
                            },
                        );
                        if resp.clicked() {
                            let additive = ui.input(|input| input.modifiers.command);
                            if additive {
                                selection_changes.push(if is_selected {
                                    SelectionChange::Remove(name.clone())
                                } else {
                                    SelectionChange::Add(name.clone())
                                });
                            } else {
                                selection_changes.push(SelectionChange::Replace(name.clone()));
                            }
                        }
                        if resp.secondary_clicked() && !is_selected {
                            selection_changes.push(SelectionChange::Replace(name.clone()));
                        }
                        if resp.double_clicked() {
                            action = Some(if *is_dir {
                                FileAction::Browse(path.clone())
                            } else if is_supported_archive(&path) {
                                FileAction::Open(path.clone())
                            } else {
                                FileAction::Create(vec![path.clone()], 0)
                            });
                        }
                        resp.context_menu(|ui| {
                            ui.set_min_width(210.0);
                            ui.add_enabled_ui(!busy, |ui| {
                                if *is_dir {
                                    if ui.button("Open folder").clicked() {
                                        action = Some(FileAction::Browse(path.clone()));
                                        ui.close();
                                    }
                                } else if is_supported_archive(&path)
                                    && ui.button("Open with Cinder").clicked()
                                {
                                    action = Some(FileAction::Open(path.clone()));
                                    ui.close();
                                }
                                if ui
                                    .button(format!("Add {} item(s) to archive…", targets.len()))
                                    .clicked()
                                {
                                    action = Some(FileAction::Create(targets.clone(), 0));
                                    ui.close();
                                }
                                if ui.button("Add to 7z archive…").clicked() {
                                    action = Some(FileAction::Create(targets.clone(), 1));
                                    ui.close();
                                }
                                if !archives.is_empty() {
                                    ui.separator();
                                    if archives.len() == 1
                                        && ui
                                            .button(format!(
                                                "Extract to {}\\",
                                                archive_stem(&archives[0])
                                            ))
                                            .clicked()
                                    {
                                        action = Some(FileAction::ExtractTo(archives.clone()));
                                        ui.close();
                                    }
                                    if ui.button("Extract to folders…").clicked() {
                                        action = Some(FileAction::ExtractDialog(archives.clone()));
                                        ui.close();
                                    }
                                    if ui.button("Extract here").clicked() {
                                        action = Some(FileAction::ExtractHere(
                                            archives.clone(),
                                            archives.len() > 1,
                                        ));
                                        ui.close();
                                    }
                                    if ui.button("Test archive(s)").clicked() {
                                        action = Some(FileAction::Test(archives.clone()));
                                        ui.close();
                                    }
                                }
                                ui.separator();
                                if ui.button("Copy path").clicked() {
                                    action = Some(FileAction::Copy(path.display().to_string()));
                                    ui.close();
                                }
                            });
                        });
                    });
                    row.col(|ui| {
                        ui.label(if *is_dir {
                            "-".to_string()
                        } else {
                            human(*size)
                        });
                    });
                    row.col(|ui| {
                        ui.label(if *is_dir { "folder" } else { "file" });
                    });
                });
            });

        for change in selection_changes {
            match change {
                SelectionChange::Add(name) => {
                    self.fs_selected.insert(name);
                }
                SelectionChange::Remove(name) => {
                    self.fs_selected.remove(&name);
                }
                SelectionChange::Replace(name) => {
                    self.fs_selected.clear();
                    self.fs_selected.insert(name);
                }
            }
        }
        if let Some(action) = action {
            match action {
                FileAction::Browse(path) => self.navigate(&path),
                FileAction::Open(path) => {
                    self.arc_pass.clear();
                    self.open_archive(&path, String::new());
                }
                FileAction::Create(paths, format) => self.prepare_create(paths, format),
                FileAction::ExtractHere(paths, separate) => {
                    self.start_batch_extract(paths, separate, false)
                }
                FileAction::ExtractTo(paths) => self.start_batch_extract(paths, true, false),
                FileAction::ExtractDialog(paths) => self.prepare_batch_extract(paths, true),
                FileAction::Test(paths) => self.start_batch_test(paths),
                FileAction::Copy(text) => ui.ctx().copy_text(text),
            }
        }

        ui.add_space(4.0);
        egui::Frame::group(ui.style())
            .fill(BG_ELEVATED)
            .corner_radius(CornerRadius::same(8))
            .inner_margin(egui::Margin::symmetric(10, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    icon_slot(ui, UiIcon::Folder, TEXT_DIM);
                    ui.label(egui::RichText::new("Location").color(TEXT_DIM));
                    let resp = ui.add(
                        egui::TextEdit::singleline(&mut self.address)
                            .desired_width(ui.available_width() - 110.0),
                    );
                    let enter = resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                    if action_button(
                        ui,
                        UiIcon::Open,
                        "Go",
                        "Navigate to this folder (Enter)",
                        false,
                    )
                    .clicked()
                        || enter
                    {
                        let t = PathBuf::from(self.address.trim());
                        if t.is_dir() {
                            self.navigate(&t);
                        } else {
                            self.set_status_error(format!("No such directory: {}", t.display()));
                            self.address = self.cwd.display().to_string();
                        }
                    }
                    if action_button(ui, UiIcon::Up, "Up", "Go to the parent folder", false)
                        .clicked()
                    {
                        if let Some(parent) = self.cwd.parent() {
                            let p = parent.to_path_buf();
                            self.navigate(&p);
                        }
                    }
                });
            });
    }

    // ---- archive members view --------------------------------------------

    fn members_table(&mut self, ctx: &egui::Context, ui: &mut egui::Ui) {
        let foreign = self.archive.as_ref().is_some_and(|a| !a.is_cinder);
        let locked = self
            .archive
            .as_ref()
            .is_some_and(|a| a.encrypted && a.members.is_empty());
        if locked {
            ui.vertical_centered(|ui| {
                ui.add_space(24.0);
                ui.horizontal(|ui| {
                    icon_slot(ui, UiIcon::Lock, EMBER_SOFT);
                    ui.label(
                        egui::RichText::new("This archive is encrypted")
                            .size(20.0)
                            .strong()
                            .color(EMBER_SOFT),
                    );
                });
                ui.add_space(4.0);
                ui.horizontal(|ui| {
                    let resp = ui.add_sized(
                        [340.0, 26.0],
                        egui::TextEdit::singleline(&mut self.arc_pass)
                            .password(true)
                            .hint_text("Passphrase"),
                    );
                    let enter = resp.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                    if action_button(
                        ui,
                        UiIcon::Open,
                        "Unlock",
                        "Open the archive with this passphrase (Enter)",
                        true,
                    )
                    .clicked()
                        || enter
                    {
                        let pass = self.arc_pass.clone();
                        let path = self.archive_path();
                        self.open_archive(&path, pass);
                    }
                });
            });
            return;
        }

        if foreign {
            ui.horizontal(|ui| {
                icon_slot(ui, UiIcon::Lock, TEXT_DIM);
                ui.label(egui::RichText::new("Password").strong());
                let input = ui.add(
                    egui::TextEdit::singleline(&mut self.arc_pass)
                        .password(true)
                        .desired_width(220.0)
                        .hint_text("Optional for encrypted archives"),
                );
                let enter = input.lost_focus() && ctx.input(|i| i.key_pressed(egui::Key::Enter));
                if action_button(
                    ui,
                    UiIcon::Open,
                    "Unlock",
                    "Read encrypted headers or refresh this archive with the password",
                    false,
                )
                .clicked()
                    || enter
                {
                    let pass = self.arc_pass.clone();
                    let path = self.archive_path();
                    self.open_archive(&path, pass);
                }
                ui.label(
                    egui::RichText::new("Used for this session only")
                        .small()
                        .color(TEXT_DIM),
                );
            });
            ui.add_space(6.0);
        }

        let (rows, selected, sort_col, sort_desc) = match self.archive.as_ref() {
            Some(a) => (
                a.members.clone(),
                a.selected.clone(),
                self.sort_col,
                self.sort_desc,
            ),
            None => return,
        };

        ui.horizontal(|ui| {
            icon_slot(ui, UiIcon::Search, TEXT_DIM);
            ui.label(egui::RichText::new("Filter").strong());
            ui.add(
                egui::TextEdit::singleline(&mut self.filter)
                    .desired_width(250.0)
                    .hint_text("Search members..."),
            )
            .on_hover_text("Filter by member path; this does not change the archive");
            if !self.filter.is_empty()
                && action_button(ui, UiIcon::Close, "Clear", "Clear the member filter", false)
                    .clicked()
            {
                self.filter.clear();
            }
            ui.separator();
            let visible_names: Vec<String> = rows
                .iter()
                .filter(|m| !m.dir)
                .filter(|m| {
                    self.filter.trim().is_empty()
                        || m.name
                            .to_lowercase()
                            .contains(&self.filter.trim().to_lowercase())
                })
                .map(|m| m.name.clone())
                .collect();
            if action_button(
                ui,
                UiIcon::Verify,
                "Select visible",
                "Select every visible file in the current filter",
                false,
            )
            .clicked()
            {
                if let Some(a) = self.archive.as_mut() {
                    a.selected.extend(visible_names.iter().cloned());
                }
            }
            if action_button(
                ui,
                UiIcon::Close,
                "Clear selection",
                "Remove all selected files",
                false,
            )
            .clicked()
            {
                if let Some(a) = self.archive.as_mut() {
                    a.selected.clear();
                }
            }
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                ui.label(
                    egui::RichText::new(format!("{} selected", selected.len())).color(TEXT_DIM),
                );
            });
        });
        let query = self.filter.trim().to_lowercase();
        let rows: Vec<Member> = rows
            .into_iter()
            .filter(|m| query.is_empty() || m.name.to_lowercase().contains(&query))
            .collect();

        let mut click: Option<String> = None;
        let mut sort_click: Option<usize> = None;
        let mut member_action: Option<MemberAction> = None;

        TableBuilder::new(ui)
            .striped(true)
            .resizable(true)
            .column(Column::remainder().clip(true).at_least(180.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(90.0))
            .column(Column::auto().at_least(130.0))
            .header(22.0, |mut h| {
                for (title, idx) in [
                    ("Name", 0usize),
                    ("Size", 1),
                    ("Packed", 2),
                    ("Modified", 3),
                ] {
                    h.col(|ui| {
                        let mark = if sort_col == idx {
                            if sort_desc {
                                " (Z-A)"
                            } else {
                                " (A-Z)"
                            }
                        } else {
                            ""
                        };
                        if ui
                            .button(format!("{title}{mark}"))
                            .on_hover_text("Click to sort; click again to reverse the order")
                            .clicked()
                        {
                            sort_click = Some(idx);
                        }
                    });
                }
            })
            .body(|body| {
                body.rows(18.0, rows.len(), |mut row| {
                    let m = &rows[row.index()];
                    let is_sel = !m.dir && selected.contains(&m.name);
                    row.set_selected(is_sel);
                    row.col(|ui| {
                        let resp = icon_selectable_label(
                            ui,
                            is_sel,
                            if m.dir { UiIcon::Folder } else { UiIcon::File },
                            m.name.clone(),
                            if m.dir {
                                "Folder"
                            } else {
                                "Click to select this member"
                            },
                        );
                        if resp.clicked() && !m.dir {
                            click = Some(m.name.clone());
                        }
                        let row_files: HashSet<String> = if m.dir {
                            let prefix = format!("{}/", m.name.trim_end_matches('/'));
                            rows.iter()
                                .filter(|member| !member.dir && member.name.starts_with(&prefix))
                                .map(|member| member.name.clone())
                                .collect()
                        } else {
                            HashSet::from([m.name.clone()])
                        };
                        let menu_selection = if is_sel {
                            selected.clone()
                        } else {
                            row_files.clone()
                        };
                        resp.context_menu(|ui| {
                            ui.set_min_width(205.0);
                            ui.add_enabled_ui(self.job.is_none(), |ui| {
                                if ui
                                    .add_enabled(
                                        !row_files.is_empty(),
                                        egui::Button::new("Extract this item"),
                                    )
                                    .clicked()
                                {
                                    member_action = Some(MemberAction::Extract(row_files.clone()));
                                    ui.close();
                                }
                                if ui
                                    .add_enabled(
                                        !menu_selection.is_empty(),
                                        egui::Button::new(format!(
                                            "Extract selected ({})",
                                            menu_selection.len()
                                        )),
                                    )
                                    .clicked()
                                {
                                    member_action =
                                        Some(MemberAction::Extract(menu_selection.clone()));
                                    ui.close();
                                }
                                if ui.button("Extract everything…").clicked() {
                                    member_action = Some(MemberAction::ExtractAll);
                                    ui.close();
                                }
                                ui.separator();
                                if ui.button("Test archive").clicked() {
                                    member_action = Some(MemberAction::Test);
                                    ui.close();
                                }
                                if ui.button("Copy member path").clicked() {
                                    member_action = Some(MemberAction::Copy(m.name.clone()));
                                    ui.close();
                                }
                            });
                        });
                    });
                    row.col(|ui| {
                        ui.label(m.size.map_or_else(|| "-".into(), human));
                    });
                    row.col(|ui| {
                        ui.label(m.packed.map_or_else(|| "-".into(), human));
                    });
                    row.col(|ui| {
                        ui.label(m.modified.clone().unwrap_or_else(|| "-".into()));
                    });
                });
            });

        if let Some(idx) = sort_click {
            if self.sort_col == idx {
                self.sort_desc = !self.sort_desc;
            } else {
                self.sort_col = idx;
                self.sort_desc = false;
            }
            self.apply_sort();
        }
        if let Some(name) = click {
            let additive = ctx.input(|i| i.modifiers.command);
            if let Some(a) = self.archive.as_mut() {
                if !additive {
                    a.selected.clear();
                }
                if !a.selected.remove(&name) {
                    a.selected.insert(name);
                }
            }
        }
        if let Some(action) = member_action {
            match action {
                MemberAction::Extract(names) => {
                    if let Some(archive) = self.archive.as_mut() {
                        archive.selected = names;
                    }
                    self.xdlg.dest = default_extract_dest(&self.archive_path());
                    self.xdlg.scope_all = false;
                    self.xdlg.show = true;
                }
                MemberAction::ExtractAll => {
                    self.xdlg.dest = default_extract_dest(&self.archive_path());
                    self.xdlg.scope_all = true;
                    self.xdlg.show = true;
                }
                MemberAction::Test => self.start_test(),
                MemberAction::Copy(text) => ctx.copy_text(text),
            }
        }
    }

    // ---- dialogs ----------------------------------------------------------

    fn new_dialog(&mut self, ctx: &egui::Context) {
        if !self.new_dlg.show {
            return;
        }
        let mut d = self.new_dlg.clone();
        let mut create_clicked = false;
        let mut cancel_clicked = false;
        egui::Window::new("New Archive")
            .open(&mut d.show)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                section_heading(ui, "Step 1 of 2", "Build an archive", "Choose what to package and how portable or compact it should be.");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    icon_slot(ui, UiIcon::Folder, TEXT_DIM);
                    ui.label(egui::RichText::new("Source").strong()).on_hover_text("One folder or file, or a group of selected files and folders");
                    if d.sources.len() > 1 {
                        ui.vertical(|ui| {
                            ui.label(format!("{} selected items", d.sources.len()));
                            ui.label(egui::RichText::new(d.source.clone()).small().color(TEXT_DIM));
                        });
                    } else if ui.add(egui::TextEdit::singleline(&mut d.source).desired_width(330.0)).changed() {
                        d.sources.clear();
                        d.dest = suggest_dest(Path::new(&d.source), d.format_idx);
                    }
                    if action_button(ui, UiIcon::Folder, "Browse", "Pick a folder to compress", false).clicked() {
                        if let Some(p) = pick_folder() {
                            d.source = p.display().to_string();
                            d.sources.clear();
                            d.dest = suggest_dest(&p, d.format_idx);
                        }
                    }
                    if action_button(ui, UiIcon::File, "Choose files", "Select one or more files to archive together", false).clicked() {
                        if let Some(paths) = pick_source_files() {
                            let paths = unique_paths(paths);
                            if !paths.is_empty() {
                                d.source = paths[0].display().to_string();
                                d.sources = if paths.len() > 1 { paths.clone() } else { Vec::new() };
                                d.dest = suggest_dest_paths(&paths, d.format_idx);
                            }
                        }
                    }
                });
                ui.horizontal(|ui| {
                    icon_slot(ui, UiIcon::File, TEXT_DIM);
                    ui.label(egui::RichText::new("Output").strong()).on_hover_text("Where the new archive will be saved");
                    ui.add(
                        egui::TextEdit::singleline(&mut d.dest)
                            .desired_width(330.0)
                            .hint_text("archive path"),
                    );
                    if action_button(ui, UiIcon::File, "Save as", "Choose the archive path", false).clicked() {
                        let ext = OUT_FORMATS[d.format_idx].1.trim_start_matches('.');
                        if let Some(p) = save_archive_file(&d.source, ext) {
                            d.dest = p.display().to_string();
                        }
                    }
                });
                ui.checkbox(&mut d.replace_output, "Replace an existing archive")
                    .on_hover_text("Cinder refuses to replace existing output unless you turn this on.");

                let previous_format = d.format_idx;
                let mut fmt = d.format_idx;
                egui::ComboBox::from_id_salt("out-format")
                    .selected_text(OUT_FORMATS[d.format_idx].0)
                    .width(180.0)
                    .show_ui(ui, |ui| {
                        for (i, (label, _)) in OUT_FORMATS.iter().enumerate() {
                            ui.selectable_value(&mut fmt, i, *label).on_hover_text(format_tooltips(i));
                        }
                    });
                d.format_idx = fmt;
                let current_sources = if d.sources.is_empty() {
                    vec![PathBuf::from(d.source.trim())]
                } else {
                    d.sources.clone()
                };
                if d.format_idx != previous_format
                    && (d.dest.trim().is_empty()
                        || d.dest == suggest_dest_paths(&current_sources, previous_format))
                {
                    d.dest = suggest_dest_paths(&current_sources, d.format_idx);
                }
                egui::Frame::group(ui.style())
                    .fill(BG_CARD)
                    .corner_radius(CornerRadius::same(7))
                    .inner_margin(egui::Margin::symmetric(10, 7))
                    .show(ui, |ui| {
                        ui.horizontal(|ui| {
                            icon_slot(ui, UiIcon::Tips, EMBER_SOFT);
                            ui.label(egui::RichText::new(format_tooltips(d.format_idx)).small().color(TEXT_DIM));
                        });
                    });
                if d.format_idx == 2 {
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("RAR version").strong());
                        egui::ComboBox::from_id_salt("rar-generation")
                            .selected_text(RAR_VERSIONS[d.rar_version_idx].0)
                            .width(120.0)
                            .show_ui(ui, |ui| {
                                for (index, (label, _)) in RAR_VERSIONS.iter().enumerate() {
                                    ui.selectable_value(&mut d.rar_version_idx, index, *label);
                                }
                            });
                        ui.add_space(10.0);
                        ui.add_enabled_ui(d.rar_version_idx >= 7, |ui| {
                            ui.label("Split at");
                            ui.add(
                                egui::TextEdit::singleline(&mut d.rar_volume_size_mb)
                                    .desired_width(68.0)
                                    .hint_text("off"),
                            );
                            ui.label("MB per part");
                        });
                    });
                    let volume_help = if d.rar_version_idx >= 7 {
                        "Parts are saved beside the output as .part01.rar, .part02.rar, and so on."
                    } else {
                        "Volume creation is available for RAR 5 and RAR 7."
                    };
                    ui.label(egui::RichText::new(volume_help).small().color(TEXT_DIM));
                }
                let supports_password = d.format_idx <= 2;
                if !supports_password {
                    d.encrypt = false;
                }

                ui.horizontal(|ui| {
                    ui.add_enabled_ui(d.format_idx != 4, |ui| {
                        let mut tier = d.tier_idx;
                        egui::ComboBox::from_id_salt("tier")
                            .selected_text(TIERS[d.tier_idx])
                            .width(110.0)
                            .show_ui(ui, |ui| {
                                for (i, t) in TIERS.iter().enumerate() {
                                    ui.selectable_value(&mut tier, i, *t).on_hover_text(match i {
                                        0 => "Faster compression, less ratio",
                                        1 => "Balanced speed/ratio (default)",
                                        _ => "Max ratio, slower compression",
                                    });
                                }
                            });
                        d.tier_idx = tier;
                        if d.format_idx <= 2 {
                            ui.checkbox(&mut d.solid, "Solid small files").on_hover_text("Group smaller files to improve compression; disable for quicker single-file access");
                        }
                    });
                    if d.format_idx == 4 {
                        ui.label(egui::RichText::new("TAR stores files without compression").color(TEXT_DIM));
                    }
                });

                ui.add_enabled_ui(supports_password, |ui| {
                    let encryption_help = match d.format_idx {
                        0 => "Protect contents with Argon2id and XChaCha20-Poly1305",
                        1 => "Encrypt the archive contents and names with AES-256",
                        _ if d.rar_version_idx < 5 => "Use legacy RAR data encryption for compatibility with older readers",
                        _ => "Encrypt the archive contents and names with AES-256",
                    };
                    ui.checkbox(&mut d.encrypt, "Encrypt archive").on_hover_text(encryption_help);
                    if d.encrypt {
                        ui.horizontal(|ui| {
                            ui.label("Passphrase");
                            ui.add(
                                egui::TextEdit::singleline(&mut d.pass1)
                                    .password(true)
                                    .desired_width(140.0),
                            );
                            ui.label("repeat");
                            ui.add(
                                egui::TextEdit::singleline(&mut d.pass2)
                                    .password(true)
                                    .desired_width(140.0),
                            );
                        });
                    }
                });

                ui.separator();
                ui.label(egui::RichText::new("Tip: Balanced is a good default for most folders. Max saves more space but takes longer.").small().color(TEXT_DIM));
                ui.horizontal(|ui| {
                    if action_button(ui, UiIcon::Add, "Create archive", "Start compression with these settings", true).clicked() {
                        create_clicked = true;
                    }
                    if action_button(ui, UiIcon::Close, "Cancel", "Close without creating an archive", false).clicked() {
                        cancel_clicked = true;
                    }
                });
            });
        self.new_dlg = d;
        if cancel_clicked {
            self.new_dlg.show = false;
        }
        if create_clicked {
            match validate_new(&self.new_dlg) {
                Ok(()) => {
                    self.launch_create_from_dialog();
                    self.new_dlg.show = false;
                }
                Err(e) => self.error_popup = Some(e),
            }
        }
    }

    fn launch_create_from_dialog(&mut self) {
        let sources = dialog_sources(&self.new_dlg);
        let source_label = if sources.len() == 1 {
            sources[0].display().to_string()
        } else {
            format!("{} selected items", sources.len())
        };
        let dst = PathBuf::from(&self.new_dlg.dest);
        let format_idx = self.new_dlg.format_idx;
        let tier_idx = self.new_dlg.tier_idx;
        let solid = self.new_dlg.solid;
        let replace_output = self.new_dlg.replace_output;
        let rar_version = RAR_VERSIONS[self.new_dlg.rar_version_idx].1;
        let rar_volume_size = self
            .new_dlg
            .rar_volume_size_mb
            .trim()
            .parse::<u64>()
            .ok()
            .and_then(|megabytes| megabytes.checked_mul(1024 * 1024));
        let passphrase = self
            .new_dlg
            .encrypt
            .then(|| self.new_dlg.pass1.clone())
            .filter(|p| !p.is_empty());

        let job = spawn_job("create", move |tx| {
            if format_idx == 0 {
                let opts = CompressOptions {
                    profile: match tier_idx {
                        0 => Profile::Fast,
                        2 => Profile::Max,
                        _ => Profile::Balanced,
                    },
                    solid_small_files: solid,
                    encryption_passphrase: passphrase,
                    ..CompressOptions::default()
                };
                let tx2 = tx.clone();
                let total = Arc::new(AtomicU64::new(0));
                let latest_progress = Arc::new(AtomicU64::new(0));
                let total_cb = Arc::clone(&total);
                let progress_cb = Arc::clone(&latest_progress);
                let sink: Arc<dyn Fn(&ProgressEvent) + Send + Sync> =
                    Arc::new(move |ev| match ev {
                        ProgressEvent::WalkDone { bytes, .. } => {
                            total_cb.store(*bytes, Ordering::Relaxed);
                            progress_cb.store(20_000, Ordering::Relaxed);
                            let _ = tx2.send(JobEvent::Progress {
                                fraction: 0.0,
                                msg: format!("{} total", human(*bytes)),
                            });
                        }
                        ProgressEvent::BytesRead(done) => {
                            let total = total_cb.load(Ordering::Relaxed);
                            let read_fraction = if total == 0 {
                                0.85
                            } else {
                                0.05 + 0.8 * (*done as f64 / total as f64).clamp(0.0, 1.0)
                            };
                            let candidate = (read_fraction * 1_000_000.0) as u64;
                            progress_cb.fetch_max(candidate, Ordering::Relaxed);
                            let fraction = progress_cb.load(Ordering::Relaxed) as f32 / 1_000_000.0;
                            let _ = tx2.send(JobEvent::Progress {
                                fraction,
                                msg: format!("Read {} / {}", human(*done), human(total)),
                            });
                        }
                        ProgressEvent::StreamStart { name } => {
                            let fraction = progress_cb.load(Ordering::Relaxed) as f32 / 1_000_000.0;
                            let _ = tx2.send(JobEvent::Progress {
                                fraction,
                                msg: format!("Preparing {name}"),
                            });
                        }
                        ProgressEvent::FramesWritten(count) => {
                            let fraction = progress_cb.load(Ordering::Relaxed) as f32 / 1_000_000.0;
                            let _ = tx2.send(JobEvent::Progress {
                                fraction,
                                msg: format!("Writing frame {count}"),
                            });
                        }
                    });
                if dst.exists() && !replace_output {
                    let _ = tx.send(JobEvent::Done(Err(format!(
                        "Output already exists: {}. Choose another name or enable Replace an existing archive.",
                        dst.display()
                    ))));
                    return;
                }
                match cinder_core::compress_paths(&sources, &dst, &opts, &sink) {
                    Ok(s) => {
                        let _ = tx.send(JobEvent::Done(Ok(format!(
                            "Compressed {} -> {}: {} -> {} ({} unique, {} deduped)",
                            source_label,
                            dst.display(),
                            human(s.input_bytes),
                            human(s.archive_bytes),
                            s.unique_chunks,
                            s.duplicate_chunks
                        ))));
                    }
                    Err(e) => {
                        let _ = tx.send(JobEvent::Done(Err(e.to_string())));
                    }
                }
            } else {
                let fmt = match format_idx {
                    1 => cinder_formats::CreateFormat::SevenZ,
                    2 => cinder_formats::CreateFormat::Rar,
                    3 => cinder_formats::CreateFormat::Zip,
                    4 => cinder_formats::CreateFormat::Tar,
                    5 => cinder_formats::CreateFormat::TarGz,
                    6 => cinder_formats::CreateFormat::TarZst,
                    _ => cinder_formats::CreateFormat::TarXz,
                };
                let level = match format_idx {
                    1 => [0, 3, 9][tier_idx],
                    2 => [0, 1, 5][tier_idx],
                    3 | 5 => [3, 6, 9][tier_idx],
                    7 => [2, 4, 9][tier_idx],
                    4 => 0,
                    6 => [3, 12, 19][tier_idx],
                    _ => 6,
                };
                let threads = std::thread::available_parallelism()
                    .ok()
                    .map(std::num::NonZeroUsize::get);
                if dst.exists() && !replace_output {
                    let _ = tx.send(JobEvent::Done(Err(format!(
                        "Output already exists: {}. Choose another name or enable Replace an existing archive.",
                        dst.display()
                    ))));
                    return;
                }
                match cinder_formats::create_paths(
                    &sources,
                    &dst,
                    fmt,
                    cinder_formats::CreateOptions {
                        level,
                        threads,
                        solid,
                        password: passphrase,
                        rar_version,
                        rar_volume_size,
                    },
                ) {
                    Ok(s) => {
                        let output_kind = if s.volume_count > 1 {
                            format!("{} RAR parts", s.volume_count)
                        } else {
                            "archive".to_string()
                        };
                        let _ = tx.send(JobEvent::Done(Ok(format!(
                            "Created {} -> {} ({}; {} -> {}, {} symlinks skipped)",
                            source_label,
                            dst.display(),
                            output_kind,
                            human(s.input_bytes),
                            human(s.output_bytes),
                            s.symlinks_skipped
                        ))));
                    }
                    Err(e) => {
                        let _ = tx.send(JobEvent::Done(Err(e.to_string())));
                    }
                }
            }
        });
        self.job = Some(job);
    }

    fn extract_dialog(&mut self, ctx: &egui::Context) {
        if !self.xdlg.show {
            return;
        }
        let sel_count = self.archive.as_ref().map_or(0, |a| a.selected.len());
        let mut d = self.xdlg.clone();
        let mut go_clicked = false;
        let mut cancel_clicked = false;
        egui::Window::new("Extract")
            .open(&mut d.show)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                section_heading(ui, "Step 2 of 2", "Extract safely", "Choose a destination and decide whether to replace files that are already there.");
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    icon_slot(ui, UiIcon::Folder, TEXT_DIM);
                    ui.label(egui::RichText::new("To").strong()).on_hover_text("Destination folder for the extracted files");
                    ui.add(egui::TextEdit::singleline(&mut d.dest).desired_width(360.0));
                    if action_button(ui, UiIcon::Folder, "Browse", "Choose a destination folder", false).clicked() {
                        if let Some(p) = pick_folder() {
                            d.dest = p.display().to_string();
                        }
                    }
                });
                ui.checkbox(&mut d.overwrite, "Overwrite existing files")
                    .on_hover_text("Replace files that have the same path in the destination");
                ui.horizontal(|ui| {
                    ui.radio_value(&mut d.scope_all, true, "Everything")
                        .on_hover_text("Extract all files and folders in the archive");
                    ui.add_enabled_ui(sel_count > 0, |ui| {
                        ui.radio_value(
                            &mut d.scope_all,
                            false,
                            format!("Selected ({sel_count})"),
                        )
                        .on_hover_text("Extract only the selected files");
                    });
                });
                if sel_count > 0 && !d.scope_all {
                    ui.label(
                        egui::RichText::new(format!("{sel_count} item(s) will be extracted"))
                            .color(TEXT_DIM),
                    );
                }
                ui.label(egui::RichText::new("Tip: Leave overwrite off when extracting into a folder you want to keep untouched.").small().color(TEXT_DIM));
                ui.separator();
                ui.horizontal(|ui| {
                    if action_button(ui, UiIcon::Extract, "Extract", "Start extraction with these settings", true).clicked() {
                        go_clicked = true;
                    }
                    if action_button(ui, UiIcon::Close, "Cancel", "Close without extracting", false).clicked() {
                        cancel_clicked = true;
                    }
                });
                // Show progress if a job is running
                if self.job.is_some() {
                    ui.add_space(8.0);
                    ui.label("Extracting in background...");
                    if let Some(job) = &self.job {
                        if let Some((frac, ref msg)) = job.progress {
                            ui.add(egui::ProgressBar::new(frac).desired_width(220.0));
                            ui.small(msg.clone());
                        }
                    }
                }
            });
        self.xdlg = d;
        if cancel_clicked {
            self.xdlg.show = false;
        }
        if go_clicked {
            if self.xdlg.dest.trim().is_empty() {
                self.error_popup = Some("Destination is empty.".into());
            } else {
                self.launch_extract_from_dialog();
                self.xdlg.show = false;
            }
        }
    }

    fn batch_extract_dialog(&mut self, ctx: &egui::Context) {
        if !self.batch_dlg.show {
            return;
        }
        let mut dialog = self.batch_dlg.clone();
        let mut go = false;
        let mut open = dialog.show;
        let mut cancel = false;
        egui::Window::new("Extract archives")
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                section_heading(
                    ui,
                    "Batch extraction",
                    "Extract a group safely",
                    "Each archive is checked independently. One failure will not stop the rest.",
                );
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .max_height(120.0)
                    .show(ui, |ui| {
                        for path in &dialog.archives {
                            ui.label(path.display().to_string());
                        }
                    });
                ui.add_space(6.0);
                ui.horizontal(|ui| {
                    icon_slot(ui, UiIcon::Folder, TEXT_DIM);
                    ui.label(egui::RichText::new("Destination").strong());
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.destination)
                            .desired_width(300.0)
                            .hint_text("destination folder"),
                    );
                    if action_button(
                        ui,
                        UiIcon::Folder,
                        "Browse",
                        "Choose a destination folder",
                        false,
                    )
                    .clicked()
                    {
                        if let Some(path) = pick_folder() {
                            dialog.destination = path.display().to_string();
                        }
                    }
                });
                ui.checkbox(
                    &mut dialog.separate_folders,
                    "Create a separate folder for each archive",
                )
                .on_hover_text(
                    "Avoids same-name collisions when extracting several archives together.",
                );
                ui.checkbox(&mut dialog.overwrite, "Overwrite existing files")
                    .on_hover_text(
                        "When enabled, files at the same destination path may be replaced.",
                    );
                ui.horizontal(|ui| {
                    icon_slot(ui, UiIcon::Lock, TEXT_DIM);
                    ui.label("Password");
                    ui.add(
                        egui::TextEdit::singleline(&mut dialog.passphrase)
                            .password(true)
                            .desired_width(220.0)
                            .hint_text("optional; used for every archive"),
                    );
                });
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    go = action_button(
                        ui,
                        UiIcon::Extract,
                        &format!("Extract {} archives", dialog.archives.len()),
                        "Start the batch extraction",
                        true,
                    )
                    .clicked();
                    if ember_button(ui, "Cancel").clicked() {
                        cancel = true;
                    }
                });
            });
        dialog.show = open && !cancel;
        self.batch_dlg = dialog.clone();
        if go {
            if dialog.destination.trim().is_empty() {
                self.error_popup = Some("Destination is empty.".into());
            } else {
                self.batch_dlg.show = false;
                self.start_batch_extract_to(
                    dialog.archives,
                    PathBuf::from(dialog.destination),
                    dialog.separate_folders,
                    dialog.overwrite,
                    dialog.passphrase,
                );
            }
        }
    }

    fn mixed_drop_dialog(&mut self, ctx: &egui::Context) {
        if !self.mixed_drop.show {
            return;
        }
        let mut dialog = self.mixed_drop.clone();
        let mut extract = false;
        let mut create = false;
        let mut open = dialog.show;
        let mut cancel = false;
        egui::Window::new("Choose what to do")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                section_heading(
                    ui,
                    "Mixed drop",
                    "Two kinds of items detected",
                    "Choose one action. You can handle the other group by dropping it again.",
                );
                ui.add_space(6.0);
                ui.label(format!("{} archives", dialog.archives.len()));
                ui.label(format!("{} files or folders", dialog.sources.len()));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    extract = action_button(
                        ui,
                        UiIcon::Extract,
                        "Extract archives",
                        "Open the grouped extraction options",
                        true,
                    )
                    .clicked();
                    create = action_button(
                        ui,
                        UiIcon::Add,
                        "Create from files",
                        "Build an archive from the regular files and folders",
                        false,
                    )
                    .clicked();
                });
                if ember_button(ui, "Cancel").clicked() {
                    cancel = true;
                }
            });
        dialog.show = open && !cancel;
        self.mixed_drop = dialog.clone();
        if extract {
            self.mixed_drop.show = false;
            self.prepare_batch_extract(dialog.archives, true);
        } else if create {
            self.mixed_drop.show = false;
            self.prepare_create(dialog.sources, 0);
        }
    }

    fn start_batch_extract(
        &mut self,
        archives: Vec<PathBuf>,
        separate_folders: bool,
        overwrite: bool,
    ) {
        let destination = common_parent(&archives).unwrap_or_else(|| self.cwd.clone());
        self.start_batch_extract_to(
            archives,
            destination,
            separate_folders,
            overwrite,
            String::new(),
        );
    }

    fn start_batch_extract_to(
        &mut self,
        archives: Vec<PathBuf>,
        destination: PathBuf,
        separate_folders: bool,
        overwrite: bool,
        passphrase: String,
    ) {
        let archives = unique_archive_sets(archives);
        if archives.is_empty() {
            self.set_status_error("No archives were selected for extraction.");
            return;
        }
        let label = format!("Extracting {} archives", archives.len());
        let job = spawn_job("batch-extract", move |tx| {
            let mut completed = Vec::new();
            let mut failures = Vec::new();
            let mut reserved = HashSet::new();
            for (index, archive) in archives.iter().enumerate() {
                let output = if separate_folders {
                    unique_extract_folder(&destination, &archive_stem(archive), &mut reserved)
                } else {
                    destination.clone()
                };
                let _ = tx.send(JobEvent::Progress {
                    fraction: index as f32 / archives.len() as f32,
                    msg: format!(
                        "Extracting {}",
                        archive.file_name().unwrap_or_default().to_string_lossy()
                    ),
                });
                match extract_one_archive(archive, &output, overwrite, &passphrase) {
                    Ok(summary) => completed.push(format!(
                        "{} → {} ({})",
                        archive.display(),
                        output.display(),
                        summary
                    )),
                    Err(error) => failures.push(format!("{}: {error}", archive.display())),
                }
            }
            let result = if failures.is_empty() {
                Ok(format!(
                    "Extracted {} archives:\n{}",
                    completed.len(),
                    completed.join("\n")
                ))
            } else {
                Err(format!(
                    "{} archive(s) failed. Successful extractions:\n{}\n\nErrors:\n{}",
                    failures.len(),
                    completed.join("\n"),
                    failures.join("\n")
                ))
            };
            let _ = tx.send(JobEvent::Done(result));
        });
        self.job = Some(job);
        self.set_status_ok(label);
    }

    fn start_batch_test(&mut self, archives: Vec<PathBuf>) {
        let archives = unique_archive_sets(archives);
        if archives.is_empty() {
            self.set_status_error("No archives were selected for testing.");
            return;
        }
        let count = archives.len();
        let passphrase = self.arc_pass.clone();
        let job = spawn_job("batch-test", move |tx| {
            let mut successes = Vec::new();
            let mut failures = Vec::new();
            for (index, archive) in archives.iter().enumerate() {
                let _ = tx.send(JobEvent::Progress {
                    fraction: index as f32 / count as f32,
                    msg: format!(
                        "Testing {}",
                        archive.file_name().unwrap_or_default().to_string_lossy()
                    ),
                });
                let result = if looks_like_cinder(archive) {
                    run_cinder_test(archive, passphrase.clone(), &tx)
                } else {
                    cinder_formats::test_with_password(
                        archive,
                        256 * 1024 * 1024 * 1024,
                        (!passphrase.is_empty()).then_some(passphrase.as_str()),
                    )
                    .map(|report| format!("{} entries, {}", report.entries, human(report.bytes)))
                    .map_err(|error| error.to_string())
                };
                match result {
                    Ok(message) => successes.push(format!("{}: {message}", archive.display())),
                    Err(error) => failures.push(format!("{}: {error}", archive.display())),
                }
            }
            let result = if failures.is_empty() {
                Ok(format!(
                    "Verified {} archives:\n{}",
                    successes.len(),
                    successes.join("\n")
                ))
            } else {
                Err(format!(
                    "{} archive(s) failed verification:\n{}",
                    failures.len(),
                    failures.join("\n")
                ))
            };
            let _ = tx.send(JobEvent::Done(result));
        });
        self.job = Some(job);
    }

    fn launch_extract_from_dialog(&mut self) {
        let Some(a) = self.archive.as_ref() else {
            return;
        };
        let path = a.path.clone();
        let is_cinder = a.is_cinder;
        let pass = if a.is_cinder && !a.encrypted {
            String::new()
        } else {
            self.arc_pass.clone()
        };
        let names: Vec<String> = a.selected.clone().into_iter().collect();
        let all = self.xdlg.scope_all;
        let overwrite = self.xdlg.overwrite;
        let dest = PathBuf::from(&self.xdlg.dest);

        let label = if all { "extract-all" } else { "extract-sel" };
        let job = spawn_job(label, move |tx| {
            let outcome: Result<String, String> = if is_cinder {
                let opts = ExtractOptions {
                    limits: cinder_core::archive::Limits::default(),
                    symlink_policy: SymlinkPolicy::PreserveSafe,
                    overwrite,
                    passphrase: (!pass.is_empty()).then_some(pass),
                };
                if all {
                    extract_archive(&path, &dest, &opts)
                        .map(|s| {
                            format!(
                                "Extracted {} files, {} dirs ({}) to {}",
                                s.files_written,
                                s.dirs_created,
                                human(s.bytes_written),
                                dest.display()
                            )
                        })
                        .map_err(|e| e.to_string())
                } else {
                    let sep = std::path::MAIN_SEPARATOR_STR;
                    let mut files_done = 0u64;
                    let mut bytes_done = 0u64;
                    for name in &names {
                        let target = dest.join(name.replace('/', sep));
                        match extract_file(&path, name, &target, &opts) {
                            Ok(s) => {
                                files_done += s.files_written.max(s.symlinks_created);
                                bytes_done += s.bytes_written;
                            }
                            Err(e) => {
                                let _ = tx.send(JobEvent::Done(Err(format!("'{name}': {e}"))));
                                return;
                            }
                        }
                    }
                    Ok(format!(
                        "Extracted {files_done} selected files ({}) to {}",
                        human(bytes_done),
                        dest.display()
                    ))
                }
            } else {
                let opts = cinder_formats::ExtractOptions {
                    overwrite,
                    password: (!pass.is_empty()).then_some(pass),
                    ..Default::default()
                };
                let summary = if all {
                    cinder_formats::extract(&path, &dest, &opts)
                } else {
                    let set: HashSet<String> = names.into_iter().collect();
                    cinder_formats::extract_selected(
                        &path,
                        &dest,
                        &opts,
                        &cinder_formats::ExtractSelection::only(set),
                    )
                };
                summary
                    .map(|s| {
                        format!(
                            "Extracted {} files, {} dirs ({}) to {}",
                            s.files,
                            s.dirs,
                            human(s.bytes),
                            dest.display()
                        )
                    })
                    .map_err(|e| e.to_string())
            };
            let _ = tx.send(JobEvent::Done(outcome));
        });
        self.job = Some(job);
    }

    fn start_test(&mut self) {
        let Some(a) = self.archive.as_ref() else {
            return;
        };
        let path = a.path.clone();
        let is_cinder = a.is_cinder;
        let pass = if a.is_cinder && !a.encrypted {
            String::new()
        } else {
            self.arc_pass.clone()
        };

        let job = spawn_job("test", move |tx| {
            let outcome: Result<String, String> = if is_cinder {
                run_cinder_test(&path, pass, &tx)
            } else {
                cinder_formats::test_with_password(
                    &path,
                    256 * 1024 * 1024 * 1024,
                    (!pass.is_empty()).then_some(pass.as_str()),
                )
                .map(|rep| {
                    format!(
                        "OK - {} entries, {} decompressed cleanly.",
                        rep.entries,
                        human(rep.bytes)
                    )
                })
                .map_err(|e| e.to_string())
            };
            let _ = tx.send(JobEvent::Done(outcome));
        });
        self.job = Some(job);
    }

    fn error_dialog(&mut self, ctx: &egui::Context) {
        let Some(err) = self.error_popup.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new("Problem")
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(egui::RichText::new(err).color(ERROR_TEXT));
                ui.add_space(4.0);
                if ember_button(ui, "Dismiss").clicked() {
                    self.error_popup = None;
                }
            });
        if !open {
            self.error_popup = None;
        }
    }
}

fn run_cinder_test(path: &Path, pass: String, tx: &Sender<JobEvent>) -> Result<String, String> {
    let auth = if pass.is_empty() {
        cinder_core::crypto::Auth::None
    } else {
        cinder_core::crypto::Auth::Passphrase(pass)
    };
    let file = fs::File::open(path).map_err(|e| e.to_string())?;
    let mut reader = ArchiveReader::open(file, auth, cinder_core::archive::Limits::default())
        .map_err(|e| e.to_string())?;
    let hashes: Vec<_> = reader.manifest.chunk_pool.keys().copied().collect();
    let total = hashes.len().max(1);
    for (i, h) in hashes.iter().enumerate() {
        if reader.read_chunk(h).is_err() {
            return Err(format!("Chunk {h} failed verification."));
        }
        let _ = tx.send(JobEvent::Progress {
            fraction: ((i + 1) as f32 / total as f32).clamp(0.0, 1.0),
            msg: format!("chunk {}/{}", i + 1, hashes.len()),
        });
    }
    Ok(format!("OK - {} unique chunks verified.", hashes.len()))
}

// ------------------------------------------------------------ pure helpers

fn looks_like_cinder(path: &Path) -> bool {
    let mut magic = [0u8; 8];
    fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut magic))
        .is_ok_and(|()| &magic == b"CINDERv1")
}

fn human(bytes: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * KB;
    const GB: f64 = MB * KB;
    let b = bytes as f64;
    if b >= GB {
        format!("{:.2} GiB", b / GB)
    } else if b >= MB {
        format!("{:.1} MiB", b / MB)
    } else if b >= KB {
        format!("{:.1} KiB", b / KB)
    } else {
        format!("{bytes} B")
    }
}

/// Tab-separated lines: deliberately boring serialization across the thread.
fn serialize_members(members: &[Member]) -> String {
    let mut out = String::new();
    for m in members {
        out.push_str(if m.dir { "d\t" } else { "f\t" });
        out.push_str(&m.name.replace(['\n', '\t'], " "));
        out.push('\t');
        out.push_str(&m.size.map_or(String::new(), |v| v.to_string()));
        out.push('\t');
        out.push_str(&m.packed.map_or(String::new(), |v| v.to_string()));
        out.push('\t');
        out.push_str(m.modified.as_deref().unwrap_or(""));
        out.push('\n');
    }
    out
}

fn deserialize_members(blob: &str) -> Option<Vec<Member>> {
    let mut out = Vec::new();
    for line in blob.lines() {
        let mut it = line.split('\t');
        let dir = match it.next()? {
            "d" => true,
            "f" => false,
            _ => continue,
        };
        let name = it.next()?.to_string();
        let size = it.next().and_then(|s| s.parse::<u64>().ok());
        let packed = it.next().and_then(|s| s.parse::<u64>().ok());
        let modified = it.next().filter(|s| !s.is_empty()).map(str::to_string);
        out.push(Member {
            dir,
            name,
            size,
            packed,
            modified,
        });
    }
    Some(out)
}

fn load_archive(path: &Path, passphrase: &str, is_cinder: bool) -> Result<Vec<Member>, String> {
    if is_cinder {
        let auth = if passphrase.is_empty() {
            cinder_core::crypto::Auth::None
        } else {
            cinder_core::crypto::Auth::Passphrase(passphrase.to_string())
        };
        let file = fs::File::open(path).map_err(|e| e.to_string())?;
        let reader = ArchiveReader::open(file, auth, cinder_core::archive::Limits::default())
            .map_err(|e| match e {
                cinder_core::CinderError::Encrypted => "ENCRYPTED".to_string(),
                other => other.to_string(),
            })?;
        let mut members: Vec<Member> = Vec::new();
        for d in &reader.manifest.directories {
            members.push(Member {
                dir: true,
                name: d.path.display().to_string(),
                size: None,
                packed: None,
                modified: None,
            });
        }
        for f in &reader.manifest.files {
            members.push(Member {
                dir: false,
                name: f.path.display().to_string(),
                size: Some(f.length),
                packed: None,
                modified: None,
            });
        }
        Ok(members)
    } else {
        let entries = cinder_formats::list_with_password(
            path,
            (!passphrase.is_empty()).then_some(passphrase),
        )
        .map_err(|e| {
            if matches!(e, cinder_formats::FormatsError::PasswordRequired) {
                "ENCRYPTED".to_string()
            } else {
                e.to_string()
            }
        })?;
        Ok(entries
            .into_iter()
            .map(|e| Member {
                dir: e.name.ends_with('/'),
                name: e.name.trim_end_matches('/').to_string(),
                size: e.size,
                packed: e.packed,
                modified: e.modified,
            })
            .collect())
    }
}

fn extract_one_archive(
    archive: &Path,
    destination: &Path,
    overwrite: bool,
    passphrase: &str,
) -> Result<String, String> {
    if looks_like_cinder(archive) {
        let options = ExtractOptions {
            limits: cinder_core::archive::Limits::default(),
            symlink_policy: SymlinkPolicy::PreserveSafe,
            overwrite,
            passphrase: (!passphrase.is_empty()).then(|| passphrase.to_string()),
        };
        extract_archive(archive, destination, &options)
            .map(|stats| {
                format!(
                    "{} files, {} directories, {}",
                    stats.files_written,
                    stats.dirs_created,
                    human(stats.bytes_written)
                )
            })
            .map_err(|error| error.to_string())
    } else {
        cinder_formats::extract(
            archive,
            destination,
            &cinder_formats::ExtractOptions {
                overwrite,
                password: (!passphrase.is_empty()).then(|| passphrase.to_string()),
                ..Default::default()
            },
        )
        .map(|stats| {
            format!(
                "{} files, {} directories, {}",
                stats.files,
                stats.dirs,
                human(stats.bytes)
            )
        })
        .map_err(|error| error.to_string())
    }
}

fn unique_extract_folder(parent: &Path, stem: &str, reserved: &mut HashSet<String>) -> PathBuf {
    let stem = if stem.is_empty() { "archive" } else { stem };
    for index in 1u32..=100_000 {
        let name = if index == 1 {
            stem.to_string()
        } else {
            format!("{stem} ({index})")
        };
        let path = parent.join(name);
        let key = path_identity(&path);
        if !path.exists() && reserved.insert(key) {
            return path;
        }
    }
    parent.join(format!("{stem}-extract"))
}

fn suggest_name(source: &Path, ext: &str) -> String {
    source.file_name().map_or_else(
        || format!("archive.{ext}"),
        |n| format!("{}.{ext}", n.to_string_lossy()),
    )
}

fn suggest_dest(source: &Path, format_idx: usize) -> String {
    let ext = OUT_FORMATS.get(format_idx).map_or(".cnd", |(_, e)| e);
    let parent = source.parent().unwrap_or(Path::new("."));
    let stem = source
        .file_name()
        .map_or("archive".to_string(), |n| n.to_string_lossy().into_owned());
    parent.join(format!("{stem}{ext}")).display().to_string()
}

fn dialog_sources(dialog: &NewDialog) -> Vec<PathBuf> {
    if dialog.sources.is_empty() {
        vec![PathBuf::from(dialog.source.trim())]
    } else {
        dialog.sources.clone()
    }
}

fn suggest_dest_paths(sources: &[PathBuf], format_idx: usize) -> String {
    if sources.len() <= 1 {
        return sources.first().map_or_else(
            || format!("New archive{}", OUT_FORMATS[format_idx].1),
            |source| suggest_dest(source, format_idx),
        );
    }
    let parent = common_parent(sources)
        .or_else(|| sources[0].parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."));
    parent
        .join(format!("New archive{}", OUT_FORMATS[format_idx].1))
        .display()
        .to_string()
}

fn unique_paths(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut seen = HashSet::new();
    paths
        .into_iter()
        .filter(|path| {
            let normalized = fs::canonicalize(path).unwrap_or_else(|_| path.clone());
            seen.insert(path_identity(&normalized))
        })
        .collect()
}

fn path_identity(path: &Path) -> String {
    let value = path.to_string_lossy().into_owned();
    #[cfg(windows)]
    {
        value.to_lowercase()
    }
    #[cfg(not(windows))]
    {
        value
    }
}

fn archive_set_first(path: &Path) -> PathBuf {
    let Some(file_name) = path
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return path.to_path_buf();
    };
    let lower = file_name.to_ascii_lowercase();
    if lower.ends_with(".rar") {
        if let Some(part_index) = lower.rfind(".part") {
            let digits = &lower[part_index + 5..lower.len() - 4];
            if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                let width = digits.len();
                let base = &file_name[..part_index];
                return path.with_file_name(format!("{base}.part{:0width$}.rar", 1));
            }
        }
    }
    if let Some(extension) = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_ascii_lowercase())
    {
        if extension.len() == 3
            && extension.as_bytes()[0].is_ascii_lowercase()
            && (b'r'..=b'z').contains(&extension.as_bytes()[0])
            && extension[1..].bytes().all(|byte| byte.is_ascii_digit())
        {
            return path.with_extension("rar");
        }
        if extension.len() == 3 && extension.bytes().all(|byte| byte.is_ascii_digit()) {
            let stem = path.file_stem().map_or_else(
                || "archive".to_string(),
                |stem| stem.to_string_lossy().into_owned(),
            );
            return path.with_file_name(format!("{stem}.001"));
        }
    }
    path.to_path_buf()
}

fn unique_archive_sets(paths: Vec<PathBuf>) -> Vec<PathBuf> {
    let mut archives = unique_paths(
        paths
            .into_iter()
            .map(|path| archive_set_first(&path))
            .collect(),
    );
    archives.sort_by_key(|path| path_identity(path));
    archives
}

fn common_parent(paths: &[PathBuf]) -> Option<PathBuf> {
    let mut paths = paths.iter();
    let first = paths.next()?.parent()?.to_path_buf();
    let key = path_identity(&first);
    for path in paths {
        if path_identity(path.parent()?) != key {
            return None;
        }
    }
    Some(first)
}

fn is_supported_archive(path: &Path) -> bool {
    looks_like_cinder(path) || cinder_formats::detect(path).is_some()
}

fn archive_stem(path: &Path) -> String {
    let name = path.file_name().map_or_else(
        || "extracted".to_string(),
        |name| name.to_string_lossy().into_owned(),
    );
    let lower = name.to_ascii_lowercase();
    if let Some(index) = lower.rfind(".part") {
        if lower.ends_with(".rar") {
            let digits = &lower[index + 5..lower.len() - 4];
            if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
                return name[..index].to_string();
            }
        }
    }
    for suffix in [
        ".tar.gz", ".tar.zst", ".tar.xz", ".tgz", ".tzst", ".txz", ".tar", ".zip", ".7z", ".rar",
        ".gz", ".zst", ".xz", ".cnd",
    ] {
        if lower.ends_with(suffix) {
            return name[..name.len() - suffix.len()].to_string();
        }
    }
    path.file_stem().map_or_else(
        || "extracted".to_string(),
        |stem| stem.to_string_lossy().into_owned(),
    )
}

fn archive_output_exists(output: &Path, format_idx: usize) -> bool {
    if output.exists() {
        return true;
    }
    if format_idx != 2 {
        return false;
    }
    let Some(file_name) = output
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
    else {
        return false;
    };
    let lower_file_name = file_name.to_ascii_lowercase();
    let Some(base) = lower_file_name.strip_suffix(".rar") else {
        return false;
    };
    let prefix = format!("{base}.part");
    fs::read_dir(output.parent().unwrap_or(Path::new(".")))
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter_map(|entry| entry.file_name().into_string().ok())
        .any(|name| {
            let lower = name.to_ascii_lowercase();
            (lower.starts_with(&prefix) && lower.ends_with(".rar"))
                || lower
                    .strip_prefix(&format!("{base}."))
                    .is_some_and(|extension| {
                        extension.len() == 3
                            && extension.as_bytes()[0].is_ascii_lowercase()
                            && (b'r'..=b'z').contains(&extension.as_bytes()[0])
                            && extension[1..].bytes().all(|byte| byte.is_ascii_digit())
                    })
        })
}

fn default_extract_dest(archive: &Path) -> String {
    let dir = archive.parent().unwrap_or(Path::new("."));
    dir.join(archive_stem(archive)).display().to_string()
}

fn validate_new(d: &NewDialog) -> Result<(), String> {
    let sources = dialog_sources(d);
    let dst = PathBuf::from(&d.dest);
    if sources.is_empty() || sources.iter().any(|path| !path.exists()) {
        let missing = sources
            .iter()
            .find(|path| !path.exists())
            .map_or_else(|| d.source.clone(), |path| path.display().to_string());
        return Err(format!("Source does not exist: {missing}"));
    }
    if d.dest.trim().is_empty() {
        return Err("Output path is empty.".into());
    }
    if d.encrypt {
        if d.pass1.is_empty() {
            return Err("Encryption requested but passphrase is empty.".into());
        }
        if d.pass1 != d.pass2 {
            return Err("Passphrases do not match.".into());
        }
    }
    if d.format_idx == 2 && !d.rar_volume_size_mb.trim().is_empty() {
        let megabytes = d
            .rar_volume_size_mb
            .trim()
            .parse::<u64>()
            .map_err(|_| "RAR split size must be a whole number of megabytes.".to_string())?;
        if megabytes == 0 || megabytes.checked_mul(1024 * 1024).is_none() {
            return Err("RAR split size must be greater than 0 MB and fit this system.".into());
        }
        if !RAR_VERSIONS[d.rar_version_idx]
            .1
            .supports_streamed_volumes()
        {
            return Err("RAR volume creation requires RAR 5.0 or RAR 7.0.".into());
        }
    }
    for src in &sources {
        if dst.exists() && fs::canonicalize(src).ok() == fs::canonicalize(&dst).ok() {
            return Err("Output must be different from every source.".into());
        }
        if src.is_dir() {
            if let (Ok(source_root), Some(parent)) = (fs::canonicalize(src), dst.parent()) {
                if fs::canonicalize(parent)
                    .is_ok_and(|parent_root| parent_root.starts_with(&source_root))
                {
                    return Err("Choose an output folder outside the source folder.".into());
                }
            }
        }
    }
    if archive_output_exists(&dst, d.format_idx) && !d.replace_output {
        return Err("That output archive already exists. Choose a new name or enable Replace an existing archive.".into());
    }
    Ok(())
}

fn parse_shell_request() -> Result<Option<ShellRequest>, String> {
    let mut args = std::env::args_os().skip(1);
    let Some(mode) = args.next() else {
        return Ok(None);
    };
    let paths: Vec<PathBuf> = args.map(PathBuf::from).collect();
    if paths.is_empty() {
        return Err(format!(
            "{} needs at least one file or folder path.",
            mode.to_string_lossy()
        ));
    }
    let request = match mode.to_string_lossy().as_ref() {
        "--shell-open" => ShellRequest::Open(paths),
        "--shell-create" => ShellRequest::Create(paths, 0),
        "--shell-create-7z" => ShellRequest::Create(paths, 1),
        "--shell-extract" => ShellRequest::Extract(paths),
        "--shell-extract-here" => ShellRequest::ExtractHere(paths),
        "--shell-extract-to" => ShellRequest::ExtractTo(paths),
        "--shell-test" => ShellRequest::Test(paths),
        other => return Err(format!("Unknown option: {other}")),
    };
    Ok(Some(request))
}

fn main() -> eframe::Result<()> {
    let icon = eframe::icon_data::from_png_bytes(include_bytes!("../../assets/Cinder-Logo.png"))
        .unwrap_or_default();
    let (startup_request, startup_error) = match parse_shell_request() {
        Ok(request) => (request, None),
        Err(error) => (None, Some(error)),
    };
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 720.0])
            .with_min_inner_size([760.0, 480.0])
            .with_icon(icon),
        ..Default::default()
    };
    eframe::run_native(
        "Cinder",
        options,
        Box::new(|cc| {
            apply_theme(&cc.egui_ctx);
            Ok(Box::new(CinderApp::with_startup(
                startup_request,
                startup_error,
            )))
        }),
    )
}

#[cfg(test)]
mod tests {
    use super::{archive_set_first, archive_stem, common_parent, unique_archive_sets};
    use std::path::{Path, PathBuf};

    #[test]
    fn rar_volume_selection_resolves_to_one_archive_set() {
        assert_eq!(
            archive_set_first(Path::new("backup.part03.rar")),
            PathBuf::from("backup.part01.rar")
        );
        assert_eq!(
            archive_set_first(Path::new("backup.r05")),
            PathBuf::from("backup.rar")
        );
        assert_eq!(
            archive_set_first(Path::new("backup.003")),
            PathBuf::from("backup.001")
        );
        assert_eq!(
            unique_archive_sets(vec![
                PathBuf::from("backup.part01.rar"),
                PathBuf::from("backup.part02.rar"),
            ]),
            vec![PathBuf::from("backup.part01.rar")]
        );
    }

    #[test]
    fn extraction_names_strip_compound_and_volume_extensions() {
        assert_eq!(archive_stem(Path::new("snapshot.tar.gz")), "snapshot");
        assert_eq!(archive_stem(Path::new("backup.part04.rar")), "backup");
        assert_eq!(archive_stem(Path::new("snapshot.cnd")), "snapshot");
    }

    #[test]
    fn grouped_destination_defaults_to_shared_parent_only() {
        assert_eq!(
            common_parent(&[
                PathBuf::from("downloads/a.zip"),
                PathBuf::from("downloads/b.7z")
            ]),
            Some(PathBuf::from("downloads"))
        );
        assert_eq!(
            common_parent(&[PathBuf::from("one/a.zip"), PathBuf::from("two/b.zip")]),
            None
        );
    }
}
