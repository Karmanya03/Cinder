//! list / extract / test / create operations over the supported formats.
//!
//! Every extraction path funnels member names through
//! [`cinder_core::extract::safe_destination`] and every decompressing read
//! through a byte budget, so hostile containers get exactly the same
//! treatment as hostile `.cnd` archives.

use std::collections::HashSet;
use std::fs;
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use super::{
    apply_mode, bounded_copy, codify, entry_destination, open_root, open_stream_reader,
    raw_file_reader, zip_err, Budget, CreateFormat, CreateOptions, CreateStats, EntryInfo,
    ExtractOptions, ExtractSummary, Format, FormatsError, RarVersion, Result,
};

const MAX_FOREIGN_ENTRIES: usize = 10_000_000;
const MAX_FOREIGN_HEADER_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RAR_DICTIONARY_BYTES: u64 = 512 * 1024 * 1024;
const MAX_RAR_VOLUMES: usize = 10_000;
const MAX_RAR_LEGACY_VOLUMES: usize = 901;

/// Which members an extraction should materialize.
#[derive(Debug, Clone, Default)]
pub struct ExtractSelection {
    /// `None` = everything; `Some` = only these normalized `/`-separated
    /// names (trailing slashes ignored).
    pub names: Option<HashSet<String>>,
}

impl ExtractSelection {
    #[must_use]
    pub fn all() -> Self {
        Self { names: None }
    }

    #[must_use]
    pub fn only(names: HashSet<String>) -> Self {
        Self { names: Some(names) }
    }

    fn allows(&self, name: &str) -> bool {
        match &self.names {
            None => true,
            Some(set) => {
                let trimmed = name.trim_end_matches('/');
                set.contains(trimmed) || set.contains(name)
            }
        }
    }
}

// ------------------------------------------------------------------ list

/// List members of any supported format.
///
/// # Errors
/// Corrupt containers or IO failures. Unsafe entry paths are *not* an error
/// at listing time â€” they only matter when extracting.
pub fn list(archive: &Path) -> Result<Vec<EntryInfo>> {
    list_with_password(archive, None)
}

/// List members of a supported archive, supplying a password for encrypted
/// 7z or RAR headers when required.
pub fn list_with_password(archive: &Path, password: Option<&str>) -> Result<Vec<EntryInfo>> {
    match super::detect(archive) {
        Some(Format::Zip) => list_zip(archive),
        Some(Format::SevenZ) => list_sevenz(archive, password),
        Some(Format::Rar) => list_rar(archive, password),
        Some(fmt @ (Format::Tar | Format::TarGz | Format::TarZst | Format::TarXz)) => {
            let reader: Box<dyn Read> = match fmt {
                Format::Tar => Box::new(io::BufReader::new(fs::File::open(archive)?)),
                _ => open_stream_reader(archive, fmt)?,
            };
            list_tar(reader)
        }
        Some(fmt @ (Format::GzSingle | Format::XzSingle | Format::ZstSingle)) => {
            let on_disk = fs::metadata(archive)?.len();
            let _ = fmt;
            Ok(vec![EntryInfo {
                name: super::stream_payload_name(archive),
                size: None,
                packed: Some(on_disk),
                modified: None,
            }])
        }
        None => Err(FormatsError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("unrecognized archive format: {}", archive.display()),
        ))),
    }
}

fn list_sevenz(archive: &Path, password: Option<&str>) -> Result<Vec<EntryInfo>> {
    let reader = sevenz_rust2::ArchiveReader::open(
        archive,
        password.map_or_else(sevenz_rust2::Password::empty, sevenz_rust2::Password::new),
    )
    .map_err(sevenz_error)?;
    let files = &reader.archive().files;
    if files.len() > MAX_FOREIGN_ENTRIES {
        return Err(cinder_core::CinderError::DecompressionBombSuspected(
            MAX_FOREIGN_ENTRIES as u64,
        )
        .into());
    }
    Ok(files
        .iter()
        .map(|entry| EntryInfo {
            name: with_directory_slash(&entry.name, entry.is_directory),
            size: Some(entry.size),
            packed: Some(entry.compressed_size),
            modified: None,
        })
        .collect())
}

fn list_rar(archive: &Path, password: Option<&str>) -> Result<Vec<EntryInfo>> {
    let parsed = read_rar_set(archive, password, None)?;
    let members = rar_volume_members(&parsed)?;
    let mut out = Vec::new();
    for member in &members {
        if out.len() >= MAX_FOREIGN_ENTRIES {
            return Err(cinder_core::CinderError::DecompressionBombSuspected(
                MAX_FOREIGN_ENTRIES as u64,
            )
            .into());
        }
        let name = member.decoded_name(None).map_err(rar_error)?;
        out.push(EntryInfo {
            name: with_directory_slash(&String::from_utf8_lossy(&name), member.meta.is_directory),
            size: Some(member.meta.unpacked_size),
            packed: Some(member.meta.packed_size),
            modified: None,
        });
    }
    Ok(out)
}

fn with_directory_slash(name: &str, is_dir: bool) -> String {
    if is_dir && !name.ends_with('/') {
        format!("{name}/")
    } else {
        name.to_string()
    }
}

fn rar_read_options(password: Option<&str>, max_total_raw: u64) -> rars::ArchiveReadOptions<'_> {
    rars::ArchiveReadOptions::with_optional_password(password.map(str::as_bytes))
        .with_max_header_count(MAX_FOREIGN_ENTRIES as u64)
        .with_max_header_bytes(MAX_FOREIGN_HEADER_BYTES)
        .with_max_member_output_bytes(max_total_raw)
        .with_max_total_output_bytes(max_total_raw)
        .with_rar50_dictionary_size_limit(MAX_RAR_DICTIONARY_BYTES)
        .with_rar50_buffered_decode_limit(64 * 1024 * 1024)
}

fn read_rar_set(
    archive: &Path,
    password: Option<&str>,
    max_total_raw: Option<u64>,
) -> Result<Vec<rars::Archive>> {
    let options = rar_read_options(password, max_total_raw.unwrap_or(256 * 1024 * 1024 * 1024));
    rar_volume_paths(archive)?
        .into_iter()
        .map(|path| rars::ArchiveReader::read_path_with_options(path, options).map_err(rar_error))
        .collect()
}

fn rar_volume_members(archives: &[rars::Archive]) -> Result<Vec<rars::ArchiveMember>> {
    let mut header_count = 0usize;
    for archive in archives {
        header_count = header_count.saturating_add(archive.members().count());
        if header_count > MAX_FOREIGN_ENTRIES {
            return Err(cinder_core::CinderError::DecompressionBombSuspected(
                MAX_FOREIGN_ENTRIES as u64,
            )
            .into());
        }
    }
    let members = rars::volume_members(archives).map_err(rar_error)?;
    if members.len() > MAX_FOREIGN_ENTRIES {
        return Err(cinder_core::CinderError::DecompressionBombSuspected(
            MAX_FOREIGN_ENTRIES as u64,
        )
        .into());
    }
    Ok(members)
}

/// Resolve any part in a RAR set to its first volume and enumerate the
/// contiguous set in archive order. RAR5/7 use `.partNN.rar`, older RAR uses
/// `.rar`, `.r00`, `.r01`, and some tools use numbered `.001` files.
fn rar_volume_paths(input: &Path) -> Result<Vec<PathBuf>> {
    let parent = input.parent().unwrap_or_else(|| Path::new("."));
    let name = input
        .file_name()
        .ok_or_else(|| invalid_rar_path(input, "archive path has no file name"))?
        .to_string_lossy()
        .into_owned();
    let lower = name.to_ascii_lowercase();

    if let Some((base, extension, width)) = parse_rar_part_name(&name) {
        let first = rar_part_path(parent, &base, &extension, 1, width);
        return collect_rar_series(first, |index| {
            rar_part_path(parent, &base, &extension, index, width)
        });
    }

    if let Some(base) = parse_rar_old_numbered_name(&name) {
        let first = rar_legacy_volume_path(parent, &base, 1);
        return collect_rar_legacy_series(first, |index| {
            rar_legacy_volume_path(parent, &base, index)
        });
    }

    if let Some((base, width)) = parse_rar_numeric_name(&name) {
        let first = parent.join(format!("{base}.{:0width$}", 1, width = width));
        return collect_rar_series(first, |index| {
            parent.join(format!("{base}.{:0width$}", index, width = width))
        });
    }

    if lower.ends_with(".rar") {
        let base = &name[..name.len() - 4];
        // A modern numbered set can be opened from its familiar base path too.
        for width in 1..=6 {
            let first = rar_part_path(parent, base, &name[name.len() - 4..], 1, width);
            if first.is_file() {
                return collect_rar_series(first, |index| {
                    rar_part_path(parent, base, &name[name.len() - 4..], index, width)
                });
            }
        }

        let first = input.to_path_buf();
        if rar_legacy_volume_path(parent, base, 2).is_file() {
            return collect_rar_legacy_series(first, |index| {
                rar_legacy_volume_path(parent, base, index)
            });
        }
    }

    Ok(vec![input.to_path_buf()])
}

fn parse_rar_part_name(name: &str) -> Option<(String, String, usize)> {
    let lower = name.to_ascii_lowercase();
    if !lower.ends_with(".rar") {
        return None;
    }
    let marker = lower.rfind(".part")?;
    let digits_start = marker + ".part".len();
    let digits_end = lower.len() - ".rar".len();
    let digits = &lower[digits_start..digits_end];
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let base = name[..marker].to_string();
    let extension = name[digits_end..].to_string();
    Some((base, extension, digits.len()))
}

fn parse_rar_old_numbered_name(name: &str) -> Option<String> {
    let lower = name.to_ascii_lowercase();
    let (base, _) = name.rsplit_once('.')?;
    let lower_extension = lower.rsplit_once('.')?.1;
    (lower_extension.len() == 3
        && (b'r'..=b'z').contains(&lower_extension.as_bytes()[0])
        && lower_extension[1..]
            .bytes()
            .all(|byte| byte.is_ascii_digit()))
    .then(|| base.to_string())
}

fn parse_rar_numeric_name(name: &str) -> Option<(String, usize)> {
    let (base, extension) = name.rsplit_once('.')?;
    (extension.len() == 3 && extension.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| (base.to_string(), extension.len()))
}

fn rar_part_path(
    parent: &Path,
    base: &str,
    extension: &str,
    index: usize,
    width: usize,
) -> PathBuf {
    parent.join(format!("{base}.part{index:0width$}{extension}"))
}

fn rar_legacy_volume_path(parent: &Path, base: &str, index: usize) -> PathBuf {
    if index == 1 {
        return parent.join(format!("{base}.rar"));
    }
    let sequence = index - 2;
    let letter = char::from(b'r' + (sequence / 100) as u8);
    parent.join(format!("{base}.{letter}{:02}", sequence % 100))
}

fn collect_rar_series(
    first: PathBuf,
    mut path_for_index: impl FnMut(usize) -> PathBuf,
) -> Result<Vec<PathBuf>> {
    collect_rar_series_with_limit(first, MAX_RAR_VOLUMES, &mut path_for_index, true)
}

fn collect_rar_legacy_series(
    first: PathBuf,
    mut path_for_index: impl FnMut(usize) -> PathBuf,
) -> Result<Vec<PathBuf>> {
    collect_rar_series_with_limit(first, MAX_RAR_LEGACY_VOLUMES, &mut path_for_index, false)
}

fn collect_rar_series_with_limit(
    first: PathBuf,
    max_volumes: usize,
    path_for_index: &mut impl FnMut(usize) -> PathBuf,
    probe_past_limit: bool,
) -> Result<Vec<PathBuf>> {
    let mut paths = vec![first];
    for index in 2..=max_volumes {
        let next = path_for_index(index);
        if !next.is_file() {
            return Ok(paths);
        }
        paths.push(next);
    }
    if !probe_past_limit || !path_for_index(max_volumes + 1).is_file() {
        return Ok(paths);
    }
    Err(FormatsError::Io(io::Error::new(
        io::ErrorKind::InvalidData,
        format!("RAR set exceeds the {max_volumes} volume safety limit"),
    )))
}

fn invalid_rar_path(path: &Path, message: &str) -> FormatsError {
    FormatsError::Io(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{}: {message}", path.display()),
    ))
}

fn rar_error(error: rars::Error) -> FormatsError {
    use rars::ErrorKind;
    if matches!(
        error.kind(),
        ErrorKind::PasswordRequired | ErrorKind::BadPassword
    ) {
        FormatsError::PasswordRequired
    } else {
        FormatsError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("RAR archive: {error}"),
        ))
    }
}

fn sevenz_error(error: sevenz_rust2::Error) -> FormatsError {
    match error {
        sevenz_rust2::Error::PasswordRequired | sevenz_rust2::Error::MaybeBadPassword(_) => {
            FormatsError::PasswordRequired
        }
        other => FormatsError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("7z archive: {other}"),
        )),
    }
}

fn list_zip(archive: &Path) -> Result<Vec<EntryInfo>> {
    let file = std::io::BufReader::new(fs::File::open(archive)?);
    let mut ar = zip::ZipArchive::new(file).map_err(|e| zip_err(&e))?;
    if ar.len() > MAX_FOREIGN_ENTRIES {
        return Err(cinder_core::CinderError::DecompressionBombSuspected(
            MAX_FOREIGN_ENTRIES as u64,
        )
        .into());
    }
    let mut out = Vec::new();
    for i in 0..ar.len() {
        let f = ar.by_index(i).map_err(|e| zip_err(&e))?;
        out.push(EntryInfo {
            name: f.name().to_string(),
            size: Some(f.size()),
            packed: Some(f.compressed_size()),
            modified: last_modified_string(&f),
        });
    }
    Ok(out)
}

fn last_modified_string<R: Read>(f: &zip::read::ZipFile<R>) -> Option<String> {
    let d = f.last_modified()?;
    Some(format!(
        "{:04}-{:02}-{:02} {:02}:{:02}",
        d.year(),
        d.month(),
        d.day(),
        d.hour(),
        d.minute()
    ))
}

fn list_tar(reader: Box<dyn Read>) -> Result<Vec<EntryInfo>> {
    let mut ar = tar::Archive::new(reader);
    let mut out = Vec::new();
    for e in ar.entries().map_err(codify("tar walk"))? {
        if out.len() >= MAX_FOREIGN_ENTRIES {
            return Err(cinder_core::CinderError::DecompressionBombSuspected(
                MAX_FOREIGN_ENTRIES as u64,
            )
            .into());
        }
        let e = e.map_err(codify("tar entry"))?;
        let h = e.header();
        out.push(EntryInfo {
            name: h
                .path()
                .map_err(codify("tar path"))?
                .to_string_lossy()
                .replace('\\', "/"),
            size: Some(h.entry_size().map_err(codify("tar size"))?),
            packed: None,
            modified: mtime_string(h.mtime().unwrap_or(0)),
        });
    }
    Ok(out)
}

fn mtime_string(secs: u64) -> Option<String> {
    if secs == 0 {
        return None;
    }
    // Civil-from-days (Howard Hinnant's algorithm), no external time crate.
    let days = i64::try_from(secs / 86_400).unwrap_or(0);
    let rem = secs % 86_400;
    let hour = u32::try_from(rem / 3600).unwrap_or(23);
    let minute = u32::try_from((rem % 3600) / 60).unwrap_or(59);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let mo = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if mo <= 2 { y + 1 } else { y };
    format!("{y:04}-{mo:02}-{d:02} {hour:02}:{minute:02}").into()
}

// --------------------------------------------------------------- extract

/// Extract a whole archive into `dest_root`.
///
/// # Errors
/// Any unsafe path aborts the entire operation; see [`FormatsError::UnsafePath`].
pub fn extract(archive: &Path, dest_root: &Path, opts: &ExtractOptions) -> Result<ExtractSummary> {
    extract_selection_impl(archive, dest_root, opts, &ExtractSelection::all())
}

/// Extract only the selected members (or all when selection is empty).
///
/// # Errors
/// Same guarantees as [`extract`].
pub fn extract_selected(
    archive: &Path,
    dest_root: &Path,
    opts: &ExtractOptions,
    selection: &ExtractSelection,
) -> Result<ExtractSummary> {
    extract_selection_impl(archive, dest_root, opts, selection)
}

fn extract_selection_impl(
    archive: &Path,
    dest_root: &Path,
    opts: &ExtractOptions,
    selection: &ExtractSelection,
) -> Result<ExtractSummary> {
    let root_canonical = open_root(dest_root)?;
    let mut budget = Budget {
        spent: 0,
        cap: opts.max_total_raw,
    };
    let mut summary = ExtractSummary::default();

    match super::detect(archive) {
        Some(Format::Zip) => extract_zip(
            archive,
            &root_canonical,
            opts,
            selection,
            &mut budget,
            &mut summary,
        )?,
        Some(Format::SevenZ) => extract_sevenz(
            archive,
            &root_canonical,
            opts,
            selection,
            &mut budget,
            &mut summary,
        )?,
        Some(Format::Rar) => extract_rar(archive, &root_canonical, opts, selection, &mut summary)?,
        Some(fmt @ (Format::Tar | Format::TarGz | Format::TarZst | Format::TarXz)) => {
            let reader: Box<dyn Read> = match fmt {
                Format::Tar => Box::new(io::BufReader::new(fs::File::open(archive)?)),
                _ => open_stream_reader(archive, fmt)?,
            };
            extract_tar(
                reader,
                &root_canonical,
                opts,
                selection,
                &mut budget,
                &mut summary,
            )?;
        }
        Some(fmt @ (Format::GzSingle | Format::XzSingle | Format::ZstSingle)) => {
            let payload = super::stream_payload_name(archive);
            if !selection.allows(&payload) {
                return Ok(summary);
            }
            let mut reader = raw_file_reader(archive, fmt)?;
            let dest = entry_destination(&root_canonical, &payload)?;
            if dest.exists() && !opts.overwrite {
                return Err(refuses(&dest));
            }
            let mut out = cinder_core::extract::create_destination(&dest, opts.overwrite)?;
            let n = bounded_copy(&mut reader, &mut out, opts.max_total_raw)?;
            drop(out);
            summary.files += 1;
            summary.bytes += n;
        }
        None => {
            return Err(FormatsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unrecognized archive format: {}", archive.display()),
            )))
        }
    }
    Ok(summary)
}

fn refuses(dest: &Path) -> FormatsError {
    FormatsError::Io(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("refusing to overwrite existing {}", dest.display()),
    ))
}

fn check_overwrite(dest: &Path, opts: &ExtractOptions) -> Result<()> {
    if dest.exists() && !opts.overwrite {
        return Err(refuses(dest));
    }
    Ok(())
}

#[allow(clippy::too_many_lines)] // one branch per container family, kept linear
fn extract_zip(
    archive: &Path,
    root_canonical: &Path,
    opts: &ExtractOptions,
    selection: &ExtractSelection,
    budget: &mut Budget,
    summary: &mut ExtractSummary,
) -> Result<()> {
    let file = std::io::BufReader::new(fs::File::open(archive)?);
    let mut ar = zip::ZipArchive::new(file).map_err(|e| zip_err(&e))?;
    if ar.len() > MAX_FOREIGN_ENTRIES {
        return Err(cinder_core::CinderError::DecompressionBombSuspected(
            MAX_FOREIGN_ENTRIES as u64,
        )
        .into());
    }
    // ZIP central directories expose every member name without decompressing
    // payloads. Validate the full selected set first so a late traversal entry
    // cannot leave earlier files behind.
    for i in 0..ar.len() {
        let zf = ar.by_index(i).map_err(|e| zip_err(&e))?;
        let name = zf.name().to_string();
        if selection.allows(&name) {
            super::validate_entry_path(root_canonical, &name)?;
        }
    }
    for i in 0..ar.len() {
        let mut zf = ar.by_index(i).map_err(|e| zip_err(&e))?;
        let name = zf.name().to_string();
        if !selection.allows(&name) {
            continue;
        }
        if zf.is_dir() {
            let dir = entry_destination(root_canonical, &name)?;
            fs::create_dir_all(dir)?;
            summary.dirs += 1;
            continue;
        }
        let dest = entry_destination(root_canonical, &name)?;
        check_overwrite(&dest, opts)?;
        let declared = zf.size();
        budget.charge(declared)?;
        // Cap by the declared size (+1 probe) so a lying header cannot expand
        // beyond what was charged to the budget.
        let mut out = cinder_core::extract::create_destination(&dest, opts.overwrite)?;
        let written = bounded_copy(&mut zf, &mut out, declared)?;
        if written != declared {
            return Err(FormatsError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "zip entry ended before its declared size",
            )));
        }
        apply_mode(&dest, zf.unix_mode());
        summary.files += 1;
        summary.bytes += written;
    }
    Ok(())
}

fn extract_sevenz(
    path: &Path,
    root: &Path,
    opts: &ExtractOptions,
    selection: &ExtractSelection,
    budget: &mut Budget,
    summary: &mut ExtractSummary,
) -> Result<()> {
    let mut reader = sevenz_rust2::ArchiveReader::open(
        path,
        opts.password
            .as_deref()
            .map_or_else(sevenz_rust2::Password::empty, sevenz_rust2::Password::new),
    )
    .map_err(sevenz_error)?;
    let files = &reader.archive().files;
    if files.len() > MAX_FOREIGN_ENTRIES {
        return Err(cinder_core::CinderError::DecompressionBombSuspected(
            MAX_FOREIGN_ENTRIES as u64,
        )
        .into());
    }
    for entry in files {
        if selection.allows(&entry.name) {
            super::validate_entry_path(root, &entry.name)?;
        }
    }

    reader
        .for_each_entries(|entry, source| {
            let name = &entry.name;
            if entry.is_directory {
                if selection.allows(name) {
                    let dest = super::entry_destination(root, name)
                        .map_err(|e| io::Error::other(e.to_string()))?;
                    fs::create_dir_all(dest)?;
                    summary.dirs += 1;
                }
                return Ok(true);
            }

            let declared = entry.size;
            let dest = if selection.allows(name) {
                Some(
                    super::entry_destination(root, name)
                        .map_err(|e| io::Error::other(e.to_string()))?,
                )
            } else {
                None
            };
            if let Some(dest) = dest {
                if dest.exists() && !opts.overwrite {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("refusing to overwrite existing {}", dest.display()),
                    )
                    .into());
                }
                budget
                    .charge(declared)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let mut out = cinder_core::extract::create_destination(&dest, opts.overwrite)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                let written = bounded_copy(source, &mut out, declared)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                if written != declared {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "7z member ended before its declared size",
                    )
                    .into());
                }
                summary.files += 1;
                summary.bytes += written;
            } else {
                let remaining = budget.cap.saturating_sub(budget.spent);
                let written = bounded_copy(source, io::sink(), remaining)
                    .map_err(|e| io::Error::other(e.to_string()))?;
                budget
                    .charge(written)
                    .map_err(|e| io::Error::other(e.to_string()))?;
            }
            Ok(true)
        })
        .map_err(sevenz_error)
}

fn extract_rar(
    path: &Path,
    root: &Path,
    opts: &ExtractOptions,
    selection: &ExtractSelection,
    summary: &mut ExtractSummary,
) -> Result<()> {
    let archives = read_rar_set(path, opts.password.as_deref(), Some(opts.max_total_raw))?;
    let members = rar_volume_members(&archives)?;
    let mut entries = Vec::new();
    for member in members {
        if member.meta.is_redirection {
            continue;
        }
        let decoded = member.decoded_name(None).map_err(rar_error)?;
        let name = String::from_utf8_lossy(&decoded).into_owned();
        if selection.allows(&name) {
            super::validate_entry_path(root, &name)?;
        }
        entries.push((name, member.meta.is_directory, member.meta.unpacked_size));
    }

    let options = rar_read_options(opts.password.as_deref(), opts.max_total_raw);
    let mut next_entry = 0usize;
    rars::extract_volumes_to_with_options(&archives, options, |meta| {
        let Some((name, is_directory, unpacked_size)) = entries.get(next_entry) else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RAR volume metadata does not match extracted members",
            )
            .into());
        };
        next_entry += 1;
        if *is_directory != meta.is_directory {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RAR volume member order does not match its headers",
            )
            .into());
        }
        if !selection.allows(name) {
            return Ok(Box::new(io::sink()) as Box<dyn Write>);
        }
        if *is_directory {
            let dest = super::entry_destination(root, name)
                .map_err(|e| io::Error::other(e.to_string()))?;
            fs::create_dir_all(dest)?;
            summary.dirs += 1;
            return Ok(Box::new(io::sink()) as Box<dyn Write>);
        }

        let dest =
            super::entry_destination(root, name).map_err(|e| io::Error::other(e.to_string()))?;
        if dest.exists() && !opts.overwrite {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                format!("refusing to overwrite existing {}", dest.display()),
            )
            .into());
        }
        let out = cinder_core::extract::create_destination(&dest, opts.overwrite)
            .map_err(|e| io::Error::other(e.to_string()))?;
        summary.files += 1;
        summary.bytes = summary.bytes.saturating_add(*unpacked_size);
        Ok(Box::new(out) as Box<dyn Write>)
    })
    .map_err(rar_error)?;
    if next_entry != entries.len() {
        return Err(FormatsError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "RAR volume set ended before all members were extracted",
        )));
    }
    Ok(())
}

fn extract_tar(
    reader: Box<dyn Read>,
    root_canonical: &Path,
    opts: &ExtractOptions,
    selection: &ExtractSelection,
    budget: &mut Budget,
    summary: &mut ExtractSummary,
) -> Result<()> {
    let mut ar = tar::Archive::new(reader);
    for e in ar.entries().map_err(codify("tar walk"))? {
        let mut e = e.map_err(codify("tar entry"))?;
        let name = e
            .path()
            .map_err(codify("tar path"))?
            .to_string_lossy()
            .replace('\\', "/");
        if !selection.allows(&name) {
            continue;
        }
        let kind = e.header().entry_type();
        if kind.is_dir() {
            let dir = entry_destination(root_canonical, &name)?;
            fs::create_dir_all(dir)?;
            summary.dirs += 1;
            continue;
        }
        if kind.is_symlink() || kind == tar::EntryType::Link {
            // v1 policy: hard/symlinks are skipped rather than recreated;
            // Cinder's native format handles links with full validation.
            continue;
        }
        let dest = entry_destination(root_canonical, &name)?;
        check_overwrite(&dest, opts)?;
        let declared = e.header().entry_size().map_err(codify("tar size"))?;
        budget.charge(declared)?;
        let mut out = cinder_core::extract::create_destination(&dest, opts.overwrite)?;
        let written = bounded_copy(&mut e, &mut out, declared)?;
        if written != declared {
            return Err(FormatsError::Io(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "tar entry ended before its declared size",
            )));
        }
        apply_mode(&dest, Some(e.header().mode().unwrap_or(0o644)));
        summary.files += 1;
        summary.bytes += written;
    }
    Ok(())
}

// ------------------------------------------------------------------ test

/// Integrity-check an archive without writing anything.
///
/// Zip entries are CRC-verified by the reader; tar walks validate structure
/// and checksums; single streams are fully decoded under the ceiling.
///
/// # Errors
/// Corruption or cap breaches surface here.
pub fn test(archive: &Path, max_total_raw: u64) -> Result<TestReport> {
    test_with_password(archive, max_total_raw, None)
}

/// Integrity-check an archive, supplying a password for encrypted 7z or RAR
/// headers and members when required.
pub fn test_with_password(
    archive: &Path,
    max_total_raw: u64,
    password: Option<&str>,
) -> Result<TestReport> {
    let mut report = TestReport::default();
    match super::detect(archive) {
        Some(Format::Zip) => {
            let file = std::io::BufReader::new(fs::File::open(archive)?);
            let mut ar = zip::ZipArchive::new(file).map_err(|e| zip_err(&e))?;
            if ar.len() > MAX_FOREIGN_ENTRIES {
                return Err(cinder_core::CinderError::DecompressionBombSuspected(
                    MAX_FOREIGN_ENTRIES as u64,
                )
                .into());
            }
            let mut budget = Budget {
                spent: 0,
                cap: max_total_raw,
            };
            for i in 0..ar.len() {
                let mut zf = ar.by_index(i).map_err(|e| zip_err(&e))?;
                if !zf.is_dir() {
                    let declared = zf.size();
                    let mut sink = io::sink();
                    let remaining = max_total_raw.saturating_sub(budget.spent);
                    let n = bounded_copy(&mut zf, &mut sink, declared.min(remaining))?;
                    if n != declared {
                        return Err(FormatsError::Io(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "zip entry ended before its declared size",
                        )));
                    }
                    budget.charge(n)?;
                    report.bytes = report.bytes.checked_add(n).ok_or(
                        cinder_core::CinderError::DecompressionBombSuspected(max_total_raw),
                    )?;
                    report.entries += 1;
                }
            }
        }
        Some(Format::SevenZ) => test_sevenz(archive, max_total_raw, password, &mut report)?,
        Some(Format::Rar) => {
            let parsed = read_rar_set(archive, password, Some(max_total_raw))?;
            rars::test_volumes_with_options(&parsed, rar_read_options(password, max_total_raw))
                .map_err(rar_error)?;
            for member in rar_volume_members(&parsed)?
                .iter()
                .filter(|m| !m.meta.is_directory && !m.meta.is_redirection)
            {
                report.entries += 1;
                report.bytes = report.bytes.checked_add(member.meta.unpacked_size).ok_or(
                    cinder_core::CinderError::DecompressionBombSuspected(max_total_raw),
                )?;
            }
        }
        Some(fmt @ (Format::Tar | Format::TarGz | Format::TarZst | Format::TarXz)) => {
            let reader: Box<dyn Read> = match fmt {
                Format::Tar => Box::new(io::BufReader::new(fs::File::open(archive)?)),
                _ => open_stream_reader(archive, fmt)?,
            };
            let mut ar = tar::Archive::new(reader);
            let mut budget = Budget {
                spent: 0,
                cap: max_total_raw,
            };
            for e in ar.entries().map_err(codify("tar walk"))? {
                let mut e = e.map_err(codify("tar entry"))?;
                if e.header().entry_type().is_dir() {
                    continue;
                }
                if report.entries >= MAX_FOREIGN_ENTRIES as u64 {
                    return Err(cinder_core::CinderError::DecompressionBombSuspected(
                        MAX_FOREIGN_ENTRIES as u64,
                    )
                    .into());
                }
                let mut sink = io::sink();
                let remaining = max_total_raw.saturating_sub(budget.spent);
                let n = bounded_copy(&mut e, &mut sink, remaining)?;
                budget.charge(n)?;
                report.bytes = report.bytes.checked_add(n).ok_or(
                    cinder_core::CinderError::DecompressionBombSuspected(max_total_raw),
                )?;
                report.entries += 1;
            }
        }
        Some(fmt @ (Format::GzSingle | Format::XzSingle | Format::ZstSingle)) => {
            let mut r = raw_file_reader(archive, fmt)?;
            let mut sink = io::sink();
            report.bytes += bounded_copy(&mut r, &mut sink, max_total_raw)?;
            report.entries += 1;
        }
        None => {
            return Err(FormatsError::Io(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("unrecognized archive format: {}", archive.display()),
            )))
        }
    }
    Ok(report)
}

fn test_sevenz(
    path: &Path,
    max_total_raw: u64,
    password: Option<&str>,
    report: &mut TestReport,
) -> Result<()> {
    let mut reader = sevenz_rust2::ArchiveReader::open(
        path,
        password.map_or_else(sevenz_rust2::Password::empty, sevenz_rust2::Password::new),
    )
    .map_err(sevenz_error)?;
    if reader.archive().files.len() > MAX_FOREIGN_ENTRIES {
        return Err(cinder_core::CinderError::DecompressionBombSuspected(
            MAX_FOREIGN_ENTRIES as u64,
        )
        .into());
    }
    let mut budget = Budget {
        spent: 0,
        cap: max_total_raw,
    };
    reader
        .for_each_entries(|entry, source| {
            if entry.is_directory {
                return Ok(true);
            }
            budget
                .charge(entry.size)
                .map_err(|e| io::Error::other(e.to_string()))?;
            let written = bounded_copy(source, io::sink(), entry.size)
                .map_err(|e| io::Error::other(e.to_string()))?;
            if written != entry.size {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "7z member ended before its declared size",
                )
                .into());
            }
            report.entries += 1;
            report.bytes = report.bytes.saturating_add(written);
            Ok(true)
        })
        .map_err(sevenz_error)
}

/// Outcome of [`test`].
#[derive(Debug, Clone, Copy, Default)]
pub struct TestReport {
    pub entries: u64,
    pub bytes: u64,
}

// ---------------------------------------------------------------- create

/// Create a new archive from a file or directory tree.
///
/// Symbolic links are skipped in foreign containers (recorded in the stats);
/// use the native `.cnd` writer when link fidelity matters.
///
/// # Errors
/// IO failures during tree walk or write-out.
pub fn create(
    input: &Path,
    output: &Path,
    fmt: CreateFormat,
    opts: CreateOptions,
) -> Result<CreateStats> {
    create_paths(&[input.to_path_buf()], output, fmt, opts)
}

/// Create one archive from several selected files and folders.
///
/// Each selected item receives a top-level archive path. Overlapping names,
/// output aliases, and output paths inside a selected directory are rejected
/// before the destination is created.
pub fn create_paths(
    inputs: &[PathBuf],
    output: &Path,
    fmt: CreateFormat,
    opts: CreateOptions,
) -> Result<CreateStats> {
    if inputs.is_empty() {
        return Err(cinder_core::CinderError::InvalidInput(
            "at least one input path is required".into(),
        )
        .into());
    }
    let output_canonical = fs::canonicalize(output).ok();
    for input in inputs {
        let input_canonical = fs::canonicalize(input)?;
        if output_canonical.as_ref() == Some(&input_canonical) {
            return Err(cinder_core::CinderError::InvalidInput(
                "output must not replace an input".into(),
            )
            .into());
        }
        if input_canonical.is_dir() {
            let parent = output.parent().unwrap_or_else(|| Path::new("."));
            if fs::canonicalize(parent)?.starts_with(&input_canonical) {
                return Err(cinder_core::CinderError::InvalidInput(
                    "output must not be placed inside an input tree".into(),
                )
                .into());
            }
        }
    }
    let walked = cinder_core::walk::walk_paths(inputs)
        .map_err(|e| FormatsError::Io(e).with_context("walk inputs"))?;

    let mut stats = CreateStats::default();
    let mut symlinks_skipped = 0u64;
    for e in &walked.entries {
        match e.kind {
            cinder_core::walk::EntryKind::Dir { .. } => stats.dirs += 1,
            cinder_core::walk::EntryKind::File { size, .. } => {
                stats.files += 1;
                stats.input_bytes += size;
            }
            cinder_core::walk::EntryKind::Symlink { .. } => symlinks_skipped += 1,
        }
    }

    if fmt == CreateFormat::Rar {
        (stats.output_bytes, stats.volume_count) = create_rar(&walked.entries, output, &opts)?;
        stats.symlinks_skipped = symlinks_skipped;
        return Ok(stats);
    }

    let file = cinder_core::extract::create_destination(output, true)?;
    match fmt {
        CreateFormat::SevenZ => create_sevenz(&walked.entries, file, &opts)?,
        CreateFormat::Rar => unreachable!("RAR output was handled before opening the destination"),
        CreateFormat::Zip => create_zip(&walked.entries, file, opts)?,
        CreateFormat::Tar => {
            let builder = tar::Builder::new(BufWriter::new(file));
            append_all_then_inner(builder, &walked.entries)?;
        }
        CreateFormat::TarGz => {
            let enc = flate2::write::GzEncoder::new(
                file,
                flate2::Compression::new(level_gzip(opts.level)),
            );
            let builder = tar::Builder::new(enc);
            let enc: flate2::write::GzEncoder<fs::File> =
                append_all_then_inner(builder, &walked.entries)?;
            enc.finish().map_err(codify("gzip finish"))?;
        }
        CreateFormat::TarZst => {
            let enc = zstd::stream::Encoder::new(file, level_zstd(opts.level))
                .map_err(codify("zstd encoder"))?;
            let builder = tar::Builder::new(enc);
            let enc: zstd::stream::Encoder<'static, fs::File> =
                append_all_then_inner(builder, &walked.entries)?;
            enc.finish().map_err(codify("zstd finish"))?;
        }
        CreateFormat::TarXz => {
            let enc = liblzma::write::XzEncoder::new(file, level_gzip(opts.level));
            let builder = tar::Builder::new(enc);
            let enc = append_all_then_inner(builder, &walked.entries)?;
            enc.finish().map_err(codify("xz finish"))?;
        }
    }

    stats.output_bytes = fs::metadata(output)?.len();
    stats.volume_count = 1;
    stats.symlinks_skipped = symlinks_skipped;
    Ok(stats)
}

fn create_sevenz(
    entries: &[cinder_core::walk::WalkedEntry],
    file: fs::File,
    opts: &CreateOptions,
) -> Result<()> {
    use cinder_core::walk::EntryKind;
    use sevenz_rust2::encoder_options::{AesEncoderOptions, Lzma2Options};
    use sevenz_rust2::{ArchiveEntry, ArchiveWriter, EncoderConfiguration, Password, SourceReader};

    let mut writer = ArchiveWriter::new(file).map_err(sevenz_error)?;
    let level = opts.level.clamp(0, 9) as u32;
    let threads = opts
        .threads
        .or_else(|| std::thread::available_parallelism().ok().map(usize::from))
        .unwrap_or(1)
        .clamp(1, 64) as u32;
    let lzma = Lzma2Options::from_level_mt(level, threads, 32 * 1024 * 1024);
    let methods: Vec<EncoderConfiguration> = if let Some(pass) = &opts.password {
        vec![
            AesEncoderOptions::new(Password::new(pass)).into(),
            lzma.into(),
        ]
    } else {
        vec![lzma.into()]
    };
    writer.set_content_methods(methods);

    let mut solid_entries = Vec::new();
    let mut solid_readers = Vec::new();
    let mut solid_bytes = 0u64;
    for entry in entries {
        match &entry.kind {
            EntryKind::File { size, .. } if opts.solid && *size <= 1024 * 1024 => {
                if !solid_entries.is_empty()
                    && (solid_entries.len() >= 2048
                        || solid_bytes.saturating_add(*size) > 32 * 1024 * 1024)
                {
                    writer
                        .push_archive_entries(
                            std::mem::take(&mut solid_entries),
                            std::mem::take(&mut solid_readers),
                        )
                        .map_err(sevenz_error)?;
                    solid_bytes = 0;
                }
                solid_entries.push(ArchiveEntry::from_path(&entry.path, entry.rel_path.clone()));
                solid_readers.push(SourceReader::new(fs::File::open(&entry.path)?));
                solid_bytes = solid_bytes.saturating_add(*size);
            }
            _ => {
                if !solid_entries.is_empty() {
                    writer
                        .push_archive_entries(
                            std::mem::take(&mut solid_entries),
                            std::mem::take(&mut solid_readers),
                        )
                        .map_err(sevenz_error)?;
                    solid_bytes = 0;
                }
                match &entry.kind {
                    EntryKind::Dir { .. } => {
                        let metadata = ArchiveEntry::from_path(&entry.path, entry.rel_path.clone());
                        writer
                            .push_archive_entry::<&[u8]>(metadata, None)
                            .map_err(sevenz_error)?;
                    }
                    EntryKind::File { .. } => {
                        let metadata = ArchiveEntry::from_path(&entry.path, entry.rel_path.clone());
                        writer
                            .push_archive_entry(metadata, Some(fs::File::open(&entry.path)?))
                            .map_err(sevenz_error)?;
                    }
                    EntryKind::Symlink { .. } => {}
                }
            }
        }
    }
    if !solid_entries.is_empty() {
        writer
            .push_archive_entries(solid_entries, solid_readers)
            .map_err(sevenz_error)?;
    }
    writer
        .finish()
        .map_err(|error| FormatsError::Io(error).with_context("7z finish"))?;
    Ok(())
}

fn create_rar(
    entries: &[cinder_core::walk::WalkedEntry],
    output: &Path,
    opts: &CreateOptions,
) -> Result<(u64, u32)> {
    use cinder_core::walk::EntryKind;

    if opts.rar_volume_size.is_some() && !opts.rar_version.supports_streamed_volumes() {
        return Err(FormatsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "split RAR creation currently requires RAR 5.0 or RAR 7.0",
        )));
    }
    let password = opts.password.as_ref().map(|pass| pass.as_bytes().to_vec());
    let volume_size = opts
        .rar_volume_size
        .map(usize::try_from)
        .transpose()
        .map_err(|_| {
            FormatsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "RAR volume size exceeds this system's addressable size",
            ))
        })?;
    let version = opts.rar_version;
    let mut builder = rars::Builder::new(version.archive_version())
        .compression_level(Some(level_rar(opts.level)))
        .solid(opts.solid)
        .password(password.clone())
        .header_encryption(password.is_some() && version.supports_header_encryption())
        .volume_size(volume_size);
    for entry in entries {
        match &entry.kind {
            EntryKind::Dir { mode } => builder
                .add_directory(
                    entry.rel_path.as_bytes().to_vec(),
                    None,
                    (!matches!(
                        version,
                        RarVersion::Rar13 | RarVersion::Rar14 | RarVersion::Rar15
                    ))
                    .then_some(*mode),
                )
                .map_err(rar_error)?,
            EntryKind::File { mode, .. } => builder
                .add_source(
                    entry.rel_path.as_bytes().to_vec(),
                    rars::EntrySource::from_path(&entry.path),
                    None,
                    Some(*mode),
                )
                .map_err(rar_error)?,
            EntryKind::Symlink { .. } => continue,
        }
    }

    if volume_size.is_some() {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let staging = tempfile::tempdir_in(parent)?;
        let mut sink = DiskRarVolumeSink::new(staging.path());
        builder
            .write_volumes_to(&mut sink, &rars::WriterResources::default(), None)
            .map_err(rar_error)?;
        let completed = sink.completed.clone();
        if completed.is_empty() {
            return Err(FormatsError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "RAR writer produced no volume files",
            )));
        }
        let output_bytes = completed.iter().try_fold(0u64, |total, (_, bytes)| {
            total.checked_add(*bytes).ok_or_else(|| {
                FormatsError::Io(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "RAR volume output size overflowed",
                ))
            })
        })?;
        let count = u32::try_from(completed.len()).map_err(|_| {
            FormatsError::Io(io::Error::new(
                io::ErrorKind::InvalidData,
                "RAR writer produced too many volumes",
            ))
        })?;
        publish_rar_volumes(output, staging.path(), &completed)?;
        return Ok((output_bytes, count));
    }

    builder.write_to_path(output, None).map_err(rar_error)?;
    remove_stale_rar_parts(output)?;
    Ok((fs::metadata(output)?.len(), 1))
}

struct DiskRarVolumeSink<'a> {
    staging: &'a Path,
    completed: Vec<(u64, u64)>,
}

impl<'a> DiskRarVolumeSink<'a> {
    fn new(staging: &'a Path) -> Self {
        Self {
            staging,
            completed: Vec::new(),
        }
    }

    fn volume_path(&self, index: u64) -> PathBuf {
        self.staging.join(format!("volume-{index:06}.tmp"))
    }
}

impl rars::rar50::VolumeSink for DiskRarVolumeSink<'_> {
    fn start_volume(&mut self, index: u64) -> rars::Result<Box<dyn Write + Send>> {
        if index != self.completed.len() as u64 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RAR writer started volumes out of order",
            )
            .into());
        }
        Ok(Box::new(
            fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.volume_path(index))?,
        ))
    }

    fn finish_volume(&mut self, index: u64, len: u64) -> rars::Result<()> {
        let path = self.volume_path(index);
        let file = fs::OpenOptions::new().read(true).write(true).open(&path)?;
        file.sync_all()?;
        if file.metadata()?.len() != len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RAR writer volume length did not match bytes written",
            )
            .into());
        }
        self.completed.push((index, len));
        Ok(())
    }
}

fn publish_rar_volumes(output: &Path, staging: &Path, completed: &[(u64, u64)]) -> Result<()> {
    let finals: Vec<_> = completed
        .iter()
        .map(|(index, _)| rar_output_volume_path(output, *index as usize + 1))
        .collect();
    let existing = matching_rar_parts(output)?;
    let mut backups = Vec::new();
    let mut published = Vec::new();
    let result = (|| -> Result<()> {
        for (index, old_path) in existing.iter().enumerate() {
            let metadata = fs::symlink_metadata(old_path)?;
            if !metadata.file_type().is_file() {
                return Err(FormatsError::Io(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "refusing to replace non-file RAR volume {}",
                        old_path.display()
                    ),
                )));
            }
            let backup = staging.join(format!("backup-{index:06}.tmp"));
            fs::rename(old_path, &backup)?;
            backups.push((old_path.clone(), backup));
        }
        for ((index, _), final_path) in completed.iter().zip(&finals) {
            let staged = staging.join(format!("volume-{index:06}.tmp"));
            fs::rename(staged, final_path)?;
            published.push(final_path.clone());
        }
        Ok(())
    })();

    if let Err(error) = result {
        for path in published.iter().rev() {
            let _ = fs::remove_file(path);
        }
        for (original, backup) in backups.iter().rev() {
            let _ = fs::rename(backup, original);
        }
        return Err(error);
    }
    Ok(())
}

fn rar_output_volume_path(output: &Path, part: usize) -> PathBuf {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let base = if output
        .extension()
        .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("rar"))
    {
        output
            .file_stem()
            .unwrap_or_else(|| output.file_name().unwrap_or_default())
    } else {
        output.file_name().unwrap_or_default()
    };
    let mut name = base.to_os_string();
    name.push(format!(".part{part:02}.rar"));
    parent.join(name)
}

fn matching_rar_parts(output: &Path) -> Result<Vec<PathBuf>> {
    let parent = output
        .parent()
        .filter(|path| !path.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let Some(name) = output.file_name() else {
        return Ok(Vec::new());
    };
    let base = if output
        .extension()
        .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("rar"))
    {
        output
            .file_stem()
            .unwrap_or(name)
            .to_string_lossy()
            .into_owned()
    } else {
        name.to_string_lossy().into_owned()
    };
    let prefix = format!("{}.part", base.to_ascii_lowercase());
    let mut paths = Vec::new();
    for entry in fs::read_dir(parent)? {
        let entry = entry?;
        let child_name = entry.file_name().to_string_lossy().into_owned();
        let lower = child_name.to_ascii_lowercase();
        let Some(number_and_extension) = lower.strip_prefix(&prefix) else {
            continue;
        };
        let Some(digits) = number_and_extension.strip_suffix(".rar") else {
            continue;
        };
        if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn remove_stale_rar_parts(output: &Path) -> Result<()> {
    for path in matching_rar_parts(output)? {
        let metadata = fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return Err(FormatsError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("refusing to remove non-file RAR volume {}", path.display()),
            )));
        }
        fs::remove_file(path)?;
    }
    if output
        .extension()
        .is_some_and(|extension| extension.to_string_lossy().eq_ignore_ascii_case("rar"))
    {
        let parent = output
            .parent()
            .filter(|path| !path.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let Some(name) = output.file_stem() else {
            return Ok(());
        };
        let base = name.to_string_lossy();
        for letter in b'r'..=b'z' {
            for index in 0..100 {
                let old_volume = parent.join(format!("{base}.{}{:02}", char::from(letter), index));
                match fs::symlink_metadata(&old_volume) {
                    Ok(metadata) if metadata.file_type().is_file() => fs::remove_file(old_volume)?,
                    Ok(_) => {
                        return Err(FormatsError::Io(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            format!(
                                "refusing to remove non-file RAR volume {}",
                                old_volume.display()
                            ),
                        )))
                    }
                    Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                    Err(error) => return Err(error.into()),
                }
            }
        }
    }
    Ok(())
}

fn level_gzip(level: i32) -> u32 {
    level.clamp(1, 9) as u32
}

fn level_zstd(level: i32) -> i32 {
    level.clamp(1, 19)
}

fn level_rar(level: i32) -> u8 {
    level.clamp(0, 5) as u8
}

type TarBuilder<W> = tar::Builder<W>;

fn append_all_then_inner<W: Write>(
    mut b: TarBuilder<W>,
    entries: &[cinder_core::walk::WalkedEntry],
) -> Result<W> {
    for e in entries {
        append_tar_entry(&mut b, e)?;
    }
    b.into_inner()
        .map_err(|e| FormatsError::Io(e).with_context("tar flush"))
}

fn append_tar_entry<W: Write>(
    b: &mut TarBuilder<W>,
    e: &cinder_core::walk::WalkedEntry,
) -> Result<()> {
    use cinder_core::walk::EntryKind;
    match &e.kind {
        EntryKind::Dir { mode } => {
            let mut h = tar::Header::new_gnu();
            h.set_size(0);
            h.set_mode(*mode);
            h.set_mtime(0);
            h.set_entry_type(tar::EntryType::Directory);
            h.set_cksum();
            b.append_data(&mut h, format!("{}/", e.rel_path), io::empty())
                .map_err(codify("tar add dir"))?;
        }
        EntryKind::File { mode, .. } => {
            let md = fs::metadata(&e.path)?;
            let mtime = mtime_secs(&md);
            let mut h = tar::Header::new_gnu();
            h.set_size(md.len());
            h.set_mode(*mode);
            h.set_mtime(mtime);
            h.set_entry_type(tar::EntryType::Regular);
            h.set_cksum();
            let f = fs::File::open(&e.path)?;
            b.append_data(&mut h, &e.rel_path, f)
                .map_err(codify("tar add file"))?;
        }
        EntryKind::Symlink { .. } => {}
    }
    Ok(())
}

fn mtime_secs(md: &fs::Metadata) -> u64 {
    md.modified()
        .ok()
        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

fn create_zip(
    entries: &[cinder_core::walk::WalkedEntry],
    file: fs::File,
    opts: CreateOptions,
) -> Result<()> {
    use cinder_core::walk::EntryKind;
    let mut w = zip::ZipWriter::new(BufWriter::new(file));
    let base = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated)
        .compression_level(Some(i64::from(opts.level.clamp(1, 9))))
        .large_file(true);

    for e in entries {
        match &e.kind {
            EntryKind::Dir { mode } => {
                w.add_directory(e.rel_path.clone(), base.unix_permissions(*mode))
                    .map_err(|e| zip_err(&e))?;
            }
            EntryKind::File { mode, .. } => {
                w.start_file(e.rel_path.clone(), base.unix_permissions(*mode))
                    .map_err(|e| zip_err(&e))?;
                let mut f = fs::File::open(&e.path)?;
                io::copy(&mut f, &mut w).map_err(codify("zip payload"))?;
            }
            EntryKind::Symlink { .. } => {}
        }
    }
    w.finish().map_err(|e| zip_err(&e))?;
    Ok(())
}

#[cfg(test)]
mod rar_volume_naming_tests {
    use super::*;

    #[test]
    fn classic_volume_extensions_roll_over_after_r99() {
        let parent = Path::new("volumes");
        assert_eq!(
            rar_legacy_volume_path(parent, "set", 1),
            parent.join("set.rar")
        );
        assert_eq!(
            rar_legacy_volume_path(parent, "set", 2),
            parent.join("set.r00")
        );
        assert_eq!(
            rar_legacy_volume_path(parent, "set", 101),
            parent.join("set.r99")
        );
        assert_eq!(
            rar_legacy_volume_path(parent, "set", 102),
            parent.join("set.s00")
        );
        assert_eq!(
            rar_legacy_volume_path(parent, "set", 901),
            parent.join("set.z99")
        );
        assert_eq!(
            parse_rar_old_numbered_name("set.S00").as_deref(),
            Some("set")
        );
        assert_eq!(Format::from_extension("set.z99"), Some(Format::Rar));
    }

    #[test]
    fn legacy_path_from_after_first_hundred_parts_resolves_to_first_volume() {
        let temp = tempfile::tempdir().unwrap();
        for index in 1..=102 {
            fs::File::create(rar_legacy_volume_path(temp.path(), "set", index)).unwrap();
        }
        let paths = rar_volume_paths(&temp.path().join("set.s00")).unwrap();
        assert_eq!(paths.len(), 102);
        assert_eq!(paths.first().unwrap(), &temp.path().join("set.rar"));
        assert_eq!(paths.last().unwrap(), &temp.path().join("set.s00"));
    }
}
