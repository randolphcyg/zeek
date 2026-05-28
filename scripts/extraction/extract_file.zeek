# ScriptID: extract_file
# Type: extraction
# Category: file_extraction
# Description: Extract firmware, executables, archives, packages, disk images, and other suspicious transferred files.
# Signature: File MIME type or extension matches extraction policy and size guardrails.
# Enabled: true

@load base/frameworks/files
@load base/utils/files

module CustomExtraction;

# Tunable threshold for offline analysis.
global extract_dir = getenv("EXTRACTED_FILE_PATH") == "" ? "./extract_files" : getenv("EXTRACTED_FILE_PATH");

# Tunable threshold for offline analysis.
global min_file_size = to_count(getenv("MIN_FILE_SIZE_KB") == "" ? "1" : getenv("MIN_FILE_SIZE_KB")) * 1024;
global max_file_size = to_count(getenv("MAX_FILE_SIZE_MB") == "" ? "200" : getenv("MAX_FILE_SIZE_MB")) * 1024 * 1024;

# Suspicious or critical path policy.
redef FileExtract::prefix = extract_dir;

# Script configuration.
redef FileExtract::default_limit = max_file_size;

# ==========================================
# File extraction policy.
# ==========================================
const TARGET_MIME_TYPES: set[string] = {
    # Script configuration.
    "application/octet-stream",       # Generic binary stream; many firmware images are detected this way
    "application/x-executable",       # Linux ELF binary
    "application/macbinary",          # macOS binary
    "application/x-mach-binary",      # Mach-O
    "application/x-elf",             # ELF executable
    
    # File extraction policy.
    "application/x-dosexec",          # PE file (exe, dll, sys)
    "application/x-msdownload",       # Windows executable or installer
    "application/x-msi",              # MSI installer
    "application/vnd.microsoft.portable-executable",  # PE file
    
    # Script configuration.
    "application/vnd.android.package-archive", # Android APK
    "application/x-debian-package",            # Debian/Ubuntu DEB
    "application/x-redhat-package-manager",    # RedHat RPM
    "application/x-rpm",                      # RPM package
    
    # Script configuration.
    "application/zip",
    "application/x-gzip",
    "application/x-tar",
    "application/x-rar",
    "application/x-7z-compressed",
    "application/x-bzip2",
    "application/x-compress",
    "application/x-lzma",
    "application/x-xz",
    "application/x-zstd",
    
    # File extraction policy.
    "application/x-squashfs",
    "application/x-cpio",
    "application/x-romfs",
    "application/x-cramfs",
    "application/x-iso9660-image",
    
    # File extraction policy.
    "application/x-object",
    "application/x-sharedlib"  # .so library file
} &redef;

# File extraction policy.
const TARGET_EXTENSIONS: set[string] = {
    # Script configuration.
    "bin", "img", "rom", "dump", "flash", "fw", "firmware",
    
    # File extraction policy.
    "squashfs", "jffs2", "yaffs2", "ubifs", "ubi",
    "cramfs", "romfs", "ext2", "ext3", "ext4", "cpio", "vmdk", "qcow2",
    
    # Script configuration.
    "hex", "s19", "mot", "dfu", "uf2", "axf", "elf", "ko", "so", "ota", "mcu",
    
    # Script configuration.
    "trx", "chk", "dlf", "bix", "ipk", "ros", "npk", "ccx", "pkg", "stk",
    
    # File extraction policy.
    "apk", "deb", "rpm", "msi", "exe", "dll", "sys", "dmg", "pkg",
    "tar", "gz", "tgz", "zip", "rar", "7z", "bz2", "xz", "zst"
} &redef;

# ==========================================
# File extraction policy.
# ==========================================
function get_filename_from_stream(f: fa_file): string {
    local fname = "";
    
    # File extraction policy.
    if ( f$info?$filename && f$info$filename != "" ) {
        fname = f$info$filename;
    } 
    # Script configuration.
    else if ( f?$http && f$http?$uri ) {
        # File extraction policy.
        local uri_parts = split_string(f$http$uri, /\?/);
        if ( |uri_parts| > 0 ) {
            local path_parts = split_string(uri_parts[0], /\//);
            if ( |path_parts| > 0 ) {
                fname = path_parts[|path_parts|-1];
            }
        }
    }
    
    return to_lower(fname);
}

function generate_safe_name(f: fa_file): string {
    local fname = get_filename_from_stream(f);
    if ( fname == "" || fname == "/" ) {
        fname = fmt("binary_stream_%s", f$id);
    }
    
    # Suspicious or critical path policy.
    fname = gsub(fname, /[\/\\:*?"<>|]/, "_");
    
    return fname;
}

# ==========================================
# Detection logic.
# ==========================================
event file_sniff(f: fa_file, meta: fa_metadata) {
    local should_extract = F;
    local reason = "";

    # File extraction policy.
    if ( meta?$mime_type ) {
        local mime = to_lower(meta$mime_type);
        if ( mime in TARGET_MIME_TYPES ) {
            should_extract = T;
            reason = fmt("MIME Match: %s", mime);
        }
    }

    # File extraction policy.
    if ( !should_extract ) {
        local fname = get_filename_from_stream(f);
        if ( fname != "" ) {
            local ext_parts = split_string(fname, /\./);
            if ( |ext_parts| > 1 ) {
                local ext = ext_parts[|ext_parts|-1];
                if ( ext in TARGET_EXTENSIONS ) {
                    should_extract = T;
                    reason = fmt("Extension Fallback Match: .%s", ext);
                }
            }
        }
    }

    # Detection logic.
    if ( should_extract ) {
        Files::add_analyzer(f, Files::ANALYZER_EXTRACT);
    }
}

# ==========================================
# Detection logic.
# ==========================================
event file_state_remove(f: fa_file) {
    # File extraction policy.
    if ( !f$info?$extracted ) return;

    local orig_path = fmt("%s/%s", FileExtract::prefix, f$info$extracted);

    # Script configuration.
    if ( f?$total_bytes ) {
        # File extraction policy.
        if ( f$total_bytes < min_file_size ) {
            # Script configuration.
            local small_discard_path = fmt("%s.discard", orig_path);
            rename(orig_path, small_discard_path);
            return;
        }
        
        # File extraction policy.
        if ( f$total_bytes > max_file_size ) {
            # Script configuration.
            local large_discard_path = fmt("%s.too_large", orig_path);
            rename(orig_path, large_discard_path);
            return;
        }
    }

    # File extraction policy.
    local safe_name = generate_safe_name(f);
    local final_name = fmt("%s-%s", f$id, safe_name);
    local final_path = fmt("%s/%s", FileExtract::prefix, final_name);

    # File extraction policy.
    if ( rename(orig_path, final_path) ) {
        f$info$extracted = final_path; # Update the path recorded in Zeek logs
    }
}