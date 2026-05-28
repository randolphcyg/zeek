# ScriptID: DETECT_FILE_TAMPERING_v1
# Type: detection
# Category: system_security
# Description: Detect access or transfer patterns that suggest critical file tampering or suspicious file modification.
# Signature: Critical paths, suspicious filenames, unusual extensions, or high-frequency modifications appear in network file activity.
# NoticeTypes: FileTampering::File_Tampering_Detected, FileTampering::Suspicious_File_Modification
# Enabled: true

@load base/frameworks/notice
@load base/frameworks/files
@load base/utils/patterns

module FileTampering;

export {
    redef enum Notice::Type += {
        # File extraction policy.
        File_Tampering_Detected,
        # File extraction policy.
        Suspicious_File_Modification
    };

    # File extraction policy.
    const critical_files_unix: set[string] = {
        "/etc/passwd",
        "/etc/shadow",
        "/etc/sudoers",
        "/etc/ssh/sshd_config",
        "/etc/hosts",
        "/etc/resolv.conf"
    } &redef;

    # File extraction policy.
    const critical_files_windows: set[string] = {
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SYSTEM",
        "C:\\Windows\\System32\\config\\SOFTWARE",
        "C:\\Windows\\System32\\config\\SAM",
        "C:\\Windows\\System32\\winlogon.exe",
        "C:\\Windows\\System32\\user32.dll"
    } &redef;

    # File extraction policy.
    const critical_dirs_unix: set[string] = {
        "/etc/",
        "/usr/bin/",
        "/usr/sbin/",
        "/bin/",
        "/sbin/"
    } &redef;

    # File extraction policy.
    const critical_dirs_windows: set[string] = {
        "C:\\Windows\\System32\\",
        "C:\\Windows\\SysWOW64\\",
        "C:\\Program Files\\",
        "C:\\Program Files (x86)\\"
    } &redef;

    # File extraction policy.
    const suspicious_extensions: set[string] = {
        ".exe",
        ".dll",
        ".sys",
        ".bat",
        ".sh",
        ".ps1",
        ".vbs",
        ".pdf",
        ".zip",
        ".iso",
        ".lnk",
        ".dat",
        ".cmd"
    } &redef;

    # Suspicious or critical path policy.
    const suspicious_domains: set[string] = {
        "allertmnemonkik.com",
        "turelomi.hair",
        "lezhidov.cloud",
        "qzmeat.cyou",
        "fepopeguc.com",
        "firebasestorage.googleapis.com"
    } &redef;

    const suspicious_ips: set[addr] = {
        162.33.177.186,
        103.208.85.127,
        94.140.115.3,
        5.230.74.203,
        199.127.60.47,
        185.173.34.36
    } &redef;

    # Suspicious or critical path policy.
    const suspicious_paths: set[string] = {
        "/download/",
        "/AppData/Roaming/",
        "/AppData/Local/",
        "/OwSq1IMH1D/",
        "/uploads/",
        "/admin/",
        "/install/"
    } &redef;

    # File extraction policy.
    const suspicious_filenames: set[string] = {
        "setup.exe",
        "install.exe",
        "update.exe",
        "loader.exe",
        "payload.exe",
        "dropper.exe",
        "download.exe",
        "sg.exe",
        "file.exe"
    } &redef;

    # File extraction policy.
    # const allowed_modification_hours: interval = 9hr to 18hr &redef;

    # File extraction policy.
    const modification_frequency_threshold: interval = 30secs &redef;

    # File extraction policy.
    global file_modification_times: table[string] of time &redef;
}

# File extraction policy.
function is_suspicious_file(file_path: string): bool
    {
    # File extraction policy.
    for ( ext in suspicious_extensions )
        {
        if ( ends_with(file_path, ext) )
            return T;
        }
    return F;
}

# Detection logic.
event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    # File extraction policy.
    if ( unescaped_URI == "/etc/passwd" || unescaped_URI == "/etc/shadow" || unescaped_URI == "/Windows/System32/winlogon.exe" )
        {
        local critical_msg = fmt("Critical file download request detected: %s", unescaped_URI);
        NOTICE([$note=File_Tampering_Detected,
                $msg=critical_msg,
                $src=c$id$orig_h,
                $dst=c$id$resp_h]);
        }
    
    # Suspicious or critical path policy.
    if ( starts_with(unescaped_URI, "/etc/") || starts_with(unescaped_URI, "/Windows/System32/") )
        {
        local dir_msg = fmt("Critical directory file download request detected: %s", unescaped_URI);
        NOTICE([$note=Suspicious_File_Modification,
                $msg=dir_msg,
                $src=c$id$orig_h,
                $dst=c$id$resp_h]);
        }
    
    # Suspicious or critical path policy.
    for ( path in suspicious_paths )
        {
        if ( unescaped_URI == path || starts_with(unescaped_URI, path) )
            {
            local path_msg = fmt("Suspicious path access detected: %s", unescaped_URI);
            NOTICE([$note=Suspicious_File_Modification,
                    $msg=path_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        }
    
    # Suspicious or critical path policy.
    if ( c$id$resp_h in suspicious_ips )
        {
        local ip_msg = fmt("Suspicious IP access detected: %s", c$id$resp_h);
        NOTICE([$note=Suspicious_File_Modification,
                $msg=ip_msg,
                $src=c$id$orig_h,
                $dst=c$id$resp_h]);
        }
    
    # File extraction policy.
    for ( ext in suspicious_extensions )
        {
        if ( ends_with(unescaped_URI, ext) )
            {
            local ext_msg = fmt("Suspicious file type download detected: %s", unescaped_URI);
            NOTICE([$note=Suspicious_File_Modification,
                    $msg=ext_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        }
    
    # File extraction policy.
    for ( filename in suspicious_filenames )
        {
        if ( unescaped_URI == filename || ends_with(unescaped_URI, "/" + filename) )
            {
            local filename_msg = fmt("Suspicious filename download detected: %s", unescaped_URI);
            NOTICE([$note=Suspicious_File_Modification,
                    $msg=filename_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        }
}

# File extraction policy.
event file_state_remove(f: fa_file)
    {
    if ( ! f?$info ) return;

    # File extraction policy.
    local file_path = f$id;

    # File extraction policy.
    if ( file_path in file_modification_times )
        {
        local time_diff = current_time() - file_modification_times[file_path];
        if ( time_diff < modification_frequency_threshold )
            {
            # File extraction policy.
            for ( cid, c in f$conns )
                {
                local freq_msg = fmt("Abnormal file modification frequency: %s (interval: %s)", file_path, time_diff);
                NOTICE([$note=Suspicious_File_Modification,
                        $msg=freq_msg,
                        $src=c$id$orig_h,
                        $dst=c$id$resp_h]);
                }
            }
        }

    # File extraction policy.
    file_modification_times[file_path] = current_time();

    # File extraction policy.
    local current_time_val = current_time();
    local current_hour = strftime("%H", current_time_val);
    if ( current_hour < "09" || current_hour > "18" )
        {
        # File extraction policy.
        if ( is_suspicious_file(file_path) )
            {
            # File extraction policy.
            for ( cid, c in f$conns )
                {
                local time_msg = fmt("Suspicious file modified outside business hours: %s", file_path);
                NOTICE([$note=Suspicious_File_Modification,
                        $msg=time_msg,
                        $src=c$id$orig_h,
                        $dst=c$id$resp_h]);
                }
            }
        }

    # File extraction policy.
    if ( file_path in critical_files_unix )
        {
        # File extraction policy.
        for ( cid, c in f$conns )
            {
            local unix_msg = fmt("Unix/Linux critical file modified: %s", file_path);
            NOTICE([$note=File_Tampering_Detected,
                    $msg=unix_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        return;
        }

    # File extraction policy.
    if ( file_path in critical_files_windows )
        {
        # File extraction policy.
        for ( cid, c in f$conns )
            {
            local win_msg = fmt("Windows critical file modified: %s", file_path);
            NOTICE([$note=File_Tampering_Detected,
                    $msg=win_msg,
                    $src=c$id$orig_h,
                    $dst=c$id$resp_h]);
            }
        return;
        }

    # File extraction policy.
    for ( dir in critical_dirs_unix )
        {
        if ( starts_with(file_path, dir) )
            {
            # Suspicious or critical path policy.
            if ( is_suspicious_file(file_path) )
                {
                # File extraction policy.
                for ( cid, c in f$conns )
                    {
                    local unix_dir_msg = fmt("Suspicious file modified under Unix/Linux critical directory: %s", file_path);
                    NOTICE([$note=File_Tampering_Detected,
                            $msg=unix_dir_msg,
                            $src=c$id$orig_h,
                            $dst=c$id$resp_h]);
                    }
                return;
                }
            }
        }

    # File extraction policy.
    for ( dir in critical_dirs_windows )
        {
        if ( starts_with(file_path, dir) )
            {
            # Suspicious or critical path policy.
            if ( is_suspicious_file(file_path) )
                {
                # File extraction policy.
                for ( cid, c in f$conns )
                    {
                    local win_dir_msg = fmt("Suspicious file modified under Windows critical directory: %s", file_path);
                    NOTICE([$note=File_Tampering_Detected,
                            $msg=win_dir_msg,
                            $src=c$id$orig_h,
                            $dst=c$id$resp_h]);
                    }
                return;
                }
            }
        }
    }

# Detection logic.
event zeek_init()
    {
    # File extraction policy.
    file_modification_times = { };
    
}