# ScriptID: DETECT_HTTP_WEBSHELL_v1
# Type: detection
# Category: web_attack
# Description: Detect suspicious HTTP POST or PUT file uploads with risky MIME types or script extensions.
# Signature: HTTP uploads include PHP, JSP, executable, shell-script, or other high-risk file indicators.
# NoticeTypes: HTTP_Upload::Suspicious_File_Upload
# Enabled: true

@load base/frameworks/notice
@load base/protocols/http
@load base/frameworks/files

module HTTP_Upload;

export {
    redef enum Notice::Type += { Suspicious_File_Upload };
    const suspicious_mimes: set[string] = { "application/x-dosexec", "application/x-executable", "text/x-php", "application/x-php", "text/x-ruby", "text/x-perl", "text/x-shellscript", "application/java-archive", "application/jsp" };
    const suspicious_exts: set[string] = { "php", "php5", "phtml", "jsp", "jspx", "asp", "aspx", "exe", "sh", "pl", "py", "war" };
}

event file_sniff(f: fa_file, meta: fa_metadata) {
    if ( ! meta?$mime_type ) return;
    local mime = meta$mime_type;

    for ( cid, c in f$conns ) {
        if ( ! c?$http ) next;
        if ( c$http$method != "POST" && c$http$method != "PUT" ) next;

        local is_suspicious = F;
        local reason = "";
        local fname = "<unknown>";
        if ( f?$info && f$info?$filename ) fname = f$info$filename;
        else if ( f?$source ) fname = f$source;

        if ( mime in suspicious_mimes ) {
            is_suspicious = T;
            reason = fmt("Detected Suspicious MIME: %s", mime);
        }
        if ( ! is_suspicious && fname != "<unknown>" ) {
            local parts = split_string(fname, /\./);
            if ( |parts| > 1 ) {
                local ext = to_lower(parts[|parts|-1]);
                if ( ext in suspicious_exts ) {
                    is_suspicious = T;
                    reason = fmt("Detected Suspicious Extension: .%s", ext);
                }
            }
        }

        if ( is_suspicious ) {
            NOTICE([$note=Suspicious_File_Upload, $msg=fmt("Suspicious web file upload detected: %s", reason), $sub=fmt("Filename: %s", fname), $conn=c, $uid=c$uid]);
            break;
        }
    }
}