# ScriptID: DETECT_SQLI_WEBSHELL_v1
# Type: detection
# Category: web_attack
# Description: Detect SQL injection payloads that attempt file writes or webshell placement.
# Signature: HTTP parameters contain INTO OUTFILE, INTO DUMPFILE, UNION SELECT, or web-root script-drop patterns.
# NoticeTypes: Detect_SQLi_Webshell::SQLi_Write_File
# Enabled: true

@load base/protocols/http
@load base/frameworks/notice

module Detect_SQLi_Webshell;

export {
    redef enum Notice::Type += { SQLi_Write_File };
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    local uri = to_lower(unescaped_URI);

    if ( "into outfile" in uri || "into dumpfile" in uri ) {
        NOTICE([
            $note = SQLi_Write_File,
            $msg = "SQL injection file-write attempt detected (possible webshell upload)",
            $sub = fmt("Payload: %s", original_URI),
            $conn = c,
            $uid = c$uid
        ]);
    } else if ( "union select" in uri ) {
        NOTICE([
            $note = SQLi_Write_File,
            $msg = "SQL injection detected (UNION SELECT)",
            $sub = fmt("Payload: %s", original_URI),
            $conn = c,
            $uid = c$uid
        ]);
    }
}