# ScriptID: DETECT_HTTP_UA_v1
# Type: detection
# Category: web_recon
# Description: Detect known scanner, automation, and attack-tool User-Agent values.
# Signature: The HTTP User-Agent contains tools such as sqlmap, nmap, masscan, curl, wget, or similar frameworks.
# NoticeTypes: Detect_HTTP_UA::Suspicious_User_Agent
# Enabled: true

@load base/protocols/http
@load base/frameworks/notice

module Detect_HTTP_UA;

export {
    redef enum Notice::Type += { Suspicious_User_Agent };
    const suspicious_agents: set[string] = {
        "curl", "wget", "python-requests", "masscan",
        "sqlmap", "nmap", "nikto", "gobuster", "hydra",
        "zgrab", "morfeus", "jorgee", "zmap", "acas",
        "nessus", "openvas", "pangolin"
    };
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( ! is_orig ) return;
    if ( name == "USER-AGENT" ) {
        local ua = to_lower(value);
        for ( agent in suspicious_agents ) {
            if ( agent in ua ) {
                NOTICE([
                    $note = Suspicious_User_Agent,
                    $msg = fmt("Suspicious User-Agent detected (scanner or attack tool): %s", ua),
                    $sub = fmt("Matched Keyword: %s", agent),
                    $conn = c,
                    $uid = c$uid
                ]);
                break;
            }
        }
    }
}