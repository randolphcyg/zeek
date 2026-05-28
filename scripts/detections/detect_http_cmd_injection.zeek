# ScriptID: DETECT_HTTP_CMD_INJECT_v1
# Type: detection
# Category: web_attack
# Description: Detect Shellshock and Unix command-injection payloads in HTTP URIs and headers.
# Signature: HTTP parameters or headers contain shell metacharacters, command names, sensitive file reads, or Shellshock payloads.
# NoticeTypes: UnixCommand::UnixCommandInjection
# Enabled: true

@load base/frameworks/notice
@load base/protocols/http

module UnixCommand;

export {
    redef enum Notice::Type += { UnixCommandInjection };
    type Sig: record { regex: pattern; name: string; };
    type SigVec: vector of Sig;

    global sigs = SigVec(
        [$regex = /\(\)\s*\{\s*:;\s*\};/, $name = "Shellshock"],
        [$regex = /(\/bin\/sh|\/bin\/bash|cmd\.exe)/, $name = "System Shell"],
        [$regex = /(cat%20\/etc\/passwd|\/etc\/shadow|cat \/etc\/passwd)/, $name = "Sensitive File Access"],
        [$regex = /\.\.\/\.\.\//, $name = "Directory Traversal"],
        [$regex = /(;|\||`|\$|\(|\)|%0a|%0d).*?(wget|curl|nc|netcat|ping|whoami|id)/, $name = "Command Chaining"]
    );
}

function check_injection(c: connection, value: string, source_type: string) {
    for (i in sigs) {
        local sig = sigs[i];
        if (sig$regex in value) {
            NOTICE([
                $note = UnixCommandInjection,
                $msg = fmt("Unix command-injection attempt detected in %s (signature: %s)", source_type, sig$name),
                $sub = fmt("Payload: %s", value),
                $conn = c,
                $uid = c$uid
            ]);
            break;
        }
    }
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    check_injection(c, unescaped_URI, "HTTP URI");
    if (original_URI != unescaped_URI) check_injection(c, original_URI, "HTTP URI (Original)");
}

event http_header(c: connection, is_orig: bool, name: string, value: string) {
    if ( is_orig ) check_injection(c, value, fmt("HTTP Header (%s)", name));
}