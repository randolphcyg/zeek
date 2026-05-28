# ScriptID: DETECT_HTTP_BRUTE_FORCE_v1
# Type: detection
# Category: brute_force
# Description: Detect repeated HTTP authentication failures against login endpoints.
# Signature: A source repeatedly requests login paths and receives failure status codes within the configured window.
# NoticeTypes: HTTPBruteForce::HTTP_Brute_Force_Detected
# Enabled: true

@load base/protocols/http
@load base/frameworks/notice

module HTTPBruteForce;

export {
    redef enum Notice::Type += {
        # Detection logic.
        HTTP_Brute_Force_Detected
    };

    const failure_threshold: count = 5 &redef;
    const time_window: interval = 60sec &redef;
    const failure_status_codes: set[count] = { 401, 403 } &redef;

    const login_paths: set[string] = {
        "/login",
        "/signin",
        "/auth",
        "/login.php",
        "/signin.php",
        "/auth.php",
        "/wp-login.php",
        "/admin",
        "/admin/login",
        "/admin/signin",
        "/admin/auth"
    } &redef;

    type FailureInfo: record {
        failure_count: count;
        first_attempt: time;
        last_attempt: time;
        alerted: bool;
    };

    global failure_info: table[addr] of FailureInfo = {};
    global login_attempts: table[string] of string = {};
}

function is_login_path(uri: string): bool
    {
    return uri in login_paths;
    }

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
    {
    if ( is_login_path(original_URI) )
        login_attempts[c$uid] = original_URI;
    }

event http_reply(c: connection, version: string, code: count, reason: string)
    {
    if ( c$uid !in login_attempts || code !in failure_status_codes )
        return;

    local src_ip = c$id$orig_h;
    local now = network_time();
    local uri = login_attempts[c$uid];

    if ( src_ip in failure_info && now - failure_info[src_ip]$first_attempt <= time_window )
        {
        failure_info[src_ip]$failure_count += 1;
        failure_info[src_ip]$last_attempt = now;
        }
    else
        {
        failure_info[src_ip] = FailureInfo($failure_count=1, $first_attempt=now, $last_attempt=now, $alerted=F);
        }

    if ( failure_info[src_ip]$failure_count >= failure_threshold && ! failure_info[src_ip]$alerted )
        {
        NOTICE([$note=HTTP_Brute_Force_Detected,
                $msg=fmt("HTTP brute-force attempt detected: host %s had login failures within %s: %d failures, latest URL %s",
                         src_ip, time_window, failure_info[src_ip]$failure_count, uri),
                $src=src_ip,
                $conn=c,
                $uid=c$uid]);
        failure_info[src_ip]$alerted = T;
        }
    }

event connection_state_remove(c: connection)
    {
    if ( c$uid in login_attempts )
        delete login_attempts[c$uid];
    }
