# ScriptID: DETECT_SSH_FILE_TRANSFER_v1
# Type: detection
# Category: data_exfiltration
# Description: Detect unusually large one-way data transfer over authenticated SSH sessions.
# Signature: An authenticated SSH connection transfers more than the configured byte threshold in one direction.
# NoticeTypes: SSH_SCP::Suspicious_SCP_Transfer
# Enabled: true

@load base/frameworks/notice
@load base/protocols/ssh

module SSH_SCP;

export {
    redef enum Notice::Type += { Suspicious_SCP_Transfer };
    const TRANSFER_THRESHOLD: count = 1024 * 1024 &redef;
}

global auth_ssh_conns: set[string];

function is_ssh_connection(c: connection): bool {
    if ( c$id$resp_p == 22/tcp ) return T;
    if ( c?$service && "ssh" in c$service ) return T;
    return F;
}

event ssh_auth_successful(c: connection, auth_method_none: bool) {
    add auth_ssh_conns[c$uid];
}

event connection_state_remove(c: connection) {
    if ( c$uid !in auth_ssh_conns && ! is_ssh_connection(c) ) return;
    if ( c$uid in auth_ssh_conns ) delete auth_ssh_conns[c$uid];

    local bytes_orig = c$orig$size;
    local bytes_resp = c$resp$size;
    local is_suspicious = F;
    local direction = "";
    local size_mb = 0.0;

    if ( bytes_orig > TRANSFER_THRESHOLD ) {
        is_suspicious = T;
        direction = "Upload (Client->Server)";
        size_mb = bytes_orig / 1024.0 / 1024.0;
    } else if ( bytes_resp > TRANSFER_THRESHOLD ) {
        is_suspicious = T;
        direction = "Download (Server->Client)";
        size_mb = bytes_resp / 1024.0 / 1024.0;
    }

    if ( is_suspicious ) {
        NOTICE([
            $note = Suspicious_SCP_Transfer,
            $msg = fmt("Large SSH data transfer detected, possible SCP/SFTP: %s", direction),
            $sub = fmt("Size: %.2f MB, Threshold: %d Bytes", size_mb, TRANSFER_THRESHOLD),
            $src = c$id$orig_h,
            $dst = c$id$resp_h,
            $conn = c,
            $uid = c$uid
        ]);
    }
}