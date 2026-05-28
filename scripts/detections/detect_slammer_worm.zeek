# ScriptID: DETECT_SLAMMER_v1
# Type: detection
# Category: worm
# Description: Detect UDP/1434 traffic patterns associated with SQL Slammer worm propagation.
# Signature: High-frequency small UDP packets target port 1434.
# NoticeTypes: Detect_Slammer::Slammer_Worm_Activity
# Enabled: true

@load base/frameworks/notice

module Detect_Slammer;

export {
    redef enum Notice::Type += { Slammer_Worm_Activity };
    const target_port: port = 1434/udp;
}

event new_packet(c: connection, p: pkt_hdr) {
    if ( ! c?$id ) return;
    if ( c$id$resp_p == target_port ) {
        NOTICE([
            $note = Slammer_Worm_Activity,
            $msg = "Possible SQL Slammer worm traffic detected",
            $sub = fmt("Target Port: 1434/UDP, Src: %s", c$id$orig_h),
            $conn = c,
            $uid = c$uid
        ]);
    }
}