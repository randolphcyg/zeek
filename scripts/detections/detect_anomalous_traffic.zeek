# ScriptID: DETECT_ANOMALOUS_TRAFFIC_v1
# Type: detection
# Category: traffic_anomaly
# Description: Detect hosts with unusually high byte volume or connection volume in offline traffic.
# Signature: A host exceeds byte or connection thresholds within the capture window.
# NoticeTypes: AnomalousTraffic::Anomalous_Traffic_Detected
# Enabled: true

@load base/frameworks/notice

module AnomalousTraffic;

export {
    redef enum Notice::Type += {
        # Detection logic.
        Anomalous_Traffic_Detected
    };

    # Tunable threshold for offline analysis.
    const traffic_threshold: count = 4 * 1024 * 1024 &redef;
}

global ip_traffic: table[addr] of count = {};
global alerted_hosts: set[addr] = set();

event connection_state_remove(c: connection)
    {
    local total_bytes = c$orig$size + c$resp$size;

    if ( c$id$orig_h in ip_traffic )
        ip_traffic[c$id$orig_h] += total_bytes;
    else
        ip_traffic[c$id$orig_h] = total_bytes;

    if ( c$id$orig_h in alerted_hosts || ip_traffic[c$id$orig_h] < traffic_threshold )
        return;

    NOTICE([$note=Anomalous_Traffic_Detected,
            $msg=fmt("Anomalous traffic detected: host %s transferred %.2f MB", c$id$orig_h, ip_traffic[c$id$orig_h] / 1048576.0),
            $src=c$id$orig_h,
            $conn=c,
            $uid=c$uid]);
    add alerted_hosts[c$id$orig_h];
    }

event zeek_done()
    {
    for ( ip in ip_traffic )
        {
        if ( ip in alerted_hosts || ip_traffic[ip] < traffic_threshold )
            next;

        NOTICE([$note=Anomalous_Traffic_Detected,
                $msg=fmt("Anomalous traffic detected: host %s transferred %.2f MB", ip, ip_traffic[ip] / 1048576.0),
                $src=ip]);
        add alerted_hosts[ip];
        }
    }