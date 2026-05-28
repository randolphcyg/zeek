# ScriptID: DETECT_SYN_FLOOD_v1
# Type: detection
# Category: dos
# Description: Detect TCP SYN flood behavior based on half-open connection attempts.
# Signature: Many SYN packets do not complete TCP handshakes within the configured interval.
# NoticeTypes: SynFlood::SynFlood
# Enabled: true

@load base/frameworks/sumstats
@load base/frameworks/notice

module SynFlood;

export {
    redef enum Notice::Type += { SynFlood };
    const syn_flood_threshold: double = 100.0 &redef;
    const check_interval: interval = 10sec &redef;
}

event zeek_init() {
    local r1 = SumStats::Reducer($stream="syn.flood", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="syn-flood-detect",
        $epoch=check_interval,
        $reducers=set(r1),
        $threshold=syn_flood_threshold,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return result["syn.flood"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note=SynFlood,
                $msg=fmt("SYN flood detected: source %s", key$host),
                $src=key$host
            ]);
        }
    ]);
}

event new_packet(c: connection, p: pkt_hdr) {
    if ( ! c?$id ) return;
    # Script configuration.
    if ( p?$tcp && p$tcp$flags == 2 ) {
        SumStats::observe("syn.flood", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
    }
}