# ScriptID: DETECT_HTTP_FLOOD_v1
# Type: detection
# Category: dos
# Description: Detect high-rate HTTP requests that may indicate CC or HTTP DoS activity.
# Signature: A source exceeds the configured HTTP request threshold within the configured interval.
# NoticeTypes: HTTP_DoS::HTTP_CC_Attack
# Enabled: true

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/protocols/http

module HTTP_DoS;

export {
    redef enum Notice::Type += { HTTP_CC_Attack };
    const HTTP_THRESHOLD: double = 100.0 &redef;
    const CHECK_INTERVAL: interval = 10sec &redef;
}

event zeek_init() {
    local r1 = SumStats::Reducer($stream="http.flood", $apply=set(SumStats::SUM));
    SumStats::create([
        $name="http-flood-detect", $epoch=CHECK_INTERVAL, $reducers=set(r1), $threshold=HTTP_THRESHOLD,
        $threshold_val(key: SumStats::Key, result: SumStats::Result): double = { return result["http.flood"]$sum; },
        $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = {
            NOTICE([
                $note = HTTP_CC_Attack,
                $msg = fmt("HTTP CC/DoS activity detected: source %s sent %.0f requests in a short window", key$host, result["http.flood"]$sum),
                $src = key$host
            ]);
        }
    ]);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string) {
    SumStats::observe("http.flood", SumStats::Key($host=c$id$orig_h), SumStats::Observation($num=1));
}