# ScriptID: DETECT_BULK_DOWNLOAD_v1
# Type: detection
# Category: file_download
# Description: Detect high-frequency or high-volume downloads of firmware, executable, archive, or other sensitive file types.
# Signature: A source downloads many watched file types or a large response byte volume in a short window.
# NoticeTypes: BulkDownload::Bulk_File_Download, BulkDownload::High_Volume_Download
# Enabled: true

@load base/frameworks/notice
@load base/frameworks/sumstats
@load base/frameworks/files

module BulkDownload;

export {
    redef enum Notice::Type += {
        # File extraction policy.
        Bulk_File_Download,
        # Script configuration.
        High_Volume_Download
    };

    # File extraction policy.
    const file_count_threshold: double = 50.0 &redef;

    # Tunable threshold for offline analysis.
    const byte_count_threshold: double = 104857600.0 &redef;

    # Tunable threshold for offline analysis.
    const observation_window: interval = 5 mins &redef;

    # File extraction policy.
    # Script configuration.
    # File extraction policy.
    const watch_mime_types: set[string] = {
        "application/pdf",
        "application/zip",
        "application/x-dosexec",
        "application/x-gzip",
        "application/x-tar",
        "application/vnd.ms-excel",
        "application/msword"
    } &redef;
}

event zeek_init()
    {
    # File extraction policy.
    local r_files: SumStats::Reducer = [$stream="bulk.download.files", $apply=set(SumStats::SUM)];
    SumStats::create([$name="detect_bulk_files",
                      $epoch=observation_window,
                      $reducers=set(r_files),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["bulk.download.files"]$sum;
                          },
                      $threshold=file_count_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local msg = fmt("Host %s downloaded sensitive files within %s: %.0f files", key$host, observation_window, result["bulk.download.files"]$sum);
                          NOTICE([$note=Bulk_File_Download,
                                  $msg=msg,
                                  $src=key$host]);
                          }]);

    # Detection logic.
    local r_bytes: SumStats::Reducer = [$stream="bulk.download.bytes", $apply=set(SumStats::SUM)];
    SumStats::create([$name="detect_bulk_bytes",
                      $epoch=observation_window,
                      $reducers=set(r_bytes),
                      $threshold_val(key: SumStats::Key, result: SumStats::Result) =
                          {
                          return result["bulk.download.bytes"]$sum;
                          },
                      $threshold=byte_count_threshold,
                      $threshold_crossed(key: SumStats::Key, result: SumStats::Result) =
                          {
                          local msg = fmt("Host %s downloaded data within %s: %.2f MB", key$host, observation_window, result["bulk.download.bytes"]$sum / 1048576.0);
                          NOTICE([$note=High_Volume_Download,
                                  $msg=msg,
                                  $src=key$host]);
                          }]);
    }

# Detection logic.
event connection_state_remove(c: connection)
    {
    # Script configuration.
    if ( c$resp$size > 0 )
        {
        # Script configuration.
        SumStats::observe("bulk.download.bytes", [$host=c$id$orig_h], [$num=c$resp$size]);
        }
    }

# File extraction policy.
event file_state_remove(f: fa_file)
    {
    if ( ! f?$info ) return;

    # File extraction policy.
    # Script configuration.
    if ( f$info?$mime_type && |watch_mime_types| > 0 && f$info$mime_type !in watch_mime_types )
        return;

    # File extraction policy.
    local downloaders: set[addr];

    # File extraction policy.
    for ( cid, c in f$conns )
        {
        # Script configuration.
        add downloaders[c$id$orig_h];
        }

    # Tunable threshold for offline analysis.
    for ( rx in downloaders )
        {
        SumStats::observe("bulk.download.files", [$host=rx], [$num=1]);
        }
    }
