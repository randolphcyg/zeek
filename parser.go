package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type PcapInfo struct {
	FileSize       int64    `json:"file_size"`
	PacketCount    int      `json:"packet_count"`
	Duration       float64  `json:"duration_sec"`
	DurationKnown  bool     `json:"duration_known"`
	Sampled        bool     `json:"sampled,omitempty"`
	Protocols      []string `json:"protocols"`
	TopTalkers     []Talker `json:"top_talkers"`
	Services       []string `json:"services"`
	Analyzable     bool     `json:"analyzable"`
	AnalysisStatus string   `json:"analysis_status"`
	Warnings       []string `json:"warnings,omitempty"`
}

type Talker struct {
	IP          string `json:"ip"`
	PacketsSent int    `json:"packets_sent"`
	BytesSent   int    `json:"bytes_sent"`
}

// GetPcapInfo collects pcap metadata using capinfos (fast path) with Zeek fallback
// for protocol and duration data when capinfos is unavailable or incomplete.
func GetPcapInfo(pcapPath string) (*PcapInfo, error) {
	if _, err := os.Stat(pcapPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("pcap file not found: %s", pcapPath)
	}

	info := &PcapInfo{
		Analyzable:     true,
		AnalysisStatus: "ok",
		Protocols:      []string{},
		TopTalkers:     []Talker{},
		Services:       []string{},
	}

	stat, err := os.Stat(pcapPath)
	if err == nil {
		info.FileSize = stat.Size()
	}

	// Fast path: use capinfos for packet count and duration
	cmd := exec.Command("capinfos", "-c", "-d", "-u", "-e", pcapPath)
	output, capinfosErr := cmd.CombinedOutput()
	if capinfosErr != nil && len(output) == 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("capinfos is unavailable: %s", capinfosErr.Error()))
	}

	if len(output) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Number of packets") && info.PacketCount == 0 {
				fmt.Sscanf(line, "Number of packets: %d", &info.PacketCount)
			}
			if strings.Contains(line, "Capture duration") && info.Duration == 0 {
				fmt.Sscanf(line, "Capture duration: %f", &info.Duration)
				info.DurationKnown = true
			}
		}
	}

	// Always fall back to Zeek for protocol info and any missing metadata.
	// This removes the dependency on tshark and works even when capinfos is unavailable.
	enrichPcapInfoFromZeek(info, pcapPath)

	if !info.DurationKnown {
		info.Warnings = append(info.Warnings, "capture duration is unavailable")
	}
	if len(info.Protocols) == 0 {
		info.Warnings = append(info.Warnings, "no supported protocol summary was detected")
	}

	return info, nil
}

func enrichPcapInfoFromZeek(info *PcapInfo, pcapPath string) {
	workDir, err := os.MkdirTemp("", "zeek_inspect_")
	if err != nil {
		info.Warnings = append(info.Warnings, fmt.Sprintf("zeek metadata fallback could not create a work directory: %s", err.Error()))
		return
	}
	defer os.RemoveAll(workDir)

	localZeekCfg := filepath.Join(workDir, "local.zeek")
	if err := os.WriteFile(localZeekCfg, []byte("redef LogAscii::use_json = T;\nredef Log::default_rotation_interval = 0 secs;\n"), 0644); err != nil {
		info.Warnings = append(info.Warnings, fmt.Sprintf("zeek metadata fallback could not write config: %s", err.Error()))
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(envInt("ZEEK_INSPECT_TIMEOUT_SECONDS", 60))*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, envOrDefault("ZEEK_BINARY", "zeek"), "-C", "-r", pcapPath, localZeekCfg)
	cmd.Dir = workDir
	output, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(output))
		if msg == "" {
			msg = err.Error()
		}
		if ctx.Err() == context.DeadlineExceeded {
			msg = "metadata fallback timed out"
		}
		info.Warnings = append(info.Warnings, fmt.Sprintf("zeek metadata fallback failed: %s", msg))
		return
	}

	applyZeekLogMetadata(info, workDir)
}

func applyZeekLogMetadata(info *PcapInfo, workDir string) bool {
	type logHint struct {
		name      string
		protocols []string
		services  []string
	}

	hints := []logHint{
		{name: "dns", protocols: []string{"dns", "udp"}, services: []string{"dns"}},
		{name: "http", protocols: []string{"http", "tcp"}, services: []string{"http"}},
		{name: "ssl", protocols: []string{"ssl", "tls", "tcp"}, services: []string{"ssl"}},
		{name: "x509", protocols: []string{"tls"}},
		{name: "ssh", protocols: []string{"ssh", "tcp"}, services: []string{"ssh"}},
		{name: "smtp", protocols: []string{"smtp", "tcp"}, services: []string{"smtp"}},
		{name: "ntp", protocols: []string{"ntp", "udp"}, services: []string{"ntp"}},
		{name: "ntp_control", protocols: []string{"ntp", "udp"}, services: []string{"ntp"}},
		{name: "ntp_private", protocols: []string{"ntp", "udp"}, services: []string{"ntp"}},
		{name: "smb_files", protocols: []string{"smb", "tcp"}, services: []string{"smb"}},
		{name: "smb_mapping", protocols: []string{"smb", "tcp"}, services: []string{"smb"}},
		{name: "rdp", protocols: []string{"rdp", "tcp"}, services: []string{"rdp"}},
		{name: "tunnel", protocols: []string{"tunnel"}},
		{name: "files", protocols: []string{"files"}},
		{name: "weird", protocols: []string{"weird"}},
		{name: "notice", protocols: []string{"notice"}},
	}

	metadataFound := false
	var minTS, maxTS float64
	var maxConnEndTS float64
	updateTS := func(v interface{}) {
		ts, ok := v.(float64)
		if !ok || ts <= 0 {
			return
		}
		if minTS == 0 || ts < minTS {
			minTS = ts
		}
		if ts > maxTS {
			maxTS = ts
		}
	}

	for _, hint := range hints {
		path := filepath.Join(workDir, hint.name+".log")
		if _, err := os.Stat(path); err != nil {
			continue
		}
		records, sampled := readZeekJSONRecords(path, 512)
		if len(records) == 0 {
			continue
		}
		metadataFound = true
		if sampled {
			info.Sampled = true
			info.Warnings = append(info.Warnings, fmt.Sprintf("capture metadata for %s is based on a sample of the log", hint.name))
		}
		for _, proto := range hint.protocols {
			info.Protocols = appendIfMissing(info.Protocols, proto)
		}
		for _, service := range hint.services {
			info.Services = appendIfMissing(info.Services, service)
		}
		for _, record := range records {
			updateTS(record["ts"])
		}
	}

	connRecords, connSampled := readZeekJSONRecords(filepath.Join(workDir, "conn.log"), 2048)
	connComplete := !connSampled
	if len(connRecords) > 0 {
		metadataFound = true
		if connSampled {
			info.Sampled = true
			info.Warnings = append(info.Warnings, "conn metadata is based on a sample of the log")
		}
		for _, record := range connRecords {
			updateTS(record["ts"])
			if proto, ok := record["proto"].(string); ok && proto != "" {
				info.Protocols = appendIfMissing(info.Protocols, proto)
			}
			if service, ok := record["service"].(string); ok && service != "" {
				info.Services = appendIfMissing(info.Services, service)
			}
			ts, tsOK := record["ts"].(float64)
			duration, durOK := record["duration"].(float64)
			if tsOK && durOK && duration >= 0 && ts+duration > maxConnEndTS {
				maxConnEndTS = ts + duration
			}
		}
	}

	sort.Strings(info.Protocols)
	sort.Strings(info.Services)
	if !info.DurationKnown && minTS > 0 {
		spanEnd := maxTS
		if maxConnEndTS > spanEnd {
			spanEnd = maxConnEndTS
		}
		if spanEnd >= minTS {
			info.Duration = spanEnd - minTS
			info.DurationKnown = true
			if !connComplete {
				info.Warnings = append(info.Warnings, "capture duration is estimated from sampled log records and may be shorter than the real capture")
			}
		}
	}
	return metadataFound
}

func readZeekJSONRecords(path string, limit int) ([]map[string]interface{}, bool) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false
	}
	defer f.Close()

	var records []map[string]interface{}
	truncated := false
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	readLine := func() (map[string]interface{}, bool) {
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			var record map[string]interface{}
			if err := json.Unmarshal([]byte(line), &record); err != nil {
				continue
			}
			return record, true
		}
		return nil, false
	}
	for {
		record, ok := readLine()
		if !ok {
			break
		}
		records = append(records, record)
		if limit > 0 && len(records) >= limit {
			if _, more := readLine(); more {
				truncated = true
			}
			break
		}
	}
	if err := scanner.Err(); err != nil {
		slog.Warn("failed to read Zeek log completely", "path", path, "error", err)
		return records, true
	}
	return records, truncated
}

func appendIfMissing(slice []string, s string) []string {
	for _, v := range slice {
		if strings.EqualFold(v, s) {
			return slice
		}
	}
	return append(slice, s)
}

func ParseZeekJSONLine(line string) (map[string]interface{}, error) {
	line = strings.TrimSpace(line)
	if line == "" || strings.HasPrefix(line, "#") {
		return nil, fmt.Errorf("skip line")
	}

	var result map[string]interface{}
	if err := json.Unmarshal([]byte(line), &result); err != nil {
		return nil, err
	}

	return result, nil
}

func FormatAlertsJSON(alerts []StandardAlert) string {
	data, _ := json.MarshalIndent(alerts, "", "  ")
	return string(data)
}

func FormatResultJSON(result *ExecutionResult) string {
	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data)
}
