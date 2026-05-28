package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

type CachedResult struct {
	PcapHash    string           `json:"pcap_hash"`
	ScriptsHash string           `json:"scripts_hash"`
	Result      *ExecutionResult `json:"result"`
}

type ResultCache struct {
	cache map[string]*CachedResult
}

func NewResultCache() *ResultCache {
	return &ResultCache{
		cache: make(map[string]*CachedResult),
	}
}

func (rc *ResultCache) Get(pcapPath string, scripts []string) *CachedResult {
	key := rc.cacheKey(pcapPath, scripts)
	return rc.cache[key]
}

func (rc *ResultCache) Set(pcapPath string, scripts []string, result *ExecutionResult) {
	key := rc.cacheKey(pcapPath, scripts)
	rc.cache[key] = &CachedResult{
		PcapHash:    pcapPath,
		ScriptsHash: strings.Join(scripts, ","),
		Result:      result,
	}
}

func (rc *ResultCache) cacheKey(pcapPath string, scripts []string) string {
	scriptStr := strings.Join(scripts, ",")
	return fmt.Sprintf("%s::%s", pcapPath, scriptStr)
}

func GetPcapInfo(pcapPath string) (*PcapInfo, error) {
	return getPcapInfo(pcapPath, false)
}

func GetPcapInfoForInspection(pcapPath string) (*PcapInfo, error) {
	return getPcapInfo(pcapPath, true)
}

func getPcapInfo(pcapPath string, zeekFallback bool) (*PcapInfo, error) {
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

	cmd := exec.Command("capinfos", "-c", "-d", "-u", "-e", pcapPath)
	output, capinfosErr := cmd.CombinedOutput()
	packetCountKnown := false
	if capinfosErr != nil && len(output) == 0 {
		info.Warnings = append(info.Warnings, fmt.Sprintf("capinfos is unavailable or failed: %s", capinfosErr.Error()))
	}

	if len(output) > 0 {
		scanner := bufio.NewScanner(strings.NewReader(string(output)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.Contains(line, "Number of packets") && info.PacketCount == 0 {
				fmt.Sscanf(line, "Number of packets: %d", &info.PacketCount)
				packetCountKnown = true
			}
			if strings.Contains(line, "Capture duration") && info.Duration == 0 {
				fmt.Sscanf(line, "Capture duration: %f", &info.Duration)
				info.DurationKnown = true
			}
		}
	}

	cmd2 := exec.Command("tshark", "-r", pcapPath, "-q", "-z", "io,phs")
	output2, tsharkErr := cmd2.Output()
	if tsharkErr != nil {
		info.Warnings = append(info.Warnings, fmt.Sprintf("tshark is unavailable or failed: %s", tsharkErr.Error()))
	}
	if output2 != nil {
		scanner := bufio.NewScanner(strings.NewReader(string(output2)))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			for _, proto := range knownProtocols {
				if strings.Contains(strings.ToLower(line), strings.ToLower(proto)) {
					info.Protocols = appendIfMissing(info.Protocols, proto)
				}
			}
		}
	}

	if info.PacketCount == 0 {
		cmd3 := exec.Command("capinfos", "-c", pcapPath)
		output3, err := cmd3.Output()
		if err == nil && output3 != nil {
			fmt.Sscanf(string(output3), "Number of packets: %d", &info.PacketCount)
			packetCountKnown = true
		}
	}

	if zeekFallback && (len(info.Protocols) == 0 || !info.DurationKnown) {
		enrichPcapInfoFromZeek(info, pcapPath)
	}

	if !info.DurationKnown {
		info.Warnings = append(info.Warnings, "capture duration is unavailable")
	}
	if len(info.Protocols) == 0 {
		info.Warnings = append(info.Warnings, "no supported protocol summary was detected")
	}
	if packetCountKnown && info.PacketCount <= 1 && len(info.Protocols) == 0 {
		info.Analyzable = false
		info.AnalysisStatus = "insufficient_traffic"
		info.Warnings = append(info.Warnings, "pcap has too little analyzable traffic for Zeek detection scripts")
	}

	return info, nil
}

func enrichPcapInfoFromZeek(info *PcapInfo, pcapPath string) {
	workDir, err := os.MkdirTemp("", "zeek_mcp_inspect_")
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

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "zeek", "-C", "-r", pcapPath, localZeekCfg)
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

	if applyZeekLogMetadata(info, workDir) {
		info.Warnings = append(info.Warnings, "used Zeek log metadata fallback because capinfos/tshark metadata was incomplete")
	}
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
		records := readZeekJSONRecords(path, 512)
		if len(records) == 0 {
			continue
		}
		metadataFound = true
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

	connRecords := readZeekJSONRecords(filepath.Join(workDir, "conn.log"), 2048)
	if len(connRecords) > 0 {
		metadataFound = true
		for _, record := range connRecords {
			updateTS(record["ts"])
			if proto, ok := record["proto"].(string); ok && proto != "" {
				info.Protocols = appendIfMissing(info.Protocols, proto)
			}
			if service, ok := record["service"].(string); ok && service != "" {
				info.Services = appendIfMissing(info.Services, service)
			}
		}
	}

	sort.Strings(info.Protocols)
	sort.Strings(info.Services)
	if !info.DurationKnown && minTS > 0 && maxTS >= minTS {
		info.Duration = maxTS - minTS
		info.DurationKnown = true
	}
	return metadataFound
}

func readZeekJSONRecords(path string, limit int) []map[string]interface{} {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var records []map[string]interface{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var record map[string]interface{}
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			continue
		}
		records = append(records, record)
		if limit > 0 && len(records) >= limit {
			break
		}
	}
	return records
}

var knownProtocols = []string{
	"tcp", "udp", "dns", "http", "https", "ssh", "smtp", "ftp",
	"smb", "dhcp", "arp", "icmp", "tls", "ssl", "modbus", "mqtt",
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
