package main

import (
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestWithTimeoutSharesSemaphore(t *testing.T) {
	parent := NewExecutor(ExecutorConfig{ZeekBinary: "/usr/bin/zeek", Timeout: 30 * time.Second})
	derived := parent.WithTimeout(5 * time.Second)
	if derived.sem == nil {
		t.Fatal("WithTimeout must preserve the parent semaphore; a nil semaphore blocks token acquisition until timeout")
	}
	if derived.sem != parent.sem {
		t.Fatal("WithTimeout must share the parent semaphore channel")
	}
	if cap(derived.sem) != cap(parent.sem) {
		t.Errorf("derived semaphore capacity = %d, want %d", cap(derived.sem), cap(parent.sem))
	}
	if derived.config.Timeout != 5*time.Second {
		t.Errorf("derived timeout = %v, want 5s", derived.config.Timeout)
	}
	if derived.config.ZeekBinary != parent.config.ZeekBinary {
		t.Errorf("derived zeek binary = %q, want %q", derived.config.ZeekBinary, parent.config.ZeekBinary)
	}
}

func TestZeekCompatibility(t *testing.T) {
	parts := strings.SplitN(TargetZeekLTS, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("TargetZeekLTS %q is not a x.y.z version", TargetZeekLTS)
	}
	patch, err := strconv.Atoi(parts[2])
	if err != nil {
		t.Fatalf("TargetZeekLTS patch %q is not numeric", parts[2])
	}
	sameLine := fmt.Sprintf("%s.%s.%d", parts[0], parts[1], patch+1)
	otherMajor := "8"
	if parts[0] == "8" {
		otherMajor = "7"
	}
	otherLine := fmt.Sprintf("%s.0.9", otherMajor)

	tests := []struct {
		name         string
		runtime      string
		want         string
		wantWarnings bool
	}{
		{"empty version", "", "unknown", true},
		{"target lts exact", "zeek version " + TargetZeekLTS, "target_lts", false},
		{"same lts line patch", "zeek version " + sameLine, "same_lts_line", false},
		{"same lts line build suffix", "zeek version " + TargetZeekLTS + "-7", "same_lts_line", false},
		{"different lts line", "zeek version " + otherLine, "runtime_differs_from_target_lts", true},
		{"unparseable output", "error: command failed to start", "unknown", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, warnings := zeekCompatibility(tt.runtime)
			if status != tt.want {
				t.Errorf("zeekCompatibility(%q) status = %q, want %q", tt.runtime, status, tt.want)
			}
			if tt.wantWarnings && len(warnings) == 0 {
				t.Errorf("zeekCompatibility(%q) expected warnings", tt.runtime)
			}
			if !tt.wantWarnings && len(warnings) != 0 {
				t.Errorf("zeekCompatibility(%q) unexpected warnings: %v", tt.runtime, warnings)
			}
		})
	}
}

func TestSameZeekLTSLine(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"9.0.0", "9.0.1", true},
		{"9.0.0", "9.1.0", false},
		{"9.0.0", "8.0.9", false},
		{"9.0.0", "9.0.0", true},
		{"", "9.0.0", false},
		{"9.0.0", "", false},
	}
	for _, tt := range tests {
		if got := sameZeekLTSLine(tt.a, tt.b); got != tt.want {
			t.Errorf("sameZeekLTSLine(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestNoticePort(t *testing.T) {
	tests := []struct {
		name  string
		value interface{}
		want  int
	}{
		{"float64", float64(443), 443},
		{"string port only", "443", 443},
		{"string port proto", "443/tcp", 443},
		{"string udp proto", "53/udp", 53},
		{"invalid string", "tcp", 0},
		{"nil", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := noticePort(tt.value); got != tt.want {
				t.Errorf("noticePort(%v) = %d, want %d", tt.value, got, tt.want)
			}
		})
	}
}

func TestNoticePortProto(t *testing.T) {
	tests := []struct {
		name      string
		value     interface{}
		wantProto string
		wantOK    bool
	}{
		{"tcp", "443/tcp", "tcp", true},
		{"udp", "53/udp", "udp", true},
		{"port only", "443", "", false},
		{"trailing slash", "443/", "", false},
		{"not a string", 443, "", false},
		{"nil", nil, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			proto, ok := noticePortProto(tt.value)
			if proto != tt.wantProto || ok != tt.wantOK {
				t.Errorf("noticePortProto(%v) = (%q, %v), want (%q, %v)", tt.value, proto, ok, tt.wantProto, tt.wantOK)
			}
		})
	}
}

func TestParseNoticeLogSrcDstFallback(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "notice.log")
	content := `{"ts":1700000000.5,"uid":"Cx1","note":"Zeek7::Flow","msg":"src/dst style","src":"10.0.0.1","dst":"10.0.0.2","src_p":"443/tcp","dst_p":"80/tcp"}
{"ts":1700000001.5,"uid":"Cx2","note":"Classic::Flow","msg":"id style","id.orig_h":"192.168.0.1","id.resp_h":"192.168.0.2","id.orig_p":1234,"id.resp_p":80,"proto":"tcp"}
{"ts":1700000002.5,"uid":"Cx3","note":"NoAddr::Flow","msg":"no addresses"}
`
	if err := os.WriteFile(logPath, []byte(content), 0644); err != nil {
		t.Fatalf("write notice log: %v", err)
	}

	e := &Executor{}
	alerts := e.parseNoticeLog(logPath, nil, map[string]FlowRefV2{})
	if len(alerts) != 3 {
		t.Fatalf("got %d alerts, want 3", len(alerts))
	}

	fallback := alerts[0]
	if fallback.Src.IP != "10.0.0.1" || fallback.Dst.IP != "10.0.0.2" {
		t.Errorf("fallback src/dst = %q/%q, want 10.0.0.1/10.0.0.2", fallback.Src.IP, fallback.Dst.IP)
	}
	if fallback.Src.Port != 443 || fallback.Dst.Port != 80 {
		t.Errorf("fallback ports = %d/%d, want 443/80", fallback.Src.Port, fallback.Dst.Port)
	}
	if fallback.Proto != "tcp" {
		t.Errorf("fallback proto = %q, want tcp (derived from src_p)", fallback.Proto)
	}
	if fallback.Evidence["src_ip"] != "10.0.0.1" || fallback.Evidence["dst_ip"] != "10.0.0.2" {
		t.Errorf("fallback evidence = %v, want src_ip/dst_ip recorded", fallback.Evidence)
	}
	if fallback.IOCs == nil || len(fallback.IOCs.IPs) != 2 {
		t.Errorf("fallback IOCs = %+v, want 2 IPs", fallback.IOCs)
	}

	classic := alerts[1]
	if classic.Src.IP != "192.168.0.1" || classic.Dst.IP != "192.168.0.2" {
		t.Errorf("classic src/dst = %q/%q, want 192.168.0.1/192.168.0.2", classic.Src.IP, classic.Dst.IP)
	}
	if classic.Src.Port != 1234 || classic.Dst.Port != 80 {
		t.Errorf("classic ports = %d/%d, want 1234/80", classic.Src.Port, classic.Dst.Port)
	}
	if classic.Proto != "tcp" {
		t.Errorf("classic proto = %q, want tcp", classic.Proto)
	}

	noAddr := alerts[2]
	if noAddr.Src.IP != "" || noAddr.Dst.IP != "" {
		t.Errorf("noAddr src/dst = %q/%q, want empty", noAddr.Src.IP, noAddr.Dst.IP)
	}
	if noAddr.IOCs != nil {
		t.Errorf("noAddr IOCs = %+v, want nil", noAddr.IOCs)
	}
}

func TestReadZeekJSONRecordsTruncationBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "test.log")
	var b strings.Builder
	for i := 0; i < 3; i++ {
		fmt.Fprintf(&b, "{\"n\":%d}\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0644); err != nil {
		t.Fatalf("write log: %v", err)
	}

	records, truncated := readZeekJSONRecords(path, 3)
	if truncated {
		t.Error("reading exactly limit records must not be flagged truncated")
	}
	if len(records) != 3 {
		t.Errorf("records = %d, want 3", len(records))
	}

	records, truncated = readZeekJSONRecords(path, 2)
	if !truncated {
		t.Error("reading fewer records than the file contains must be flagged truncated")
	}
	if len(records) != 2 {
		t.Errorf("records = %d, want 2", len(records))
	}

	records, truncated = readZeekJSONRecords(path, 10)
	if truncated {
		t.Error("reading more records than the file contains must not be flagged truncated")
	}
	if len(records) != 3 {
		t.Errorf("records = %d, want 3", len(records))
	}

	if err := os.WriteFile(path, []byte("# comment\n{\"n\":1}\n# c2\n{\"n\":2}\n"), 0644); err != nil {
		t.Fatalf("rewrite log: %v", err)
	}
	records, truncated = readZeekJSONRecords(path, 2)
	if truncated {
		t.Error("comment lines must not count toward the record limit")
	}
	if len(records) != 2 {
		t.Errorf("records = %d, want 2", len(records))
	}
}

func TestApplyZeekLogMetadataDurationFromConn(t *testing.T) {
	dir := t.TempDir()
	conn := `{"ts":100.0,"uid":"C1","proto":"udp","duration":10.0}
{"ts":105.0,"uid":"C2","proto":"tcp","duration":20.0,"service":"http"}
`
	if err := os.WriteFile(filepath.Join(dir, "conn.log"), []byte(conn), 0644); err != nil {
		t.Fatalf("write conn log: %v", err)
	}

	info := &PcapInfo{}
	if !applyZeekLogMetadata(info, dir) {
		t.Fatal("expected metadata to be found")
	}
	if !info.DurationKnown {
		t.Fatal("expected duration to be estimated from conn.log")
	}
	if info.Duration != 25.0 {
		t.Errorf("duration = %v, want 25 (max conn end ts 125 - min ts 100)", info.Duration)
	}
	if info.Sampled {
		t.Error("complete conn.log must not set Sampled")
	}
	if len(info.Warnings) != 0 {
		t.Errorf("unexpected warnings: %v", info.Warnings)
	}
}

func TestApplyZeekLogMetadataSampledFlag(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 2049; i++ {
		fmt.Fprintf(&b, "{\"ts\":%d.0,\"duration\":0.0}\n", 100+i)
	}
	if err := os.WriteFile(filepath.Join(dir, "conn.log"), []byte(b.String()), 0644); err != nil {
		t.Fatalf("write conn log: %v", err)
	}

	info := &PcapInfo{}
	applyZeekLogMetadata(info, dir)
	if !info.Sampled {
		t.Error("Sampled must be set when conn.log exceeds the read limit")
	}
	foundSamplingWarning := false
	for _, w := range info.Warnings {
		if strings.Contains(w, "sample") {
			foundSamplingWarning = true
		}
	}
	if !foundSamplingWarning {
		t.Errorf("expected a sampling warning, got %v", info.Warnings)
	}
}

func TestCopyLocalScriptsStagingError(t *testing.T) {
	workDir := t.TempDir()
	scriptDir := t.TempDir()
	good := filepath.Join(scriptDir, "good.zeek")
	if err := os.WriteFile(good, []byte("event zeek_init() { }"), 0644); err != nil {
		t.Fatalf("write script: %v", err)
	}
	missing := filepath.Join(scriptDir, "missing.zeek")

	e := NewExecutor(ExecutorConfig{ZeekBinary: "zeek", Timeout: time.Second})
	staged, errs := e.copyLocalScripts(workDir, []string{good, missing})
	if len(staged) != 1 {
		t.Fatalf("staged scripts = %v, want exactly the good script", staged)
	}
	if len(errs) != 1 {
		t.Fatalf("staging errors = %v, want 1", errs)
	}
	if errs[0].Script != "missing.zeek" {
		t.Errorf("error script = %q, want missing.zeek", errs[0].Script)
	}
	if errs[0].ErrorType != "staging_failed" {
		t.Errorf("error type = %q, want staging_failed", errs[0].ErrorType)
	}
	if errs[0].Message == "" {
		t.Error("staging error message must not be empty")
	}
}

func TestApplyRunResultStagingErrors(t *testing.T) {
	result := &ExecutionResult{Errors: []ExecutionError{}}
	run := zeekRun{
		StagingErrors: []ExecutionError{
			{Script: "broken.zeek", ErrorType: "staging_failed", Message: "read failure"},
		},
	}
	e := &Executor{}
	e.applyRunResult(result, run, time.Now(), []string{"a.zeek", "b.zeek", "broken.zeek"}, "")
	if result.Statistics.TotalScriptsRun != 2 {
		t.Errorf("total_scripts_run = %d, want 2 (3 selected minus 1 staging failure)", result.Statistics.TotalScriptsRun)
	}
	if len(result.Errors) != 1 {
		t.Fatalf("result errors = %v, want 1 staging error", result.Errors)
	}
	if result.Errors[0].Script != "broken.zeek" || result.Errors[0].ErrorType != "staging_failed" {
		t.Errorf("result error = %+v, want broken.zeek staging_failed", result.Errors[0])
	}
	if result.Status != "completed" {
		t.Errorf("status = %q, want completed when zeek itself ran fine", result.Status)
	}
}

func TestRunZeekPcapReplay(t *testing.T) {
	zeekBin, err := exec.LookPath(envOrDefault("ZEEK_BINARY", "zeek"))
	if err != nil {
		t.Skipf("zeek binary not available, skipping pcap replay integration test: %v", err)
	}
	pcapPath := filepath.Join(t.TempDir(), "sample.pcap")
	if err := writeMinimalUDPPcap(pcapPath); err != nil {
		t.Fatalf("write pcap: %v", err)
	}

	parent := NewExecutor(ExecutorConfig{ZeekBinary: zeekBin, Timeout: 2 * time.Minute})
	executor := parent.WithTimeout(2 * time.Minute)
	run := executor.runZeek(context.Background(), pcapPath, nil, "", nil, nil, false)
	defer run.cleanup()
	if run.Err != nil {
		t.Fatalf("runZeek failed: %v\nstderr: %s", run.Err, run.Stderr)
	}

	connPath := filepath.Join(run.WorkDir, "conn.log")
	if _, err := os.Stat(connPath); err != nil {
		t.Fatalf("conn.log missing after replay: %v\nstderr: %s", err, run.Stderr)
	}
	records, truncated := readZeekJSONRecords(connPath, 100)
	if len(records) == 0 {
		t.Fatalf("conn.log has no records; stderr: %s", run.Stderr)
	}
	if truncated {
		t.Error("conn.log should not be flagged truncated for a single-flow pcap")
	}
	if got := records[0]["id.orig_h"]; got != "192.168.1.10" {
		t.Errorf("id.orig_h = %v, want 192.168.1.10", got)
	}
	if got := records[0]["id.resp_h"]; got != "192.168.1.20" {
		t.Errorf("id.resp_h = %v, want 192.168.1.20", got)
	}
	if got := records[0]["proto"]; got != "udp" {
		t.Errorf("proto = %v, want udp", got)
	}
}

func writeMinimalUDPPcap(path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	var w []byte
	put32 := func(v uint32) { w = binary.LittleEndian.AppendUint32(w, v) }
	put16 := func(v uint16) { w = binary.LittleEndian.AppendUint16(w, v) }

	put32(0xa1b2c3d4)
	put16(2)
	put16(4)
	put32(0)
	put32(0)
	put32(65535)
	put32(1)

	eth := make([]byte, 14)
	copy(eth[0:6], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01})
	copy(eth[6:12], []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x02})
	eth[12], eth[13] = 0x08, 0x00

	payload := make([]byte, 12)
	totalLen := 20 + 8 + len(payload)

	ip := make([]byte, 20)
	ip[0] = 0x45
	ip[2] = byte(totalLen >> 8)
	ip[3] = byte(totalLen)
	ip[4], ip[5] = 0x12, 0x34
	ip[6] = 0x40
	ip[8] = 64
	ip[9] = 17
	ip[12], ip[13], ip[14], ip[15] = 192, 168, 1, 10
	ip[16], ip[17], ip[18], ip[19] = 192, 168, 1, 20

	udp := make([]byte, 8)
	udp[0], udp[1] = 0xD4, 0x31
	udp[2], udp[3] = 0xD4, 0x32
	udp[4] = byte((8 + len(payload)) >> 8)
	udp[5] = byte(8 + len(payload))

	frame := append(append(append(eth, ip...), udp...), payload...)

	ts := uint32(1700000000)
	put32(ts)
	put32(0)
	put32(uint32(len(frame)))
	put32(uint32(len(frame)))
	w = append(w, frame...)

	_, err = f.Write(w)
	return err
}
