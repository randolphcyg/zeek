package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type PathMap struct {
	HostPrefix      string `json:"host_prefix"`
	ContainerPrefix string `json:"container_prefix"`
}

type PathResolver struct {
	maps []PathMap
}

type PathResolution struct {
	Requested string `json:"requested_path"`
	Resolved  string `json:"resolved_path"`
	Mapped    bool   `json:"mapped"`
}

type PathResolutionError struct {
	Field     string
	Path      string
	Resolved  string
	Mappings  []PathMap
	Operation string
}

func (e *PathResolutionError) Error() string {
	if len(e.Mappings) == 0 {
		return fmt.Sprintf("%s %q is not accessible and no path maps are configured", e.Field, e.Path)
	}
	return fmt.Sprintf("%s %q is not accessible inside the container; mount it or pass a path under one of the configured host prefixes", e.Field, e.Path)
}

func NewPathResolver(maps []PathMap) *PathResolver {
	cleaned := normalizePathMaps(maps)
	return &PathResolver{maps: cleaned}
}

func ParsePathMaps(values []string, envValue string) ([]PathMap, error) {
	var raw []string
	raw = append(raw, values...)
	for _, item := range strings.Split(envValue, ",") {
		item = strings.TrimSpace(item)
		if item != "" {
			raw = append(raw, item)
		}
	}

	var maps []PathMap
	for _, item := range raw {
		parts := strings.SplitN(item, "=", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, fmt.Errorf("invalid path map %q, expected host_prefix=container_prefix", item)
		}
		maps = append(maps, PathMap{
			HostPrefix:      strings.TrimSpace(parts[0]),
			ContainerPrefix: strings.TrimSpace(parts[1]),
		})
	}
	return normalizePathMaps(maps), nil
}

func (r *PathResolver) ResolveExisting(field, requested string) (PathResolution, error) {
	resolution := r.resolve(requested, true)
	if _, err := os.Stat(resolution.Resolved); err == nil {
		return resolution, nil
	}
	return resolution, &PathResolutionError{
		Field:     field,
		Path:      requested,
		Resolved:  resolution.Resolved,
		Mappings:  r.maps,
		Operation: "read",
	}
}

func (r *PathResolver) ResolveWritable(field, requested string) (PathResolution, error) {
	resolution := r.resolve(requested, false)
	parent := filepath.Dir(resolution.Resolved)
	if _, err := os.Stat(parent); err == nil {
		return resolution, nil
	}
	return resolution, &PathResolutionError{
		Field:     field,
		Path:      requested,
		Resolved:  resolution.Resolved,
		Mappings:  r.maps,
		Operation: "write",
	}
}

func (r *PathResolver) Mappings() []PathMap {
	result := make([]PathMap, len(r.maps))
	copy(result, r.maps)
	return result
}

func (r *PathResolver) RecommendedIntakeDirs() []string {
	seen := make(map[string]bool)
	var dirs []string
	for _, m := range r.maps {
		if strings.Contains(strings.ToLower(m.ContainerPrefix), "output") {
			continue
		}
		for _, dir := range []string{m.HostPrefix, m.ContainerPrefix} {
			if dir != "" && !seen[dir] {
				dirs = append(dirs, dir)
				seen[dir] = true
			}
		}
	}
	return dirs
}

func (r *PathResolver) resolve(requested string, onlyWhenMissing bool) PathResolution {
	resolution := PathResolution{
		Requested: requested,
		Resolved:  requested,
	}

	if onlyWhenMissing {
		if _, err := os.Stat(requested); err == nil {
			return resolution
		}
	}

	cleanRequested := filepath.Clean(requested)
	for _, m := range r.maps {
		if !pathHasPrefix(cleanRequested, m.HostPrefix) {
			continue
		}
		rel, err := filepath.Rel(m.HostPrefix, cleanRequested)
		if err != nil {
			continue
		}
		if rel == "." {
			resolution.Resolved = m.ContainerPrefix
		} else {
			resolution.Resolved = filepath.Join(m.ContainerPrefix, rel)
		}
		resolution.Mapped = true
		return resolution
	}

	return resolution
}

func normalizePathMaps(maps []PathMap) []PathMap {
	result := make([]PathMap, 0, len(maps))
	for _, m := range maps {
		host := filepath.Clean(strings.TrimSpace(m.HostPrefix))
		container := filepath.Clean(strings.TrimSpace(m.ContainerPrefix))
		if host == "." || container == "." {
			continue
		}
		result = append(result, PathMap{
			HostPrefix:      host,
			ContainerPrefix: container,
		})
	}
	sort.Slice(result, func(i, j int) bool {
		return len(result[i].HostPrefix) > len(result[j].HostPrefix)
	})
	return result
}

func pathHasPrefix(path, prefix string) bool {
	if path == prefix {
		return true
	}
	rel, err := filepath.Rel(prefix, path)
	if err != nil {
		return false
	}
	return rel != "." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && rel != ".."
}
