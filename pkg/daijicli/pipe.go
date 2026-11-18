// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package daijicli

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// PipeStage represents one `| <op> [arg]` post-processing filter.
type PipeStage struct {
	Op  string
	Arg string
}

// SplitPipes separates a command line into base command and pipe stages, respecting quotes.
func SplitPipes(raw string) (base string, pipes []PipeStage, err error) {
	parts := splitPipeRespectQuotes(raw)
	if len(parts) == 0 {
		return "", nil, nil
	}
	base = strings.TrimSpace(parts[0])
	for _, p := range parts[1:] {
		toks := splitShellTokens(strings.TrimSpace(p))
		if len(toks) == 0 {
			return "", nil, fmt.Errorf("empty pipe stage")
		}
		op := strings.ToLower(toks[0])
		arg := ""
		if len(toks) > 1 {
			arg = strings.Join(toks[1:], " ")
		}
		switch op {
		case "include", "exclude":
			if arg == "" {
				return "", nil, fmt.Errorf("pipe %q requires a pattern argument", op)
			}
		case "count", "json":
		default:
			return "", nil, fmt.Errorf("unsupported pipe operator %q (supported: include, exclude, count, json)", op)
		}
		pipes = append(pipes, PipeStage{Op: op, Arg: arg})
	}
	return base, pipes, nil
}

// ApplyPipes transforms rendered text (or structured data for `| json`) across pipe stages.
func ApplyPipes(humanText string, structuredData any, pipes []PipeStage) (string, error) {
	wantsJSON := false
	var lineFilters []PipeStage
	for _, st := range pipes {
		if st.Op == "json" {
			wantsJSON = true
			continue
		}
		lineFilters = append(lineFilters, st)
	}

	out := humanText
	if wantsJSON {
		if structuredData != nil {
			b, err := json.MarshalIndent(structuredData, "", "  ")
			if err != nil {
				return "", err
			}
			out = string(b)
		} else {
			lines := nonEmptyLines(humanText)
			b, _ := json.MarshalIndent(map[string]any{"lines": lines}, "", "  ")
			out = string(b)
		}
	}

	for _, st := range lineFilters {
		lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
		switch st.Op {
		case "include":
			pat := strings.ToLower(st.Arg)
			var kept []string
			for _, ln := range lines {
				if strings.Contains(strings.ToLower(ln), pat) {
					kept = append(kept, ln)
				}
			}
			out = strings.Join(kept, "\n")
		case "exclude":
			pat := strings.ToLower(st.Arg)
			var kept []string
			for _, ln := range lines {
				if !strings.Contains(strings.ToLower(ln), pat) {
					kept = append(kept, ln)
				}
			}
			out = strings.Join(kept, "\n")
		case "count":
			cnt := 0
			for _, ln := range lines {
				if strings.TrimSpace(ln) != "" {
					cnt++
				}
			}
			out = strconv.Itoa(cnt)
		}
	}
	return out, nil
}

func splitPipeRespectQuotes(s string) []string {
	var parts []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			cur.WriteByte(c)
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			cur.WriteByte(c)
			continue
		}
		if c == '|' {
			parts = append(parts, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteByte(c)
	}
	parts = append(parts, cur.String())
	return parts
}

func splitShellTokens(s string) []string {
	var toks []string
	var cur strings.Builder
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			if c == quote {
				quote = 0
				continue
			}
			cur.WriteByte(c)
			continue
		}
		if c == '"' || c == '\'' {
			quote = c
			continue
		}
		if c == ' ' || c == '\t' {
			if cur.Len() > 0 {
				toks = append(toks, cur.String())
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		toks = append(toks, cur.String())
	}
	return toks
}

func nonEmptyLines(s string) []string {
	var out []string
	for _, ln := range strings.Split(s, "\n") {
		if strings.TrimSpace(ln) != "" {
			out = append(out, ln)
		}
	}
	return out
}
