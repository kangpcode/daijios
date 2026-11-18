// SPDX-License-Identifier: Apache-2.0
// DaijiOS — Ecosystem by kangpcode (Dhafa Nazula Permadi)

package secreconcile

import (
	"fmt"
	"strconv"

	"github.com/kangpcode/daijios/pkg/secplan"
)

// BuildQoSCommands returns deterministic, idempotent Linux tc commands implementing
// HTB, CAKE, fq_codel, queue trees, simple queues with burst, and PCQ-like per-IP fairness.
func BuildQoSCommands(cfg *secplan.SecurityConfig) [][]string {
	var cmds [][]string

	htbRoots := make(map[string]bool)
	// 1. Interface-level root shapers (CAKE / HTB / fq_codel) + ingress IFB shaping.
	for _, qi := range cfg.QoS.Interfaces {
		switch qi.Scheduler {
		case "cake":
			args := []string{
				"qdisc", "replace", "dev", qi.Interface, "root", "cake",
				"bandwidth", fmt.Sprintf("%dkbit", qi.UploadKbps),
				defaultOr(qi.Diffserv, "diffserv4"),
				fmt.Sprintf("rtt %dms", maxInt(qi.RTTMS, 10)),
			}
			if qi.OverheadBytes > 0 {
				args = append(args, "overhead", strconv.Itoa(qi.OverheadBytes))
			}
			if qi.NATMode {
				args = append(args, "nat")
			}
			cmds = append(cmds, args)
		case "fq_codel":
			cmds = append(cmds, []string{"qdisc", "replace", "dev", qi.Interface, "root", "fq_codel"})
		case "htb":
			htbRoots[qi.Interface] = true
			cmds = append(cmds,
				[]string{"qdisc", "replace", "dev", qi.Interface, "root", "handle", "1:", "htb", "default", "99"},
				[]string{"class", "replace", "dev", qi.Interface, "parent", "1:", "classid", "1:1", "htb",
					"rate", fmt.Sprintf("%dkbit", qi.UploadKbps), "ceil", fmt.Sprintf("%dkbit", qi.UploadKbps)},
			)
		}

		// Ingress shaping via IFB device when download_kbps is specified.
		if qi.DownloadKbps > 0 {
			ifb := "ifb-" + qi.Interface
			if len(ifb) > 15 {
				ifb = ifb[:15]
			}
			cmds = append(cmds,
				[]string{"qdisc", "replace", "dev", qi.Interface, "handle", "ffff:", "ingress"},
				[]string{"filter", "replace", "dev", qi.Interface, "parent", "ffff:", "matchall",
					"action", "mirred", "egress", "redirect", "dev", ifb},
				[]string{"qdisc", "replace", "dev", ifb, "root", "cake",
					"bandwidth", fmt.Sprintf("%dkbit", qi.DownloadKbps), "ingress"},
			)
		}
	}

	// 2. Queue trees (hierarchical HTB classes keyed by firewall fwmark).
	for i, qt := range cfg.QoS.QueueTrees {
		if !htbRoots[qt.ParentInterface] {
			htbRoots[qt.ParentInterface] = true
			cmds = append(cmds,
				[]string{"qdisc", "replace", "dev", qt.ParentInterface, "root", "handle", "1:", "htb", "default", "99"},
				[]string{"class", "replace", "dev", qt.ParentInterface, "parent", "1:", "classid", "1:1", "htb",
					"rate", fmt.Sprintf("%dkbit", qt.CeilKbps), "ceil", fmt.Sprintf("%dkbit", qt.CeilKbps)},
			)
		}
		cid := qt.ClassID
		if cid <= 0 {
			cid = 10 + i
		}
		classID := fmt.Sprintf("1:%d", cid)
		args := []string{
			"class", "replace", "dev", qt.ParentInterface, "parent", "1:1", "classid", classID, "htb",
			"rate", fmt.Sprintf("%dkbit", qt.RateKbps),
			"ceil", fmt.Sprintf("%dkbit", qt.CeilKbps),
			"prio", strconv.Itoa(maxInt(qt.Priority, 1)),
		}
		if qt.BurstBytes > 0 {
			args = append(args, "burst", strconv.Itoa(qt.BurstBytes))
		}
		cmds = append(cmds, args)

		leafQdisc := defaultOr(qt.Qdisc, "fq_codel")
		cmds = append(cmds, []string{"qdisc", "replace", "dev", qt.ParentInterface, "parent", classID,
			"handle", fmt.Sprintf("%d:", cid), leafQdisc})

		if qt.MarkMatch > 0 {
			cmds = append(cmds, []string{"filter", "replace", "dev", qt.ParentInterface,
				"parent", "1:", "protocol", "all", "prio", "1",
				"handle", strconv.FormatUint(uint64(qt.MarkMatch), 10), "fw", "flowid", classID})
		}
	}

	// 3. Simple queues per user/subnet with burst & PCQ-like dynamic per-host fairness.
	for i, sq := range cfg.QoS.SimpleQueues {
		if !sq.Enabled {
			continue
		}
		if !htbRoots[sq.Interface] {
			htbRoots[sq.Interface] = true
			cmds = append(cmds,
				[]string{"qdisc", "replace", "dev", sq.Interface, "root", "handle", "1:", "htb", "default", "99"},
				[]string{"class", "replace", "dev", sq.Interface, "parent", "1:", "classid", "1:1", "htb",
					"rate", "1000000kbit", "ceil", "1000000kbit"},
			)
		}
		cid := 200 + i
		classID := fmt.Sprintf("1:%d", cid)
		rate := sq.MaxDownloadKbps
		ceil := sq.MaxDownloadKbps
		if sq.BurstDownloadKbps > ceil {
			ceil = sq.BurstDownloadKbps
		}
		burst := (ceil * maxInt(sq.BurstTimeSec, 1)) / 8
		if burst < 16 {
			burst = 16
		}
		cmds = append(cmds,
			[]string{"class", "replace", "dev", sq.Interface, "parent", "1:1", "classid", classID, "htb",
				"rate", fmt.Sprintf("%dkbit", rate),
				"ceil", fmt.Sprintf("%dkbit", ceil),
				"burst", fmt.Sprintf("%dk", burst)},
		)
		if sq.PCQMode {
			// PCQ-like per-subscriber fairness via CAKE dual-dsthost / per-host flow isolation.
			pcqRate := sq.PCQRateKbps
			if pcqRate <= 0 {
				pcqRate = rate
			}
			cmds = append(cmds, []string{"qdisc", "replace", "dev", sq.Interface, "parent", classID,
				"handle", fmt.Sprintf("%d:", cid), "cake",
				"bandwidth", fmt.Sprintf("%dkbit", pcqRate), "dual-dsthost", "flows", "nonat"})
		} else {
			cmds = append(cmds, []string{"qdisc", "replace", "dev", sq.Interface, "parent", classID,
				"handle", fmt.Sprintf("%d:", cid), "fq_codel"})
		}
		cmds = append(cmds, []string{"filter", "replace", "dev", sq.Interface, "parent", "1:",
			"protocol", "ip", "prio", "2", "u32", "match", "ip", "dst", sq.TargetCIDR, "flowid", classID})
	}

	return cmds
}

func maxInt(v, minV int) int {
	if v < minV {
		return minV
	}
	return v
}
