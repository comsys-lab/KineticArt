package main

import "strconv"

type capStats struct {
	HostBufferMB float64 `json:"host_buffer_mb"`
	CxlFreeMB    float64 `json:"cxl_free_mb"`
	HostNode     int     `json:"host_node"`
	CxlNode      int     `json:"cxl_node"`
}

type latStats struct {
	LatRatio float64 `json:"latency_ratio"`
}

type decision struct {
	Tier   string
	Mems   string
	Reason string
}

func decide(sizeMB, marginMB, latThresh float64, cap *capStats, capFresh bool, lat *latStats, latFresh bool) decision {
	if !capFresh {
		return decision{"DEFER", "", "capacity_stale_or_missing"}
	}
	need := sizeMB + marginMB
	ratio := -1.0
	if latFresh {
		ratio = lat.LatRatio
	}
	hostLatOK := ratio <= 0 || ratio < latThresh
	if cap.HostBufferMB >= need && hostLatOK {
		return decision{"HOST", strconv.Itoa(cap.HostNode), "host_fits_lat_ok"}
	}
	if cap.CxlFreeMB >= need {
		reason := "host_lat_busy"
		if cap.HostBufferMB < need {
			reason = "host_capacity_short"
		}
		return decision{"CXL", strconv.Itoa(cap.CxlNode), reason}
	}
	return decision{"REJECT", "", "host_and_cxl_full"}
}
