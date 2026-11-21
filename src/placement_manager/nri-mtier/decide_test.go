package main

import "testing"

func TestDecide(t *testing.T) {
	cap := &capStats{HostBufferMB: 1000, CxlFreeMB: 50000, HostNode: 1, CxlNode: 2}
	cases := []struct {
		name               string
		size, margin, thr  float64
		cap                *capStats
		capFresh           bool
		lat                *latStats
		latFresh           bool
		wantTier, wantMems string
	}{
		{"host_fits_lat_ok", 500, 32, 1.2, cap, true, &latStats{LatRatio: 1.0}, true, "HOST", "1"},
		{"host_capacity_short", 2000, 32, 1.2, cap, true, &latStats{LatRatio: 1.0}, true, "CXL", "2"},
		{"host_lat_busy", 500, 32, 1.2, cap, true, &latStats{LatRatio: 1.5}, true, "CXL", "2"},
		{"lat_negative_host", 500, 32, 1.2, cap, true, &latStats{LatRatio: -1}, true, "HOST", "1"},
		{"lat_zero_host", 500, 32, 1.2, cap, true, &latStats{LatRatio: 0}, true, "HOST", "1"},
		{"lat_stale_host", 500, 32, 1.2, cap, true, &latStats{LatRatio: 1.9}, false, "HOST", "1"},
		{"capacity_stale_defer", 500, 32, 1.2, cap, false, nil, false, "DEFER", ""},
		{"boundary_exact_fit", 968, 32, 1.2, cap, true, &latStats{LatRatio: 1.0}, true, "HOST", "1"},
		{"host_and_cxl_full_reject", 2000, 32, 1.2, &capStats{HostBufferMB: 1000, CxlFreeMB: 100, HostNode: 1, CxlNode: 2}, true, &latStats{LatRatio: 1.0}, true, "REJECT", ""},
	}
	for _, c := range cases {
		got := decide(c.size, c.margin, c.thr, c.cap, c.capFresh, c.lat, c.latFresh)
		if got.Tier != c.wantTier || got.Mems != c.wantMems {
			t.Errorf("%s: got {tier=%s mems=%s reason=%s}, want tier=%s mems=%s",
				c.name, got.Tier, got.Mems, got.Reason, c.wantTier, c.wantMems)
		}
	}
}
