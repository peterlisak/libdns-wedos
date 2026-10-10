package wedos

import "testing"

func TestNormalizeZone(t *testing.T) {
	tests := []struct {
		name string
		zone string
		want string
	}{
		{name: "fully qualified zone", zone: "lisak.site.", want: "lisak.site"},
		{name: "already normalized zone", zone: "lisak.site", want: "lisak.site"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := normalizeZone(test.zone); got != test.want {
				t.Errorf("normalizeZone(%q) = %q, want %q", test.zone, got, test.want)
			}
		})
	}
}
