package model

import "testing"

func TestSeverityOrder(t *testing.T) {
	if !Critical.AtLeast(High) || !High.AtLeast(Medium) || !Medium.AtLeast(Low) || !Low.AtLeast(Info) {
		t.Error("severity ordering broken")
	}
	if Info.AtLeast(High) {
		t.Error("info must not rank as high")
	}
	if Critical.Weight() <= High.Weight() || High.Weight() <= Medium.Weight() {
		t.Error("severity weights must be strictly ordered")
	}
}

func TestParseSeverity(t *testing.T) {
	for _, v := range []string{"critical", "HIGH", "Medium", "low", "info"} {
		if _, err := ParseSeverity(v); err != nil {
			t.Errorf("ParseSeverity(%q): %v", v, err)
		}
	}
	if _, err := ParseSeverity("nope"); err == nil {
		t.Error("expected an error for an unknown severity")
	}
}
