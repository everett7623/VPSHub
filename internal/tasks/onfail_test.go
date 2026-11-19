package tasks

import "testing"

func TestTaskOnFail(t *testing.T) {
	if taskOnFail(`{}`) != "pause" {
		t.Fatal("default pause")
	}
	if taskOnFail(`{"on_fail":"continue"}`) != "continue" {
		t.Fatal("continue")
	}
	if taskOnFail(`{"on_fail":"PAUSE"}`) != "pause" {
		t.Fatal("pause")
	}
}
