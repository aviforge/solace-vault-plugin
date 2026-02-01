package solacevaultplugin

import (
	"strings"
	"testing"
)

func TestGeneratePassword(t *testing.T) {
	pw, err := generatePassword(32)
	if err != nil {
		t.Fatalf("generatePassword: %v", err)
	}
	if len(pw) != 32 {
		t.Errorf("len = %d, want 32", len(pw))
	}

	// Verify no excluded characters
	excluded := `:()";'<>,` + "`\\*&|"
	for _, c := range pw {
		if strings.ContainsRune(excluded, c) {
			t.Errorf("password contains excluded character: %c", c)
		}
	}
}

func TestGeneratePassword_Uniqueness(t *testing.T) {
	pw1, _ := generatePassword(32)
	pw2, _ := generatePassword(32)
	if pw1 == pw2 {
		t.Error("two generated passwords should not be identical")
	}
}

func TestGeneratePassword_MaxLength(t *testing.T) {
	pw, err := generatePassword(128)
	if err != nil {
		t.Fatalf("generatePassword(128): %v", err)
	}
	if len(pw) != 128 {
		t.Errorf("len = %d, want 128", len(pw))
	}
}
