package installpath

import (
	"strings"
	"testing"
)

func TestCanonicalLocalPaths(t *testing.T) {
	for input, expected := range map[string]string{
		`C:\Program Files\Vault443`: `C:\Program Files\Vault443`,
		`d:\Программы\Vault 443\`:   `D:\Программы\Vault 443`,
		`e:/Apps/Vault443`:          `E:\Apps\Vault443`,
	} {
		actual, err := Canonical(input)
		if err != nil || actual != expected {
			t.Errorf("Canonical(%q) = %q, %v", input, actual, err)
		}
	}
}

func TestCanonicalRejectsRedirectedOrAmbiguousPaths(t *testing.T) {
	for _, input := range []string{
		`C:\`, `C:relative`, `\rooted`, `\\server\share\Vault443`, `\\?\C:\Apps\Vault443`,
		`\\.\C:\Apps\Vault443`, `C:\Apps\..\Windows`, `C:\Apps\.\Vault443`,
		`C:\Apps\\Vault443`, `C:\Apps.\Vault443`, `C:\Apps \Vault443`,
		`C:\Apps\file:stream`, `C:\Apps\con.txt`, `C:\Apps\LPT1`, `C:\Apps\COM¹`,
		`C:\Apps\Vault"443`, "C:\\Apps\\Vault\x00443", `C:\` + strings.Repeat("x", 239),
	} {
		if path, err := Canonical(input); err == nil {
			t.Errorf("accepted unsafe input %q as %q", input, path)
		}
	}
}
