package handler

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func extractZipSafe(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		destPath := filepath.Join(destDir, f.Name)
		// SAFE: validate path stays within destDir
		cleanPath := filepath.Clean(destPath)
		if !strings.HasPrefix(cleanPath, filepath.Clean(destDir)+string(os.PathSeparator)) {
			return fmt.Errorf("illegal file path: %s", f.Name)
		}

		os.MkdirAll(filepath.Dir(cleanPath), 0755)

		rc, err := f.Open()
		if err != nil {
			return err
		}

		outFile, err := os.Create(cleanPath)
		if err != nil {
			rc.Close()
			return err
		}

		io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
	}
	return nil
}
