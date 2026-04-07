package handler

import (
	"archive/zip"
	"io"
	"os"
	"path/filepath"
)

func extractZip(zipPath, destDir string) error {
	r, err := zip.OpenReader(zipPath)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// VULNERABLE: using zip entry name directly in filepath.Join without validation
		destPath := filepath.Join(destDir, f.Name)
		os.MkdirAll(filepath.Dir(destPath), 0755)

		rc, err := f.Open()
		if err != nil {
			return err
		}

		outFile, err := os.Create(destPath)
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
