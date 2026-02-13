import * as fs from 'fs';
import * as path from 'path';
import * as yauzl from 'yauzl';

function extractZip(zipPath: string, destDir: string) {
  yauzl.open(zipPath, { lazyEntries: true }, (err, zipfile) => {
    zipfile.readEntry();
    zipfile.on('entry', (entry) => {
      // VULNERABLE: using entry.fileName directly in path.join without validation
      const destPath = path.join(destDir, entry.fileName);
      const writeStream = fs.createWriteStream(destPath);
      zipfile.openReadStream(entry, (err, readStream) => {
        readStream.pipe(writeStream);
      });
      zipfile.readEntry();
    });
  });
}
