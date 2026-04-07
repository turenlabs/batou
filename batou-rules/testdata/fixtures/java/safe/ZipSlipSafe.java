import java.io.*;
import java.util.zip.*;

public class ZipSlipSafe {
    public void extractZip(String zipFile, String destDir) throws Exception {
        File destDirectory = new File(destDir);
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            File destFile = new File(destDir, entry.getName());
            // SAFE: validate canonical path is within destination directory
            String canonicalPath = destFile.getCanonicalPath();
            String canonicalDest = destDirectory.getCanonicalPath() + File.separator;
            if (!canonicalPath.startsWith(canonicalDest)) {
                throw new SecurityException("Entry outside target dir: " + entry.getName());
            }
            destFile.getParentFile().mkdirs();

            FileOutputStream fos = new FileOutputStream(destFile);
            byte[] buffer = new byte[1024];
            int len;
            while ((len = zis.read(buffer)) > 0) {
                fos.write(buffer, 0, len);
            }
            fos.close();
        }
        zis.close();
    }
}
