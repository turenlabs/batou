import java.io.*;
import java.util.zip.*;

public class ZipSlip {
    public void extractZip(String zipFile, String destDir) throws Exception {
        ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile));
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            // VULNERABLE: using entry.getName() directly in new File without validation
            File destFile = new File(destDir, entry.getName());
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
