package compression;

import org.apache.commons.compress.compressors.deflate.DeflateCompressorInputStream;
import org.apache.commons.compress.compressors.deflate.DeflateCompressorOutputStream;

import java.io.*;

public class CompressionUtil {

    private static final int BUFFER_SIZE = 10485760;

    public synchronized static byte[] compress(byte[] data) throws IOException {
        BufferedInputStream in = new BufferedInputStream(new ByteArrayInputStream(data));
        ByteArrayOutputStream fOut = new ByteArrayOutputStream();
        BufferedOutputStream out = new BufferedOutputStream(fOut);

        DeflateCompressorOutputStream compressorOut = new DeflateCompressorOutputStream(out);

        byte[] buffer = new byte[BUFFER_SIZE];
        int n;
        while(-1 != (n = in.read(buffer))) {
            compressorOut.write(buffer, 0, n);
        }
        compressorOut.close();
        in.close();
        return fOut.toByteArray();
    }

    public synchronized static byte[] decompress(byte[] data) throws IOException {
        BufferedInputStream in = new BufferedInputStream(new ByteArrayInputStream(data));
        ByteArrayOutputStream fOut = new ByteArrayOutputStream();

        DeflateCompressorInputStream compressorIn = new DeflateCompressorInputStream(in);

        byte[] buffer = new byte[BUFFER_SIZE];
        int n;
        while(-1 != (n = compressorIn.read(buffer))) {
            fOut.write(buffer, 0, n);
        }
        compressorIn.close();
        in.close();
        return fOut.toByteArray();
    }
}
