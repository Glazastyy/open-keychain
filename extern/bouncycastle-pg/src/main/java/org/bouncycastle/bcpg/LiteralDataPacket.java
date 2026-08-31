package org.bouncycastle.bcpg;

import java.io.IOException;

import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Strings;

/**
 * Generic literal data packet.
 */
public class LiteralDataPacket
    extends InputStreamPacket
{
    int     format;
    byte[]  fileName;
    long    modDate;
    Long    literalLength;

    LiteralDataPacket(
            BCPGInputStream    in)
            throws IOException
    {
        this(in, false);
    }

    LiteralDataPacket(
        BCPGInputStream    in,
        boolean newPacketFormat)
        throws IOException
    {
        super(in, LITERAL_DATA, newPacketFormat);

        format = in.read();
        int    l = in.read();
        if (l < 0)
        {
            throw new MalformedPacketException("File name size cannot be negative.");
        }

        fileName = new byte[l];
        for (int i = 0; i != fileName.length; i++)
        {
            int ch = in.read();
            if (ch < 0)
            {
                throw new IOException("literal data truncated in header");
            }
            fileName[i] = (byte)ch;
        }

        modDate = StreamUtil.readTime(in);
        if (modDate < 0)
        {
            throw new IOException("literal data truncated in header");
        }

        literalLength = in.getBodyLengthIfAvailable();
        if (literalLength != null) {
            // length of literal data is length of the packet...
            // ...minus 1 byte format, 1 byte filename length
            literalLength -= 2;
            // ...minus length of the filename
            literalLength -= l;
            // ...minus two bytes timestamp
            literalLength -= 4;
        }
    }

    /**
     * Return the format tag of the data packet.
     */
    public int getFormat()
    {
        return format;
    }

    /**
     * Return the modification time for the file (milliseconds at second level precision).
     */
    public long getModificationTime()
    {
        return modDate;
    }

    /**
     * Return the file name associated with the data packet.
     */
    public String getFileName()
    {
        return Strings.fromUTF8ByteArray(fileName);
    }

    /**
     * Return the file name as an uninterpreted byte array.
     */
    public byte[] getRawFileName()
    {
        return Arrays.clone(fileName);
    }

}
