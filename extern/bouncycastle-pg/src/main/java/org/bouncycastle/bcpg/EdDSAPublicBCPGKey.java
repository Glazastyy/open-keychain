package org.bouncycastle.bcpg;

import java.io.IOException;
import java.math.BigInteger;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;

/**
 * Base class for an EdDSA Public Key.
 * Here, the curve is identified by an OID and the key is MPI encoded.
 * This class is used with {@link PublicKeyAlgorithmTags#EDDSA_LEGACY} only and MUST NOT be used with v6 keys.
 * Modern OpenPGP uses dedicated key types:
 * For {@link PublicKeyAlgorithmTags#Ed25519} see {@link Ed25519PublicBCPGKey} instead.
 * For {@link PublicKeyAlgorithmTags#Ed448} see {@link Ed448PublicBCPGKey} instead.
 * @see <a href="https://www.rfc-editor.org/rfc/rfc9580.html#name-algorithm-specific-part-for-ed">
 *     OpenPGP - Algorithm-Specific Parts for EdDSALegacy Keys (deprecated)</a>
 */
public class EdDSAPublicBCPGKey
    extends ECPublicBCPGKey
{
    /**
     * @param in the stream to read the packet from.
     */
    protected EdDSAPublicBCPGKey(
        BCPGInputStream in)
        throws IOException
    {
        super(in);
    }

    public EdDSAPublicBCPGKey(
        ASN1ObjectIdentifier oid,
        ECPoint point)
    {
        super(oid, point);
    }

    public EdDSAPublicBCPGKey(
           ASN1ObjectIdentifier oid,
           BigInteger encodedPoint)
    {
        super(oid, encodedPoint);
    }

    public byte[] getEdDSAEncodedPoint()
    {
        BigInteger encodedPoint = getEncodedPoint();
        byte[] pointData = BigIntegers.asUnsignedByteArray(encodedPoint);
        if (pointData[0] != 0x40)
        {
            throw new IllegalStateException("Invalid point format in EdDSA key!");
        }
        return Arrays.copyOfRange(pointData, 1, pointData.length);
    }
}
