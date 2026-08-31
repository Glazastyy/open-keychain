/*
 * Copyright (C) 2026 OpenKeychain contributors
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.sufficientlysecure.keychain.pgp;


import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Date;
import java.util.Iterator;

import org.bouncycastle.bcpg.AEADAlgorithmTags;
import org.bouncycastle.bcpg.CompressionAlgorithmTags;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedDataGenerator;
import org.bouncycastle.openpgp.PGPEncryptedDataGenerator;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPLiteralDataGenerator;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.operator.jcajce.JcePBEKeyEncryptionMethodGenerator;
import org.bouncycastle.openpgp.operator.jcajce.JcePGPDataEncryptorBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePublicKeyKeyEncryptionMethodGenerator;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.openintents.openpgp.OpenPgpDecryptionResult;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.daos.KeyWritableRepository;
import org.sufficientlysecure.keychain.operations.results.DecryptVerifyResult;
import org.sufficientlysecure.keychain.service.input.CryptoInputParcel;
import org.sufficientlysecure.keychain.support.KeyringTestingHelper;
import org.sufficientlysecure.keychain.util.InputData;
import org.sufficientlysecure.keychain.util.Passphrase;
import org.sufficientlysecure.keychain.util.TestingUtils;


/**
 * Messages in the shapes RFC 9580 introduced, which other implementations (GnuPG 2.4+,
 * Sequoia, Thunderbird) now emit by default. These are produced with Bouncy Castle
 * directly rather than through {@link PgpSignEncryptOperation}, because OpenKeychain
 * does not write them itself - the point is that it can read what others send.
 */
@RunWith(KeychainTestRunner.class)
public class PgpDecryptModernFormatTest {

    private static final String PLAINTEXT = "dies ist ein plaintext ☭";

    private static UncachedKeyRing sStaticRing;
    private static Passphrase sKeyPhrase;

    @BeforeClass
    public static void setUpOnce() throws Exception {
        Security.insertProviderAt(new BouncyCastleProvider(), 1);

        sKeyPhrase = new Passphrase("RsKrW^raOPcnQ=ZJr-pP");
        sStaticRing = KeyringTestingHelper.readRingFromResource("/test-keys/encrypt_decrypt_key_1.sec");
    }

    @Before
    public void setUp() {
        KeyWritableRepository databaseInteractor =
                KeyWritableRepository.create(RuntimeEnvironment.getApplication());
        databaseInteractor.saveSecretKeyRing(sStaticRing);
    }

    /** SEIPD version 2, the AEAD packet RFC 9580 defines. */
    @Test
    public void testDecryptSeipdV2Aead() throws Exception {
        byte[] ciphertext = encryptToStaticRing(builderWithV6Aead());
        assertDecryptsToPlaintext(ciphertext, CryptoInputParcel.createCryptoInputParcel(sKeyPhrase));
    }

    /** The LibrePGP / OpenPGP v5 style AEAD packet, as emitted by GnuPG 2.4. */
    @Test
    public void testDecryptV5StyleAead() throws Exception {
        byte[] ciphertext = encryptToStaticRing(builderWithV5Aead());
        assertDecryptsToPlaintext(ciphertext, CryptoInputParcel.createCryptoInputParcel(sKeyPhrase));
    }

    /** A passphrase-encrypted message using the v2 SEIPD packet. */
    @Test
    public void testDecryptSymmetricSeipdV2Aead() throws Exception {
        Passphrase passphrase = TestingUtils.testPassphrase0;

        PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(builderWithV6Aead());
        generator.addMethod(new JcePBEKeyEncryptionMethodGenerator(passphrase.getCharArray())
                .setProvider(new BouncyCastleProvider()));
        byte[] ciphertext = writeMessage(generator);

        assertDecryptsToPlaintext(ciphertext, CryptoInputParcel.createCryptoInputParcel(passphrase));
    }

    private JcePGPDataEncryptorBuilder builderWithV6Aead() {
        return new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithAEAD(AEADAlgorithmTags.OCB, 6)
                .setUseV6AEAD()
                .setProvider(new BouncyCastleProvider());
    }

    private JcePGPDataEncryptorBuilder builderWithV5Aead() {
        return new JcePGPDataEncryptorBuilder(SymmetricKeyAlgorithmTags.AES_256)
                .setWithAEAD(AEADAlgorithmTags.OCB, 6)
                .setUseV5AEAD()
                .setProvider(new BouncyCastleProvider());
    }

    private byte[] encryptToStaticRing(JcePGPDataEncryptorBuilder encryptorBuilder) throws Exception {
        PGPEncryptedDataGenerator generator = new PGPEncryptedDataGenerator(encryptorBuilder);
        generator.addMethod(new JcePublicKeyKeyEncryptionMethodGenerator(findEncryptionKey())
                .setProvider(new BouncyCastleProvider()));
        return writeMessage(generator);
    }

    private PGPPublicKey findEncryptionKey() {
        Iterator<UncachedPublicKey> keys = sStaticRing.getPublicKeys();
        while (keys.hasNext()) {
            PGPPublicKey key = keys.next().getPublicKey();
            if (key.isEncryptionKey() && !key.isMasterKey()) {
                return key;
            }
        }
        throw new AssertionError("test key ring has no encryption subkey");
    }

    private byte[] writeMessage(PGPEncryptedDataGenerator generator) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        OutputStream encryptedOut = generator.open(out, new byte[1 << 16]);

        PGPCompressedDataGenerator compressGenerator =
                new PGPCompressedDataGenerator(CompressionAlgorithmTags.ZIP);
        OutputStream compressedOut = compressGenerator.open(encryptedOut);

        PGPLiteralDataGenerator literalGenerator = new PGPLiteralDataGenerator();
        OutputStream literalOut = literalGenerator.open(compressedOut, PGPLiteralData.UTF8,
                "", PLAINTEXT.getBytes("UTF-8").length, new Date());
        literalOut.write(PLAINTEXT.getBytes("UTF-8"));
        literalGenerator.close();

        compressGenerator.close();
        generator.close();
        return out.toByteArray();
    }

    private void assertDecryptsToPlaintext(byte[] ciphertext, CryptoInputParcel cryptoInput)
            throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ByteArrayInputStream in = new ByteArrayInputStream(ciphertext);
        InputData data = new InputData(in, in.available());

        PgpDecryptVerifyOperation op = new PgpDecryptVerifyOperation(RuntimeEnvironment.getApplication(),
                KeyWritableRepository.create(RuntimeEnvironment.getApplication()), null);
        PgpDecryptVerifyInputParcel input = PgpDecryptVerifyInputParcel.builder()
                .setAllowSymmetricDecryption(true)
                .build();

        DecryptVerifyResult result = op.execute(input, cryptoInput, data, out);

        if (!result.success()) {
            StringBuilder sb = new StringBuilder("decryption must succeed, log was:");
            for (org.sufficientlysecure.keychain.operations.results.OperationResult.LogEntryParcel le
                    : result.getLog().toList()) {
                sb.append("\n  ").append(le.mType);
            }
            Assert.fail(sb.toString());
        }
        Assert.assertEquals("decrypted ciphertext should equal plaintext",
                PLAINTEXT, new String(out.toByteArray(), "UTF-8"));
        Assert.assertEquals("decryptionResult should be RESULT_ENCRYPTED",
                OpenPgpDecryptionResult.RESULT_ENCRYPTED, result.getDecryptionResult().getResult());
    }
}
