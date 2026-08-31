/*
 * Copyright (c) 2013-2014 Philipp Jakubeit, Signe Rüsch, Dominik Schürmann
 * Copyright (c) 2017 Vincent Breitmoser
 *
 * Licensed under the Bouncy Castle License (MIT license). See LICENSE file for details.
 */

package org.bouncycastle.openpgp.operator.jcajce;


import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.bouncycastle.bcpg.AEADEncDataPacket;
import org.bouncycastle.bcpg.InputStreamPacket;
import org.bouncycastle.bcpg.PublicKeyEncSessionPacket;
import org.bouncycastle.bcpg.SymmetricEncIntegrityPacket;
import org.bouncycastle.jcajce.util.NamedJcaJceHelper;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSessionKey;
import org.bouncycastle.openpgp.operator.PGPDataDecryptor;
import org.bouncycastle.openpgp.operator.PublicKeyDataDecryptorFactory;


public class CachingDataDecryptorFactory implements PublicKeyDataDecryptorFactory
{
    private final PublicKeyDataDecryptorFactory mWrappedDecryptor;
    private final HashMap<ByteBuffer, byte[]> mSessionKeyCache;

    private OperatorHelper mOperatorHelper;
    private JceAEADUtil mAeadHelper;

    public CachingDataDecryptorFactory(String providerName, Map<ByteBuffer, byte[]> sessionKeyCache)
    {
        this((PublicKeyDataDecryptorFactory) null, sessionKeyCache);

        mOperatorHelper = new OperatorHelper(new NamedJcaJceHelper(providerName));
        mAeadHelper = new JceAEADUtil(mOperatorHelper);
    }

    public CachingDataDecryptorFactory(PublicKeyDataDecryptorFactory wrapped,
            Map<ByteBuffer, byte[]> sessionKeyCache)
    {
        mSessionKeyCache = new HashMap<>();
        if (sessionKeyCache != null)
        {
            mSessionKeyCache.putAll(sessionKeyCache);
        }

        mWrappedDecryptor = wrapped;
    }

    public boolean hasCachedSessionData(PGPPublicKeyEncryptedData encData) throws PGPException {
        ByteBuffer bi = ByteBuffer.wrap(encData.getSessionKey()[0]);
        return mSessionKeyCache.containsKey(bi);
    }

    public Map<ByteBuffer, byte[]> getCachedSessionKeys() {
        return Collections.unmodifiableMap(mSessionKeyCache);
    }

    public boolean canDecrypt() {
        return mWrappedDecryptor != null;
    }

    @Override
    public byte[] recoverSessionData(PublicKeyEncSessionPacket pkesk, InputStreamPacket encData)
            throws PGPException {
        ByteBuffer bi = ByteBuffer.wrap(pkesk.getEncSessionKey()[0]);  // encoded MPI
        byte[] cachedSessionData = mSessionKeyCache.get(bi);
        if (cachedSessionData != null) {
            return cachedSessionData;
        }

        byte[] sessionData = requireWrappedDecryptor().recoverSessionData(pkesk, encData);
        mSessionKeyCache.put(bi, sessionData);
        return sessionData;
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData) throws PGPException {
        return recoverSessionData(keyAlgorithm, secKeyData, PublicKeyEncSessionPacket.VERSION_3);
    }

    @Override
    public byte[] recoverSessionData(int keyAlgorithm, byte[][] secKeyData, int pkeskVersion)
            throws PGPException {
        ByteBuffer bi = ByteBuffer.wrap(secKeyData[0]);  // encoded MPI
        byte[] cachedSessionData = mSessionKeyCache.get(bi);
        if (cachedSessionData != null) {
            return cachedSessionData;
        }

        byte[] sessionData =
                requireWrappedDecryptor().recoverSessionData(keyAlgorithm, secKeyData, pkeskVersion);
        mSessionKeyCache.put(bi, sessionData);
        return sessionData;
    }

    private PublicKeyDataDecryptorFactory requireWrappedDecryptor() {
        if (mWrappedDecryptor == null) {
            throw new IllegalStateException("tried to decrypt without wrapped decryptor, this is a bug!");
        }
        return mWrappedDecryptor;
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(boolean withIntegrityPacket, int encAlgorithm, byte[] key)
            throws PGPException {
        if (mWrappedDecryptor != null) {
            return mWrappedDecryptor.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
        }
        return mOperatorHelper.createDataDecryptor(withIntegrityPacket, encAlgorithm, key);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(AEADEncDataPacket aeadEncDataPacket,
            PGPSessionKey sessionKey) throws PGPException {
        if (mWrappedDecryptor != null) {
            mWrappedDecryptor.createDataDecryptor(aeadEncDataPacket, sessionKey);
        }
        return mAeadHelper.createOpenPgpV5DataDecryptor(aeadEncDataPacket, sessionKey);
    }

    @Override
    public PGPDataDecryptor createDataDecryptor(SymmetricEncIntegrityPacket seipd,
            PGPSessionKey sessionKey) throws PGPException {
        if (mWrappedDecryptor != null) {
            mWrappedDecryptor.createDataDecryptor(seipd, sessionKey);
        }
        return mAeadHelper.createOpenPgpV6DataDecryptor(seipd, sessionKey);
    }

}
