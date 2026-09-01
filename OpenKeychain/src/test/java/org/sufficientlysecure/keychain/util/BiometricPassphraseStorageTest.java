/*
 * Copyright (c) 2026 André Glazastov <andre@glazastov.com>
 *
 * SPDX-License-Identifier: MIT
 *
 * This file is new in this fork and is offered by its author under the MIT
 * License; see LICENSE.MIT. It is distributed as part of an application
 * licensed under the GPLv3 as a whole; see LICENSE and NOTICE.md.
 */

package org.sufficientlysecure.keychain.util;


import java.util.Arrays;
import java.util.Collections;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RuntimeEnvironment;
import org.sufficientlysecure.keychain.KeychainTestRunner;
import org.sufficientlysecure.keychain.util.BiometricPassphraseStorage.InvalidatedException;


/**
 * Covers what can be exercised off-device: the encoding helpers, and how the storage behaves when
 * the ciphertext it kept is missing or damaged. The Keystore itself needs real hardware, so the
 * encrypt and decrypt paths are not reachable here.
 *
 * <p>The failure handling is worth pinning down: every one of these paths has to leave the entry
 * gone rather than half-present, or the user is asked for a passphrase that can never be stored
 * again.
 */
@RunWith(KeychainTestRunner.class)
public class BiometricPassphraseStorageTest {

    private static final String PREFS_NAME = "biometric_passphrases";
    private static final long MASTER_KEY_ID = 0x1234567890ABCDEFL;

    private BiometricPassphraseStorage storage;
    private SharedPreferences prefs;

    @Before
    public void setUp() {
        Context context = RuntimeEnvironment.getApplication();
        storage = BiometricPassphraseStorage.create(context);
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        prefs.edit().clear().commit();
    }

    @Test
    public void hasPassphrase_isFalseForUnknownKey() {
        Assert.assertFalse(storage.hasPassphrase(MASTER_KEY_ID));
    }

    @Test
    public void createDecryptCipher_withNothingStored_reportsInvalidated() {
        try {
            storage.createDecryptCipher(MASTER_KEY_ID);
            Assert.fail("expected InvalidatedException");
        } catch (InvalidatedException e) {
            // expected
        }
    }

    @Test
    public void createDecryptCipher_withCorruptCiphertext_discardsIt() {
        prefs.edit().putString(Long.toString(MASTER_KEY_ID), "this is not base64 %%%").commit();
        Assert.assertTrue(storage.hasPassphrase(MASTER_KEY_ID));

        try {
            storage.createDecryptCipher(MASTER_KEY_ID);
            Assert.fail("expected InvalidatedException");
        } catch (InvalidatedException e) {
            // expected
        }

        Assert.assertFalse("a passphrase that cannot be read must not be left behind",
                storage.hasPassphrase(MASTER_KEY_ID));
    }

    @Test
    public void createDecryptCipher_withTruncatedCiphertext_discardsIt() {
        // shorter than the 12 byte GCM nonce, so there is no ciphertext at all
        byte[] tooShort = new byte[] { 1, 2, 3, 4 };
        prefs.edit()
                .putString(Long.toString(MASTER_KEY_ID), Base64.encodeToString(tooShort, Base64.NO_WRAP))
                .commit();

        try {
            storage.createDecryptCipher(MASTER_KEY_ID);
            Assert.fail("expected InvalidatedException");
        } catch (InvalidatedException e) {
            // expected
        }

        Assert.assertFalse(storage.hasPassphrase(MASTER_KEY_ID));
    }

    @Test
    public void removePassphrase_forgetsOnlyThatKey() {
        prefs.edit()
                .putString(Long.toString(MASTER_KEY_ID), "AAAA")
                .putString(Long.toString(1L), "BBBB")
                .commit();

        storage.removePassphrase(MASTER_KEY_ID);

        Assert.assertFalse(storage.hasPassphrase(MASTER_KEY_ID));
        Assert.assertTrue(storage.hasPassphrase(1L));
    }

    @Test
    public void removeAllPassphrases_forgetsEverything() {
        prefs.edit()
                .putString(Long.toString(MASTER_KEY_ID), "AAAA")
                .putString(Long.toString(1L), "BBBB")
                // an entry we cannot parse must not stop the rest from being cleared
                .putString("not-a-key-id", "CCCC")
                .commit();

        storage.removeAllPassphrases();

        Assert.assertTrue(storage.getStoredKeyIds().isEmpty());
    }

    @Test
    public void charsAndBytesRoundTrip() {
        char[] original = "sênha çom acentos ☭ and spaces".toCharArray();

        byte[] bytes = BiometricPassphraseStorage.toBytes(original);
        char[] roundTripped = BiometricPassphraseStorage.toChars(bytes);

        Assert.assertArrayEquals(original, roundTripped);
    }

    @Test
    public void charsAndBytesRoundTrip_empty() {
        byte[] bytes = BiometricPassphraseStorage.toBytes(new char[0]);
        Assert.assertEquals(0, bytes.length);
        Assert.assertEquals(0, BiometricPassphraseStorage.toChars(bytes).length);
    }

    @Test
    public void toBytes_doesNotShareTheCallersArray() {
        char[] original = "passphrase".toCharArray();
        byte[] bytes = BiometricPassphraseStorage.toBytes(original);
        Arrays.fill(bytes, (byte) 0);

        Assert.assertArrayEquals("wiping the encoded copy must not touch the input",
                "passphrase".toCharArray(), original);
    }

    @Test
    public void findStoredMasterKeyId_picksTheKeyWeCanAnswerFor() {
        // Decrypting a message asks for any one of the keys it was encrypted to, and a message
        // encrypted to its sender as well as its recipient names two. The stored passphrase has
        // to be found even when it belongs to the second one.
        long otherKeyId = 0x99L;
        prefs.edit().putString(Long.toString(MASTER_KEY_ID), "AAAA").commit();

        Assert.assertEquals(Long.valueOf(MASTER_KEY_ID),
                storage.findStoredMasterKeyId(Arrays.asList(otherKeyId, MASTER_KEY_ID)));
    }

    @Test
    public void findStoredMasterKeyId_withNothingStored_isNull() {
        Assert.assertNull(storage.findStoredMasterKeyId(Arrays.asList(1L, 2L)));
        Assert.assertNull(storage.findStoredMasterKeyId(Collections.<Long>emptyList()));
    }

    @Test
    public void getPromptMode_withoutAScreenLock_reportsUnavailable() {
        // the test device has no screen lock and no sensor, so there is nothing to authenticate
        // with; the feature has to report that rather than offering itself and failing later
        Assert.assertEquals(BiometricPassphraseStorage.PROMPT_UNAVAILABLE, storage.getPromptMode());
        Assert.assertFalse(storage.isAvailable());
    }

    @Test
    public void parseMasterKeyId_rejectsNonsense() {
        Assert.assertEquals(Long.valueOf(42L), BiometricPassphraseStorage.parseMasterKeyId("42"));
        Assert.assertNull(BiometricPassphraseStorage.parseMasterKeyId("not-a-key-id"));
    }
}
