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

package org.sufficientlysecure.keychain.util;


import java.util.Arrays;

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
