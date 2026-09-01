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


import java.nio.charset.Charset;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import android.content.Context;
import android.app.KeyguardManager;
import android.content.SharedPreferences;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricManager;
import androidx.biometric.BiometricManager.Authenticators;
import timber.log.Timber;


/**
 * Stores a key's passphrase encrypted under a key that lives in the Android Keystore and can only
 * be used after the user authenticates, with a fingerprint or with the device's PIN, pattern or
 * password.
 *
 * <p>This is opt-in per key. Nothing here happens unless the user ticks "remember with biometrics"
 * on the passphrase dialog; the ordinary path still keeps passphrases in memory only.
 *
 * <p>What lands on disk is the AES-GCM ciphertext of the passphrase and its nonce. The key that
 * decrypts it never leaves the Keystore, is bound to the user's current biometric enrolment, and
 * on hardware with a secure element never enters the application's address space at all.
 *
 * <p>Two shapes of Keystore key are needed, because a key that requires authentication for every
 * single use can only be combined with device-credential fallback from API 30 on:
 * <ul>
 *   <li>API 30+: authentication per use, and the cipher is handed to the prompt as a
 *       {@code CryptoObject} so the authentication is bound to this one operation.</li>
 *   <li>API 23-29: authentication valid for a short window, and the prompt runs without a
 *       {@code CryptoObject}. The window is {@link #AUTH_VALIDITY_SECONDS} seconds, long enough
 *       to finish the operation the user just authorised and no longer.</li>
 * </ul>
 */
public class BiometricPassphraseStorage {

    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private static final String PREFS_NAME = "biometric_passphrases";
    private static final String KEY_ALIAS_PREFIX = "com.glazastov.keychain.passphrase.";
    private static final String TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/"
            + KeyProperties.BLOCK_MODE_GCM + "/" + KeyProperties.ENCRYPTION_PADDING_NONE;
    private static final int GCM_TAG_LENGTH_BITS = 128;
    private static final int GCM_NONCE_LENGTH_BYTES = 12;
    private static final int AUTH_VALIDITY_SECONDS = 15;
    private static final int ALLOWED_AUTHENTICATORS =
            Authenticators.BIOMETRIC_STRONG | Authenticators.DEVICE_CREDENTIAL;
    private static final Charset UTF_8 = Charset.forName("UTF-8");

    /** Raised when the stored passphrase can no longer be read and has been discarded. */
    public static class InvalidatedException extends Exception {
        InvalidatedException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    private final Context mContext;

    public BiometricPassphraseStorage(Context context) {
        mContext = context.getApplicationContext();
    }

    public static BiometricPassphraseStorage create(Context context) {
        return new BiometricPassphraseStorage(context);
    }

    /** The prompt cannot be shown: no screen lock, or no usable authenticator. */
    public static final int PROMPT_UNAVAILABLE = 0;
    /** Ask for a biometric or the device credential, in one prompt. API 30 and up. */
    public static final int PROMPT_BIOMETRIC_OR_CREDENTIAL = 1;
    /** Ask for a biometric only; the combined set is rejected on API 28-29. */
    public static final int PROMPT_BIOMETRIC_ONLY = 2;
    /** Ask for the device credential through the pre-API-30 route. */
    public static final int PROMPT_CREDENTIAL_LEGACY = 3;

    /**
     * Whether this device can protect a passphrase right now: it has a screen lock set up, and
     * either a usable biometric sensor or a device credential we can fall back to.
     */
    public boolean isAvailable() {
        return getPromptMode() != PROMPT_UNAVAILABLE;
    }

    /**
     * How to ask this device for authentication.
     *
     * <p>Android 11 takes a biometric and the device credential as one set. Android 9 and 10
     * reject that combination outright, so there the two have to be asked for separately: the
     * sensor when something is enrolled on it, and otherwise the PIN, pattern or password
     * through the route that predates the combined set.
     */
    public int getPromptMode() {
        BiometricManager biometricManager = BiometricManager.from(mContext);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            return biometricManager.canAuthenticate(ALLOWED_AUTHENTICATORS)
                    == BiometricManager.BIOMETRIC_SUCCESS
                    ? PROMPT_BIOMETRIC_OR_CREDENTIAL
                    : PROMPT_UNAVAILABLE;
        }

        if (biometricManager.canAuthenticate(Authenticators.BIOMETRIC_STRONG)
                == BiometricManager.BIOMETRIC_SUCCESS) {
            return PROMPT_BIOMETRIC_ONLY;
        }

        // DEVICE_CREDENTIAL on its own is not a set canAuthenticate() understands before API 30,
        // so ask the keyguard directly, as the platform documentation says to.
        KeyguardManager keyguardManager =
                (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        if (keyguardManager != null && keyguardManager.isDeviceSecure()) {
            return PROMPT_CREDENTIAL_LEGACY;
        }

        return PROMPT_UNAVAILABLE;
    }

    /** The authenticators to ask {@code BiometricPrompt} for in {@link #PROMPT_BIOMETRIC_OR_CREDENTIAL}. */
    public static int getAllowedAuthenticators() {
        return ALLOWED_AUTHENTICATORS;
    }

    /**
     * Whether the cipher must be handed to the prompt as a {@code CryptoObject}. Below API 30 a
     * key that allows device-credential fallback cannot be used that way, so the prompt runs on
     * its own and the key stays usable for a short window afterwards.
     */
    public static boolean usesCryptoObject() {
        return Build.VERSION.SDK_INT >= Build.VERSION_CODES.R;
    }

    public boolean hasPassphrase(long masterKeyId) {
        return getPrefs().contains(prefsKey(masterKeyId));
    }

    /**
     * The first of these keys that has a passphrase stored, or null if none does.
     *
     * <p>A request for a passphrase can name several keys at once - decrypting a message asks for
     * any one of the keys it was encrypted to - so the caller needs whichever of them we can
     * actually answer for.
     */
    @Nullable
    public Long findStoredMasterKeyId(@NonNull Iterable<Long> masterKeyIds) {
        for (Long masterKeyId : masterKeyIds) {
            if (masterKeyId != null && hasPassphrase(masterKeyId)) {
                return masterKeyId;
            }
        }
        return null;
    }

    public Set<String> getStoredKeyIds() {
        return getPrefs().getAll().keySet();
    }

    /** Forgets the passphrase for one key, and destroys the Keystore key that protected it. */
    public void removePassphrase(long masterKeyId) {
        getPrefs().edit().remove(prefsKey(masterKeyId)).apply();
        deleteKeystoreKey(keyAlias(masterKeyId));
    }

    /** Forgets every stored passphrase. Used by the panic responder and on database consolidation. */
    public void removeAllPassphrases() {
        SharedPreferences prefs = getPrefs();
        for (Map.Entry<String, ?> entry : prefs.getAll().entrySet()) {
            try {
                deleteKeystoreKey(keyAlias(Long.parseLong(entry.getKey())));
            } catch (NumberFormatException e) {
                Timber.w(e, "Unparseable entry in biometric passphrase storage, dropping it");
            }
        }
        prefs.edit().clear().apply();
    }

    /**
     * Creates the Keystore key for this master key and returns a cipher ready to encrypt with it.
     * On API 30+ the returned cipher must be handed to {@code BiometricPrompt} as a
     * {@code CryptoObject}; below that, call this only after the prompt has succeeded.
     */
    @NonNull
    public Cipher createEncryptCipher(long masterKeyId) throws InvalidatedException {
        try {
            SecretKey secretKey = generateKeystoreKey(keyAlias(masterKeyId));
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return cipher;
        } catch (Exception e) {
            throw new InvalidatedException("Could not prepare a cipher to store the passphrase", e);
        }
    }

    /**
     * Encrypts and stores the passphrase. The cipher must be the one from
     * {@link #createEncryptCipher(long)}, after the user has authenticated.
     */
    public void savePassphrase(long masterKeyId, @NonNull Cipher cipher, @NonNull Passphrase passphrase)
            throws InvalidatedException {
        byte[] plaintext = null;
        try {
            plaintext = toBytes(passphrase.getCharArray());
            byte[] ciphertext = cipher.doFinal(plaintext);
            byte[] nonce = cipher.getIV();
            if (nonce == null || nonce.length != GCM_NONCE_LENGTH_BYTES) {
                throw new IllegalStateException("Unexpected GCM nonce length");
            }

            byte[] stored = new byte[nonce.length + ciphertext.length];
            System.arraycopy(nonce, 0, stored, 0, nonce.length);
            System.arraycopy(ciphertext, 0, stored, nonce.length, ciphertext.length);

            getPrefs().edit()
                    .putString(prefsKey(masterKeyId), Base64.encodeToString(stored, Base64.NO_WRAP))
                    .apply();
        } catch (Exception e) {
            // do not leave a Keystore key behind for a passphrase we failed to write
            removePassphrase(masterKeyId);
            throw new InvalidatedException("Could not store the passphrase", e);
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    /**
     * Returns a cipher ready to decrypt the stored passphrase. On API 30+ hand it to
     * {@code BiometricPrompt} as a {@code CryptoObject}; below that, call this only after the
     * prompt has succeeded.
     *
     * @throws InvalidatedException if the stored passphrase can no longer be read, in which case
     *         it has been discarded and the user has to enter it again. This is the expected
     *         outcome when a new fingerprint is enrolled or the screen lock is removed.
     */
    @NonNull
    public Cipher createDecryptCipher(long masterKeyId) throws InvalidatedException {
        byte[] stored = readStored(masterKeyId);
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            SecretKey secretKey = (SecretKey) keyStore.getKey(keyAlias(masterKeyId), null);
            if (secretKey == null) {
                throw new IllegalStateException("No Keystore key for this passphrase");
            }

            byte[] nonce = Arrays.copyOf(stored, GCM_NONCE_LENGTH_BYTES);
            Cipher cipher = Cipher.getInstance(TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey,
                    new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce));
            return cipher;
        } catch (KeyPermanentlyInvalidatedException e) {
            removePassphrase(masterKeyId);
            throw new InvalidatedException(
                    "Keystore key was invalidated, the passphrase must be entered again", e);
        } catch (Exception e) {
            removePassphrase(masterKeyId);
            throw new InvalidatedException("Could not prepare a cipher for the passphrase", e);
        }
    }

    /**
     * Decrypts the stored passphrase. The cipher must be the one from
     * {@link #createDecryptCipher(long)}, after the user has authenticated.
     */
    @NonNull
    public Passphrase loadPassphrase(long masterKeyId, @NonNull Cipher cipher)
            throws InvalidatedException {
        byte[] stored = readStored(masterKeyId);
        byte[] plaintext = null;
        try {
            plaintext = cipher.doFinal(stored, GCM_NONCE_LENGTH_BYTES,
                    stored.length - GCM_NONCE_LENGTH_BYTES);
            return new Passphrase(toChars(plaintext));
        } catch (Exception e) {
            removePassphrase(masterKeyId);
            throw new InvalidatedException("Could not read the stored passphrase", e);
        } finally {
            if (plaintext != null) {
                Arrays.fill(plaintext, (byte) 0);
            }
        }
    }

    @NonNull
    private byte[] readStored(long masterKeyId) throws InvalidatedException {
        String encoded = getPrefs().getString(prefsKey(masterKeyId), null);
        if (encoded == null) {
            throw new InvalidatedException("No passphrase stored for this key", null);
        }
        byte[] stored;
        try {
            stored = Base64.decode(encoded, Base64.NO_WRAP);
        } catch (IllegalArgumentException e) {
            removePassphrase(masterKeyId);
            throw new InvalidatedException("Stored passphrase is corrupt", e);
        }
        if (stored.length <= GCM_NONCE_LENGTH_BYTES) {
            removePassphrase(masterKeyId);
            throw new InvalidatedException("Stored passphrase is truncated", null);
        }
        return stored;
    }

    @RequiresApi(Build.VERSION_CODES.M)
    private SecretKey generateKeystoreKey(String alias) throws Exception {
        KeyGenerator keyGenerator =
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);

        KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(alias,
                KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .setUserAuthenticationRequired(true);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            // enrolling a new fingerprint must not silently widen who can read the passphrase
            builder.setInvalidatedByBiometricEnrollment(true);
        }

        if (usesCryptoObject()) {
            builder.setUserAuthenticationParameters(0,
                    KeyProperties.AUTH_BIOMETRIC_STRONG | KeyProperties.AUTH_DEVICE_CREDENTIAL);
        } else {
            //noinspection deprecation - the only way to allow a device credential before API 30
            builder.setUserAuthenticationValidityDurationSeconds(AUTH_VALIDITY_SECONDS);
        }

        keyGenerator.init(builder.build());
        return keyGenerator.generateKey();
    }

    private void deleteKeystoreKey(String alias) {
        try {
            KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            keyStore.load(null);
            if (keyStore.containsAlias(alias)) {
                keyStore.deleteEntry(alias);
            }
        } catch (Exception e) {
            Timber.w(e, "Could not delete Keystore key %s", alias);
        }
    }

    private SharedPreferences getPrefs() {
        return mContext.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
    }

    private static String prefsKey(long masterKeyId) {
        return Long.toString(masterKeyId);
    }

    private static String keyAlias(long masterKeyId) {
        return KEY_ALIAS_PREFIX + masterKeyId;
    }

    /** Encodes without going through String, which we could not wipe afterwards. */
    static byte[] toBytes(char[] chars) {
        java.nio.ByteBuffer buffer = UTF_8.encode(java.nio.CharBuffer.wrap(chars));
        byte[] bytes = new byte[buffer.remaining()];
        buffer.get(bytes);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), (byte) 0);
        }
        return bytes;
    }

    /** Decodes without going through String, for the same reason. */
    static char[] toChars(byte[] bytes) {
        java.nio.CharBuffer buffer = UTF_8.decode(java.nio.ByteBuffer.wrap(bytes));
        char[] chars = new char[buffer.remaining()];
        buffer.get(chars);
        if (buffer.hasArray()) {
            Arrays.fill(buffer.array(), '\0');
        }
        return chars;
    }

    @Nullable
    public static Long parseMasterKeyId(String prefsKey) {
        try {
            return Long.parseLong(prefsKey);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
