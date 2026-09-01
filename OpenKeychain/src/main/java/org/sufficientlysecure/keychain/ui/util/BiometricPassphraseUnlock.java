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

package org.sufficientlysecure.keychain.ui.util;


import javax.crypto.Cipher;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.biometric.BiometricPrompt;
import androidx.biometric.BiometricPrompt.AuthenticationResult;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentActivity;

import org.sufficientlysecure.keychain.R;
import org.sufficientlysecure.keychain.util.BiometricPassphraseStorage;
import org.sufficientlysecure.keychain.util.BiometricPassphraseStorage.InvalidatedException;
import org.sufficientlysecure.keychain.util.Passphrase;
import timber.log.Timber;


/**
 * Drives {@link BiometricPrompt} on behalf of {@link BiometricPassphraseStorage}, so callers deal
 * in passphrases rather than in ciphers and authentication callbacks.
 *
 * <p>On API 30 and up the cipher is bound to the prompt through a {@code CryptoObject}, so the
 * authentication authorises exactly this one decryption. Below that a key that allows the device
 * credential as a fallback cannot be used that way, so the prompt runs on its own and the cipher
 * is created once it succeeds; see {@link BiometricPassphraseStorage} for what that costs.
 */
public class BiometricPassphraseUnlock {

    public interface UnlockCallback {
        void onPassphraseUnlocked(@NonNull Passphrase passphrase);

        /**
         * The passphrase could not be recovered and is no longer stored. The caller should fall
         * back to asking the user to type it.
         *
         * @param message a message to show, or null to stay quiet (the user cancelled)
         */
        void onUnlockFailed(@Nullable String message);
    }

    public interface SaveCallback {
        void onPassphraseSaved();

        /** Storing failed; the passphrase is not remembered, but the operation itself is fine. */
        void onSaveFailed(@Nullable String message);
    }

    private BiometricPassphraseUnlock() {
    }

    /** Asks the user to authenticate, then hands back the passphrase stored for this key. */
    public static void unlock(@NonNull Fragment fragment, long masterKeyId,
            @NonNull UnlockCallback callback) {
        final BiometricPassphraseStorage storage =
                BiometricPassphraseStorage.create(fragment.requireContext());

        Cipher cipher;
        try {
            cipher = storage.createDecryptCipher(masterKeyId);
        } catch (InvalidatedException e) {
            Timber.d(e, "Stored passphrase is no longer usable");
            callback.onUnlockFailed(
                    fragment.getString(R.string.biometric_passphrase_invalidated));
            return;
        }

        final Cipher preparedCipher = cipher;
        BiometricPrompt prompt = new BiometricPrompt(fragment,
                ContextCompat.getMainExecutor(fragment.requireContext()),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(@NonNull AuthenticationResult result) {
                        Cipher authorisedCipher = preparedCipher;
                        if (result.getCryptoObject() != null
                                && result.getCryptoObject().getCipher() != null) {
                            authorisedCipher = result.getCryptoObject().getCipher();
                        }
                        try {
                            callback.onPassphraseUnlocked(
                                    storage.loadPassphrase(masterKeyId, authorisedCipher));
                        } catch (InvalidatedException e) {
                            Timber.d(e, "Could not decrypt the stored passphrase");
                            callback.onUnlockFailed(fragment.getString(
                                    R.string.biometric_passphrase_invalidated));
                        }
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        if (isUserCancellation(errorCode)) {
                            callback.onUnlockFailed(null);
                        } else {
                            callback.onUnlockFailed(errString.toString());
                        }
                    }
                });

        BiometricPrompt.PromptInfo promptInfo = buildPromptInfo(fragment,
                fragment.getString(R.string.biometric_unlock_title),
                fragment.getString(R.string.biometric_unlock_description));

        if (BiometricPassphraseStorage.usesCryptoObject()) {
            prompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(preparedCipher));
        } else {
            prompt.authenticate(promptInfo);
        }
    }

    /**
     * Asks the user to authenticate, then stores the passphrase for this key. Activity flavour,
     * for callers that are not inside a fragment.
     */
    public static void save(@NonNull final FragmentActivity activity, long masterKeyId,
            @NonNull final Passphrase passphrase, @NonNull SaveCallback callback) {
        final BiometricPassphraseStorage storage =
                BiometricPassphraseStorage.create(activity);

        Cipher cipher;
        try {
            cipher = storage.createEncryptCipher(masterKeyId);
        } catch (InvalidatedException e) {
            Timber.w(e, "Could not prepare to store the passphrase");
            callback.onSaveFailed(activity.getString(R.string.biometric_passphrase_save_failed));
            return;
        }

        final Cipher preparedCipher = cipher;
        BiometricPrompt prompt = new BiometricPrompt(activity,
                ContextCompat.getMainExecutor(activity),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(@NonNull AuthenticationResult result) {
                        Cipher authorisedCipher = preparedCipher;
                        if (result.getCryptoObject() != null
                                && result.getCryptoObject().getCipher() != null) {
                            authorisedCipher = result.getCryptoObject().getCipher();
                        }
                        try {
                            storage.savePassphrase(masterKeyId, authorisedCipher, passphrase);
                            callback.onPassphraseSaved();
                        } catch (InvalidatedException e) {
                            Timber.w(e, "Could not store the passphrase");
                            callback.onSaveFailed(activity.getString(
                                    R.string.biometric_passphrase_save_failed));
                        }
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        storage.removePassphrase(masterKeyId);
                        if (isUserCancellation(errorCode)) {
                            callback.onSaveFailed(null);
                        } else {
                            callback.onSaveFailed(errString.toString());
                        }
                    }
                });

        BiometricPrompt.PromptInfo promptInfo = buildPromptInfo(storage.getPromptMode(), activity,
                activity.getString(R.string.biometric_save_title),
                activity.getString(R.string.biometric_save_description));

        if (BiometricPassphraseStorage.usesCryptoObject()) {
            prompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(preparedCipher));
        } else {
            prompt.authenticate(promptInfo);
        }
    }

    /** Asks the user to authenticate, then stores the passphrase for this key. */
    public static void save(@NonNull Fragment fragment, long masterKeyId,
            @NonNull final Passphrase passphrase, @NonNull SaveCallback callback) {
        final BiometricPassphraseStorage storage =
                BiometricPassphraseStorage.create(fragment.requireContext());

        Cipher cipher;
        try {
            cipher = storage.createEncryptCipher(masterKeyId);
        } catch (InvalidatedException e) {
            Timber.w(e, "Could not prepare to store the passphrase");
            callback.onSaveFailed(fragment.getString(R.string.biometric_passphrase_save_failed));
            return;
        }

        final Cipher preparedCipher = cipher;
        BiometricPrompt prompt = new BiometricPrompt(fragment,
                ContextCompat.getMainExecutor(fragment.requireContext()),
                new BiometricPrompt.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationSucceeded(@NonNull AuthenticationResult result) {
                        Cipher authorisedCipher = preparedCipher;
                        if (result.getCryptoObject() != null
                                && result.getCryptoObject().getCipher() != null) {
                            authorisedCipher = result.getCryptoObject().getCipher();
                        }
                        try {
                            storage.savePassphrase(masterKeyId, authorisedCipher, passphrase);
                            callback.onPassphraseSaved();
                        } catch (InvalidatedException e) {
                            Timber.w(e, "Could not store the passphrase");
                            callback.onSaveFailed(fragment.getString(
                                    R.string.biometric_passphrase_save_failed));
                        }
                    }

                    @Override
                    public void onAuthenticationError(int errorCode, @NonNull CharSequence errString) {
                        storage.removePassphrase(masterKeyId);
                        if (isUserCancellation(errorCode)) {
                            callback.onSaveFailed(null);
                        } else {
                            callback.onSaveFailed(errString.toString());
                        }
                    }
                });

        BiometricPrompt.PromptInfo promptInfo = buildPromptInfo(fragment,
                fragment.getString(R.string.biometric_save_title),
                fragment.getString(R.string.biometric_save_description));

        if (BiometricPassphraseStorage.usesCryptoObject()) {
            prompt.authenticate(promptInfo, new BiometricPrompt.CryptoObject(preparedCipher));
        } else {
            prompt.authenticate(promptInfo);
        }
    }

    private static BiometricPrompt.PromptInfo buildPromptInfo(Fragment fragment, String title,
            String description) {
        return buildPromptInfo(
                BiometricPassphraseStorage.create(fragment.requireContext()).getPromptMode(),
                fragment.requireContext(), title, description);
    }

    /**
     * Builds the prompt for the way this device wants to be asked. See
     * {@link BiometricPassphraseStorage#getPromptMode()} for why there is more than one way.
     */
    private static BiometricPrompt.PromptInfo buildPromptInfo(int promptMode,
            android.content.Context context, String title, String description) {
        BiometricPrompt.PromptInfo.Builder builder = new BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .setDescription(description)
                .setConfirmationRequired(false);

        switch (promptMode) {
            case BiometricPassphraseStorage.PROMPT_BIOMETRIC_ONLY:
                builder.setAllowedAuthenticators(
                        androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG);
                builder.setNegativeButtonText(context.getString(android.R.string.cancel));
                break;
            case BiometricPassphraseStorage.PROMPT_CREDENTIAL_LEGACY:
                //noinspection deprecation - the only route to the device credential before API 30
                builder.setDeviceCredentialAllowed(true);
                break;
            case BiometricPassphraseStorage.PROMPT_BIOMETRIC_OR_CREDENTIAL:
            default:
                // no negative button may be set alongside a device credential fallback
                builder.setAllowedAuthenticators(
                        BiometricPassphraseStorage.getAllowedAuthenticators());
                break;
        }

        return builder.build();
    }

    private static boolean isUserCancellation(int errorCode) {
        return errorCode == BiometricPrompt.ERROR_USER_CANCELED
                || errorCode == BiometricPrompt.ERROR_NEGATIVE_BUTTON
                || errorCode == BiometricPrompt.ERROR_CANCELED;
    }
}
