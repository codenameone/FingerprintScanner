/*
 * Copyright (c) 2012, Codename One and/or its affiliates. All rights reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER.
 * This code is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 only, as
 * published by the Free Software Foundation.  Codename One designates this
 * particular file as subject to the "Classpath" exception as provided
 * by Oracle in the LICENSE file that accompanied this code.
 *
 * This code is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * version 2 for more details (a copy is included in the LICENSE file that
 * accompanied this code).
 *
 * You should have received a copy of the GNU General Public License version
 * 2 along with this work; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 * Please contact Codename One through http://www.codenameone.com/ if you
 * need additional information or have any questions.
 */
package com.codename1.fingerprint.impl;

// FingerprintManager was removed in API 37; the Compat class keeps API 23-28 devices
// working and compiles against every platform (Codename One issue #5701).
import android.support.v4.hardware.fingerprint.FingerprintManagerCompat;
import com.codename1.impl.android.AndroidNativeUtil;
import com.codename1.impl.android.AndroidImplementation;

import android.os.Build;
import android.os.CancellationSignal;
import android.Manifest;
import android.app.Activity;
import android.content.Context;
import android.content.DialogInterface;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricManager;
import android.hardware.biometrics.BiometricPrompt;
import android.os.Looper;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.support.annotation.RequiresApi;
import android.util.Base64;
import com.codename1.io.Log;
import com.codename1.ui.CN;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;


public class InternalFingerprintImpl {
    private FingerprintManagerCompat mFingerPrintManager;
    private BiometricManager mBiometricManager;
    private KeyGenerator mKeyGenerator;
    private static final String KEY_ID = "FingerprintScannerKey";
    private static final String SHARED_PREFS_NAME = "FingerprintScannerPrefs";
    private static final String ANDROID_KEY_STORE = "AndroidKeyStore";
    private KeyStore mKeyStore;
    private Cipher mCipher;
    private static CancellationSignal cancellationSignal;

    /// The Compat authenticate takes the support library's CancellationSignal. The
    /// platform one is what cancellationSignal holds and what cancel() calls, so the
    /// Compat signal follows it.
    private static android.support.v4.os.CancellationSignal compatSignal(CancellationSignal cancel) {
        final android.support.v4.os.CancellationSignal compat = new android.support.v4.os.CancellationSignal();
        cancel.setOnCancelListener(new CancellationSignal.OnCancelListener() {
            public void onCancel() {
                compat.cancel();
            }
        });
        return compat;
    }



    public boolean isAvailable() {
        //final boolean[] response = new boolean[1];
        if (android.os.Build.VERSION.SDK_INT < 23) {
            return false;
        }
        final StringBuilder paramBuilder = new StringBuilder();
        if (android.os.Build.VERSION.SDK_INT >= 29) {
            CN.setProperty("FingerprintScanner.showDialogOnAndroid", "false");
            AndroidImplementation.runOnUiThreadAndBlock(new Runnable() {
                @RequiresApi(api = Build.VERSION_CODES.Q)
                public void run() {
                    if(!AndroidNativeUtil.checkForPermission(Manifest.permission.USE_BIOMETRIC, "Authorize using biometrics")){
                        return;
                    }
                    try {
                        if (mBiometricManager == null) {
                            mBiometricManager = (BiometricManager)AndroidNativeUtil.getActivity().
                                    getSystemService(Activity.BIOMETRIC_SERVICE);
                        }
                        PackageManager packageManager = AndroidNativeUtil.getActivity().getPackageManager();
                        boolean canAuthenticate = mBiometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
                        if (canAuthenticate) {
                            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)) {
                                if (Build.VERSION.SDK_INT >= 37) {
                                    // FingerprintManagerCompat reaches the platform FingerprintManager, which API 37
                                    // removed: it throws NoClassDefFoundError there, and the catch below then skipped
                                    // the face and iris checks too. Per-modality enrolment is not exposed on these
                                    // releases; canAuthenticate() only says SOME biometric is enrolled. That proves a
                                    // fingerprint only when fingerprint is the sole biometric hardware. With face or
                                    // iris hardware too, the enrolled one may not be a fingerprint, so "touch" is left
                                    // out rather than guessed: isTouchIDAvailable() must not answer true for a phone
                                    // with only a face enrolled (it never did before API 37). The price is a false
                                    // negative on multi-sensor phones, documented on Fingerprint.isTouchIDAvailable();
                                    // isAvailable() is unaffected because "face"/"iris" is still reported there.
                                    // BiometricManager.getStrings() button labels hint at the modality but are
                                    // localized text, not an API, so they are not matched.
                                    if (!packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)
                                            && !packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
                                        paramBuilder.append("touch ");
                                    } else {
                                        // Some biometric is enrolled and it may be any of the sensors. This token
                                        // is what makes Fingerprint.getBiometricType() answer BIOMETRICS instead of
                                        // reading the "face" below as an enrolled face. It matches none of the
                                        // words the older methods search for (BiometricType.UNDETERMINED).
                                        paramBuilder.append("mixed ");
                                    }
                                } else {
                                    FingerprintManagerCompat fingerprintManager = FingerprintManagerCompat.from(AndroidNativeUtil.getActivity());
                                    if (fingerprintManager.hasEnrolledFingerprints()) {
                                        paramBuilder.append("touch ");
                                    }
                                }
                            }
                            if (packageManager.hasSystemFeature(PackageManager.FEATURE_FACE)) {
                                paramBuilder.append("face ");
                            }
                            if (packageManager.hasSystemFeature(PackageManager.FEATURE_IRIS)) {
                                paramBuilder.append("iris ");
                            }
                        }


                    } catch(Throwable t) {
                        Log.p("This exception could be 100% valid on old devices, we're logging it just to be safe. Older devices might throw NoClassDefFoundError...");
                        Log.e(t);
                    }
                }
            });
        } else {
            CN.setProperty("FingerprintScanner.showDialogOnAndroid", "true");
            AndroidImplementation.runOnUiThreadAndBlock(new Runnable() {
                @RequiresApi(api = Build.VERSION_CODES.M)
                public void run() {
                    if(!AndroidNativeUtil.checkForPermission(Manifest.permission.USE_FINGERPRINT, "Authorize using fingerprint")){
                        return;
                    }
                    try {
                        mFingerPrintManager = FingerprintManagerCompat.from(AndroidNativeUtil.getActivity());

                        if (mFingerPrintManager.isHardwareDetected() &&
                                mFingerPrintManager.hasEnrolledFingerprints()) {
                            paramBuilder.append("touch ");
                        }
                    } catch(Throwable t) {
                        Log.p("This exception could be 100% valid on old devices, we're logging it just to be safe. Older devices might throw NoClassDefFoundError...");
                        Log.e(t);
                    }
                }
            });
        }
        String param = paramBuilder.toString().trim();
        CN.setProperty("Fingerprint.types", param);

        return !param.isEmpty();
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private void scan29(final String reason) {
        runOnUiThreadIfNotAlready(new Runnable() {
            @RequiresApi(api = Build.VERSION_CODES.Q)
            public void run() {
                if (cancellationSignal != null) {
                    // Fingerprint scanning can continue for a long time even after the user
                    // has given up.  Keep a reference globally so that we can clear it
                    // if we need to start another scan.
                    cancellationSignal.cancel();
                    cancellationSignal = null;
                }
                final CancellationSignal cs = new CancellationSignal();
                cancellationSignal = cs;

                BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
                    int failures;
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        InternalCallback.scanFail();
                    }

                    public void onAuthenticationFailed() {
                        // NOTE: Often authentication fails several times
                        // before it succeeds.  Because often times it takes a while
                        // for the user to put their finger in the right spot
                        // This method will be called continually in a stream until
                        // either the user cancels the action, it succeeds, or until
                        // we cancel the action with cs.cancel.
                        // Here, we'll try 5 times then quit.
                        if (failures++ > 5) {
                            cs.cancel();
                            InternalCallback.scanFail();
                        }
                    }

                    public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                        cs.cancel();
                        InternalCallback.scanSuccess();
                    }
                };
                new BiometricPrompt.Builder(AndroidNativeUtil.getActivity())
                        .setTitle(reason)
                        .setNegativeButton("Cancel", AndroidNativeUtil.getActivity().getMainExecutor(), new DialogInterface.OnClickListener() {
                            @Override
                            public void onClick(DialogInterface dialogInterface, int i) {
                                InternalCallback.scanFail();
                            }
                        })
                        .build().authenticate(cs, AndroidNativeUtil.getActivity().getMainExecutor(), callback);

            }
        });
    }

    public void scan(String reason) {
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.p("minimum SDK version 23 required");
            InternalCallback.scanFail();
        }

        if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            scan29(reason);
            return;
        }

        runOnUiThreadIfNotAlready(new Runnable() {
            @RequiresApi(api = Build.VERSION_CODES.M)
            public void run() {
                if (cancellationSignal != null) {
                    // Fingerprint scanning can continue for a long time even after the user
                    // has given up.  Keep a reference globally so that we can clear it
                    // if we need to start another scan.
                    cancellationSignal.cancel();
                    cancellationSignal = null;
                }
                final CancellationSignal cs = new CancellationSignal();
                cancellationSignal = cs;

                FingerprintManagerCompat.AuthenticationCallback callback = new FingerprintManagerCompat.AuthenticationCallback() {
                    int failures;
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        InternalCallback.scanFail();
                    }

                    public void onAuthenticationFailed() {
                        // NOTE: Often authentication fails several times
                        // before it succeeds.  Because often times it takes a while
                        // for the user to put their finger in the right spot
                        // This method will be called continually in a stream until
                        // either the user cancels the action, it succeeds, or until
                        // we cancel the action with cs.cancel.
                        // Here, we'll try 5 times then quit.
                        if (failures++ > 5) {
                            cs.cancel();
                            InternalCallback.scanFail();
                        }
                    }

                    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                        cs.cancel();
                        InternalCallback.scanSuccess();
                    }
                };

                mFingerPrintManager.authenticate(null, 0, compatSignal(cs), callback, null);
            }
        });
    }

    public boolean isSupported() {
        return true;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean isFingerprintAuthAvailable() {

        if (Looper.getMainLooper().isCurrentThread()) {
            if(!AndroidNativeUtil.checkForPermission(Manifest.permission.USE_FINGERPRINT, "Authorize using fingerprint")){
                return false;
            }
            try {
                mFingerPrintManager = FingerprintManagerCompat.from(AndroidNativeUtil.getActivity());

                return mFingerPrintManager.isHardwareDetected() &&
                        mFingerPrintManager.hasEnrolledFingerprints();
            } catch(Throwable t) {
                Log.p("This exception could be 100% valid on old devices, we're logging it just to be safe. Older devices might throw NoClassDefFoundError...");
                Log.e(t);
                return false;
            }
        } else {
            return isAvailable();
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private boolean isBiometricAuthAvailable() {

        if (Looper.getMainLooper().isCurrentThread()) {
            if(!AndroidNativeUtil.checkForPermission(Manifest.permission.USE_FINGERPRINT, "Authorize using fingerprint")){
                return false;
            }
            try {
                if (mBiometricManager == null) {
                    mBiometricManager = (BiometricManager)AndroidNativeUtil.getActivity().
                            getSystemService(Activity.BIOMETRIC_SERVICE);
                }

                return mBiometricManager.canAuthenticate() == BiometricManager.BIOMETRIC_SUCCESS;
            } catch(Throwable t) {
                Log.p("This exception could be 100% valid on old devices, we're logging it just to be safe. Older devices might throw NoClassDefFoundError...");
                Log.e(t);
                return false;
            }
        } else {
            return isAvailable();
        }
    }


    public void addPassword(int requestId, String reason, String key, String value) {
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.p("minimum SDK version 23 required");
            InternalCallback.requestError(requestId, "minimum SDK version 23 is required");
        } else if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            addPassword29(requestId, reason, key, value, true, 0);
        } else {
            addPassword(requestId, reason, key, value, true, 0);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private boolean addPassword29(final int requestId, final String reason, final String account, final String password, final boolean requestAuth, final int depth) {
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.p("minimum SDK version 23 required");
            InternalCallback.requestError(requestId, "minimum SDK version 23 is required");
            return true;
        }
        final SharedPreferences sharedPref = AndroidNativeUtil.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
        final SharedPreferences.Editor editor = sharedPref.edit();
        if (isBiometricAuthAvailable()) {
            SecretKey secretKey = getSecretKey();

            if (secretKey == null && keyUnverifiedState()) {
                InternalCallback.requestError(requestId, "Cannot confirm the key is bound to the enrolled biometrics");
                return false;
            }
            if (secretKey == null) {
                if (createReplacementKey()) {
                    secretKey = getSecretKey();
                } else {
                    InternalCallback.requestError(requestId, String.valueOf("Failed to create key"));
                    return false;
                }
            }

            runOnUiThreadIfNotAlready(new Runnable() {
                public void run() {
                    if (cancellationSignal != null) {
                        // Fingerprint scanning can continue for a long time even after the user
                        // has given up.  Keep a reference globally so that we can clear it
                        // if we need to start another scan.
                        cancellationSignal.cancel();
                        cancellationSignal = null;
                    }
                    final CancellationSignal cs = new CancellationSignal();
                    cancellationSignal = cs;
                    BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
                        int failures;
                        public void onAuthenticationError(int errorCode, CharSequence errString) {

                            InternalCallback.requestError(requestId, String.valueOf(errString));
                        }


                        public void onAuthenticationFailed() {
                            // NOTE: Often authentication fails several times
                            // before it succeeds.  Because often times it takes a while
                            // for the user to put their finger in the right spot
                            // This method will be called continually in a stream until
                            // either the user cancels the action, it succeeds, or until
                            // we cancel the action with cs.cancel.
                            // Here, we'll try 5 times then quit.
                            //if (failures++ > 5) {
                            //    cs.cancel();
                            //    InternalCallback.requestComplete(requestId, false);
                            //}
                        }

                        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            // Cancelled AFTER the cipher work: cancelling first may tear the
                            // keystore operation down under the doFinal the authentication
                            // unlocked, the suspected cause of issue #8.
                            try {
                            
                            byte[] enc = new byte[0];
                            try {
                                Cipher cipher = result.getCryptoObject().getCipher();
                                enc = cipher.doFinal(password.getBytes());

                                editor.putString("fing" + account, Base64.encodeToString(enc, Base64.DEFAULT));
                                editor.putString("fing_iv" + account,
                                        Base64.encodeToString(cipher.getIV(), Base64.DEFAULT));
                                revokedPrefs().edit().remove(account).apply();

                                editor.apply();
                                InternalCallback.requestComplete(requestId, true);
                            } catch (Throwable e) {

                                // Never fall back to encrypting without the prompt, as this
                                // once did for issue #8: that needs an unbound key. Retry once
                                // with a fresh key and a fresh prompt (the Samsung 8.0.0 case,
                                // https://issuetracker.google.com/u/0/issues/65578763).
                                if (depth == 0 && isKeyInvalidation(e)) {
                                    removePermanentlyInvalidatedKey();
                                    addPassword29(requestId, reason, account, password, requestAuth, depth + 1);
                                } else {
                                    Log.e(e);
                                    InternalCallback.requestError(requestId, "Failed to add password: " + e.getMessage());
                                }
                            }

                                                    } finally {
                                cs.cancel();
                            }
                        }
                    };
                    if(!initCipher(Cipher.ENCRYPT_MODE, account)) {
                        // Could not initialize cipher, key must have been invalidated
                        if (!createReplacementKey()) {
                            InternalCallback.requestError(requestId, "Failed to initialize the cipher.");
                            return;
                        }
                        if(!initCipher(Cipher.ENCRYPT_MODE, account)) {
                            InternalCallback.requestError(requestId, "Failed to initialize the cipher even after generating new key.  Something must be wrong");
                            return;
                        }


                    }
                    BiometricPrompt.CryptoObject crypto = new BiometricPrompt.CryptoObject(mCipher());

                    //mBiometricManager.authenticate(crypto, cs, 0, callback, null);
                    new BiometricPrompt.Builder(AndroidNativeUtil.getActivity())
                            .setTitle(reason)
                            .setNegativeButton("Cancel", AndroidNativeUtil.getActivity().getMainExecutor(), new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialogInterface, int i) {
                                    InternalCallback.requestError(requestId, "__CANCELLED__");
                                }
                            })
                            .build().authenticate(crypto, cs, AndroidNativeUtil.getActivity().getMainExecutor(), callback);

                }
            });

        } else {
            InternalCallback.requestError(requestId, String.valueOf("No biometric hardware is available"));

        }
        return true;

    }
    /**
     * Adds a secure item.
     * @param requestId The request ID
     * @param reason The reason to show if a biometric prompt is shown.
     * @param account The account name
     * @param password The password
     * @param requestAuth Whether to request biometric authentication.
     * @return If requestAuth is false, and we *need* to use biometric authentication, then this will return false.  Otherwise it returns true.
     */

    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean addPassword(final int requestId, final String reason, final String account, final String password, final boolean requestAuth, final int depth) {
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.p("minimum SDK version 23 required");
            InternalCallback.requestError(requestId, "minimum SDK version 23 is required");
            return true;
        }
        final SharedPreferences sharedPref = AndroidNativeUtil.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
        final SharedPreferences.Editor editor = sharedPref.edit();
        if (isFingerprintAuthAvailable()) {
            SecretKey secretKey = getSecretKey();

            if (secretKey == null && keyUnverifiedState()) {
                InternalCallback.requestError(requestId, "Cannot confirm the key is bound to the enrolled biometrics");
                return false;
            }
            if (secretKey == null) {
                if (createReplacementKey()) {
                    secretKey = getSecretKey();
                } else {
                    InternalCallback.requestError(requestId, String.valueOf("Failed to create key"));
                    return false;
                }
            }




            runOnUiThreadIfNotAlready(new Runnable() {
                public void run() {
                    if (cancellationSignal != null) {
                        // Fingerprint scanning can continue for a long time even after the user
                        // has given up.  Keep a reference globally so that we can clear it
                        // if we need to start another scan.
                        cancellationSignal.cancel();
                        cancellationSignal = null;
                    }
                    final CancellationSignal cs = new CancellationSignal();
                    cancellationSignal = cs;
                    FingerprintManagerCompat.AuthenticationCallback callback = new FingerprintManagerCompat.AuthenticationCallback() {
                        int failures;
                        public void onAuthenticationError(int errorCode, CharSequence errString) {

                            InternalCallback.requestError(requestId, String.valueOf(errString));
                        }


                        public void onAuthenticationFailed() {
                            // NOTE: Often authentication fails several times
                            // before it succeeds.  Because often times it takes a while
                            // for the user to put their finger in the right spot
                            // This method will be called continually in a stream until
                            // either the user cancels the action, it succeeds, or until
                            // we cancel the action with cs.cancel.
                            // Here, we'll try 5 times then quit.
                            //if (failures++ > 5) {
                            //    cs.cancel();
                            //    InternalCallback.requestComplete(requestId, false);
                            //}
                        }

                        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                            // Cancelled AFTER the cipher work: cancelling first may tear the
                            // keystore operation down under the doFinal the authentication
                            // unlocked, the suspected cause of issue #8.
                            try {
                            
                            byte[] enc = new byte[0];
                            try {
                                Cipher cipher = result.getCryptoObject().getCipher();
                                enc = cipher.doFinal(password.getBytes());

                                editor.putString("fing" + account, Base64.encodeToString(enc, Base64.DEFAULT));
                                editor.putString("fing_iv" + account,
                                        Base64.encodeToString(cipher.getIV(), Base64.DEFAULT));
                                revokedPrefs().edit().remove(account).apply();

                                editor.apply();
                                InternalCallback.requestComplete(requestId, true);
                            } catch (Throwable e) {
                                if (depth == 0 && isKeyInvalidation(e)) {
                                    // This typically shouldn't happen.  If the key was invalidated, it should have caught
                                    // it before the authentication step in initCipher.  BUT in some cases, e.g. Samsung
                                    // phones on 8.0.0, it somehow passes that initial step without failure, but fails
                                    // here.
                                    //https://issuetracker.google.com/u/0/issues/65578763
                                    removePermanentlyInvalidatedKey();
                                    addPassword(requestId, reason, account, password, requestAuth, depth + 1);
                                } else {


                                    Log.e(e);
                                    InternalCallback.requestError(requestId, e.getMessage());
                                }
                            }

                                                    } finally {
                                cs.cancel();
                            }
                        }
                    };
                    if(!initCipher(Cipher.ENCRYPT_MODE, account)) {
                        // Could not initialize cipher, key must have been invalidated
                        if (!createReplacementKey()) {
                            InternalCallback.requestError(requestId, "Failed to initialize the cipher.");
                            return;
                        }
                        if(!initCipher(Cipher.ENCRYPT_MODE, account)) {
                            InternalCallback.requestError(requestId, "Failed to initialize the cipher even after generating new key.  Something must be wrong");
                            return;
                        }


                    }
                    FingerprintManagerCompat.CryptoObject crypto = new FingerprintManagerCompat.CryptoObject(mCipher());
                    mFingerPrintManager.authenticate(crypto, 0, compatSignal(cs), callback, null);
                }
            });

        } else {
            InternalCallback.requestError(requestId, String.valueOf("No biometric hardware is available"));

        }
        return true;

    }
    public void deletePassword(int requestId, String reason, String account) {
        SharedPreferences sharedPref = AndroidNativeUtil.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
        sharedPref.edit().remove("fing"+account).remove("fing_iv"+account).apply();
        revokedPrefs().edit().remove(account).apply();
        InternalCallback.requestComplete(requestId, true);
    }

    public void getPassword(int requestId, String reason, String key) {
        if (android.os.Build.VERSION.SDK_INT < 23) {
            Log.p("minimum SDK version 23 required");
            InternalCallback.requestError(requestId, "minimum SDK version 23 is required");
        } else if (android.os.Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            getPassword29(requestId, reason, key, true);
        } else {
            getPassword(requestId, reason, key, true);
        }
    }

    @RequiresApi(api = Build.VERSION_CODES.Q)
    private boolean getPassword29(final int requestId, final String reason, final String key, final boolean requestAuth) {

        final SharedPreferences sharedPref = AndroidNativeUtil.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
        if (sharedPref.getString("fing_iv" + key, null) == null) {
            revokedOrMissing(requestId, sharedPref, key);
            return false;
        }
        // Before the availability check: when the user deleted EVERY biometric, nothing
        // is enrolled, so that check fails and the password would be reported as "not
        // available" -- although Android has already deleted its key and it can never be
        // read again, even after re-enrolment. A stored password with no key is revoked.
        if (getSecretKey() == null && keyRevokedState()) {
            InternalCallback.requestKeyRevokedError(requestId, "Key has been invalidated");
            return false;
        }
        if (isBiometricAuthAvailable()) {
            SecretKey secretKey = getSecretKey();

            if (secretKey == null) {
                /*
                if (createKey()) {
                    secretKey = getSecretKey();
                } else {
                    InternalCallback.requestError(requestId, String.valueOf("Failed to create key"));
                    return false;
                }
                */
                if (keyRevokedState()) {
                    InternalCallback.requestKeyRevokedError(requestId, String.valueOf("Key has been invalidated"));
                } else {
                    InternalCallback.requestError(requestId, String.valueOf("No key found"));
                }
                return false;
            }



            runOnUiThreadIfNotAlready(new Runnable() {
                @RequiresApi(api = Build.VERSION_CODES.Q)
                public void run() {
                    // Fingerprint scanning can continue for a long time even after the user
                    // has given up.  Keep a reference globally so that we can clear it
                    // if we need to start another scan.
                    if (cancellationSignal != null) {
                        cancellationSignal.cancel();
                        cancellationSignal = null;
                    }
                    final CancellationSignal cs = new CancellationSignal();
                    cancellationSignal = cs;
                    BiometricPrompt.AuthenticationCallback callback = new BiometricPrompt.AuthenticationCallback() {
                        int failures;

                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            InternalCallback.requestError(requestId, String.valueOf(errString));
                        }

                        public void onAuthenticationFailed() {
                            // NOTE: Often authentication fails several times
                            // before it succeeds.  Because often times it takes a while
                            // for the user to put their finger in the right spot
                            // This method will be called continually in a stream until
                            // either the user cancels the action, it succeeds, or until
                            // we cancel the action with cs.cancel.
                            // Here, we'll try 5 times then quit.
                            //if (failures++ > 5) {
                            //    cs.cancel();
                            //    InternalCallback.requestError(requestId, "Authentication failed");
                            //}

                        }

                        public void onAuthenticationSucceeded(BiometricPrompt.AuthenticationResult result) {
                            // Cancelled AFTER the cipher work: cancelling first may tear the
                            // keystore operation down under the doFinal the authentication
                            // unlocked, the suspected cause of issue #8.
                            try {
                            
                            try {
                                if (result.getCryptoObject() == null || result.getCryptoObject().getCipher() == null) {
                                    InternalCallback.requestError(requestId, "Authenticated cipher missing");
                                    return;
                                }
                                Cipher cipher = result.getCryptoObject().getCipher();
                                byte[] enc = Base64.decode(sharedPref.getString("fing" + key, ""), Base64.DEFAULT);

                                byte[] decrypted = cipher.doFinal(enc);
                                String decryptedStr = new String(decrypted);
                                InternalCallback.requestSuccess(requestId, decryptedStr);
                            } catch (Throwable e) {
                                if (isKeyInvalidation(e)) {
                                    removePermanentlyInvalidatedKey();
                                    InternalCallback.requestKeyRevokedError(requestId, "Key has been invalidated");
                                    return;
                                }
                                Log.e(e);
                                InternalCallback.requestError(requestId, e.getMessage());
                            }


                                                    } finally {
                                cs.cancel();
                            }
                        }
                    };
                    if(!initCipher(Cipher.DECRYPT_MODE, key)) {
                        // Could not initialize cipher, key must have been invalidated
                        InternalCallback.requestKeyRevokedError(requestId, "Failed to initialize cipher.  Secret key must have been revoked");
                        return;
                        /*
                        if (!createKey()) {
                            InternalCallback.requestError(requestId, "Failed to create a new key after old key failed to initialize the cipher.  Something must be wrong.");
                            return;
                        }
                        if(!initCipher(Cipher.DECRYPT_MODE, key)) {
                            InternalCallback.requestError(requestId, "Failed to initialize the cipher even after generating new key.  Something must be wrong");
                            return;
                        }
                        */


                    }

                    BiometricPrompt.CryptoObject crypto = new BiometricPrompt.CryptoObject(mCipher());
                    //mFingerPrintManager.authenticate(crypto, cs, 0, callback, null);
                    new BiometricPrompt.Builder(AndroidNativeUtil.getActivity())
                            .setTitle(reason)
                            .setNegativeButton("Cancel", AndroidNativeUtil.getActivity().getMainExecutor(), new DialogInterface.OnClickListener() {
                                @Override
                                public void onClick(DialogInterface dialogInterface, int i) {
                                    InternalCallback.requestError(requestId, "__CANCELLED__");
                                }
                            })
                            .build().authenticate(crypto, cs, AndroidNativeUtil.getActivity().getMainExecutor(), callback);
                }
            });

        } else {
            InternalCallback.requestError(requestId, String.valueOf("No biometric hardware is available"));

        }
        return true;

    }

    /**
     * Gets a secure item.
     * @param requestId The request ID
     * @param reason The reason to show if a biometric prompt is shown.
     * @param key The key of the secure item.
     * @param requestAuth Whether to request biometric authentication.
     * @return If requestAuth is false, and we *need* to use biometric authentication, then this will return false.  Otherwise it returns true.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean getPassword(final int requestId, final String reason, final String key, final boolean requestAuth) {

        final SharedPreferences sharedPref = AndroidNativeUtil.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
        if (sharedPref.getString("fing_iv" + key, null) == null) {
            revokedOrMissing(requestId, sharedPref, key);
            return false;
        }
        // Before the availability check: when the user deleted EVERY biometric, nothing
        // is enrolled, so that check fails and the password would be reported as "not
        // available" -- although Android has already deleted its key and it can never be
        // read again, even after re-enrolment. A stored password with no key is revoked.
        if (getSecretKey() == null && keyRevokedState()) {
            InternalCallback.requestKeyRevokedError(requestId, "Key has been invalidated");
            return false;
        }
        if (isFingerprintAuthAvailable()) {
            SecretKey secretKey = getSecretKey();

            if (secretKey == null) {
                /*
                if (createKey()) {
                    secretKey = getSecretKey();
                } else {
                    InternalCallback.requestError(requestId, String.valueOf("Failed to create key"));
                    return false;
                }
                */
                if (keyRevokedState()) {
                    InternalCallback.requestKeyRevokedError(requestId, String.valueOf("Key has been invalidated"));
                } else {
                    InternalCallback.requestError(requestId, String.valueOf("No key found"));
                }
                return false;
            }



            runOnUiThreadIfNotAlready(new Runnable() {
                @RequiresApi(api = Build.VERSION_CODES.M)
                public void run() {
                    // Fingerprint scanning can continue for a long time even after the user
                    // has given up.  Keep a reference globally so that we can clear it
                    // if we need to start another scan.
                    if (cancellationSignal != null) {
                        cancellationSignal.cancel();
                        cancellationSignal = null;
                    }
                    final CancellationSignal cs = new CancellationSignal();
                    cancellationSignal = cs;
                    FingerprintManagerCompat.AuthenticationCallback callback = new FingerprintManagerCompat.AuthenticationCallback() {
                        int failures;

                        public void onAuthenticationError(int errorCode, CharSequence errString) {
                            InternalCallback.requestError(requestId, String.valueOf(errString));
                        }

                        public void onAuthenticationFailed() {
                            // NOTE: Often authentication fails several times
                            // before it succeeds.  Because often times it takes a while
                            // for the user to put their finger in the right spot
                            // This method will be called continually in a stream until
                            // either the user cancels the action, it succeeds, or until
                            // we cancel the action with cs.cancel.
                            // Here, we'll try 5 times then quit.
                            //if (failures++ > 5) {
                            //    cs.cancel();
                            //    InternalCallback.requestError(requestId, "Authentication failed");
                            //}

                        }

                        public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                            // Cancelled AFTER the cipher work: cancelling first may tear the
                            // keystore operation down under the doFinal the authentication
                            // unlocked, the suspected cause of issue #8.
                            try {
                            
                            try {
                                if (result.getCryptoObject() == null || result.getCryptoObject().getCipher() == null) {
                                    InternalCallback.requestError(requestId, "Authenticated cipher missing");
                                    return;
                                }
                                Cipher cipher = result.getCryptoObject().getCipher();
                                byte[] enc = Base64.decode(sharedPref.getString("fing" + key, ""), Base64.DEFAULT);

                                byte[] decrypted = cipher.doFinal(enc);
                                String decryptedStr = new String(decrypted);
                                InternalCallback.requestSuccess(requestId, decryptedStr);
                            } catch (Throwable e) {
                                if (isKeyInvalidation(e)) {
                                    removePermanentlyInvalidatedKey();
                                    InternalCallback.requestKeyRevokedError(requestId, "Key has been invalidated");
                                    return;
                                }
                                Log.e(e);
                                InternalCallback.requestError(requestId, e.getMessage());
                            }


                                                    } finally {
                                cs.cancel();
                            }
                        }
                    };
                    if(!initCipher(Cipher.DECRYPT_MODE, key)) {
                        // Could not initialize cipher, key must have been invalidated
                        InternalCallback.requestKeyRevokedError(requestId, "Failed to initialize cipher.  Secret key must have been revoked");
                        return;
                        /*
                        if (!createKey()) {
                            InternalCallback.requestError(requestId, "Failed to create a new key after old key failed to initialize the cipher.  Something must be wrong.");
                            return;
                        }
                        if(!initCipher(Cipher.DECRYPT_MODE, key)) {
                            InternalCallback.requestError(requestId, "Failed to initialize the cipher even after generating new key.  Something must be wrong");
                            return;
                        }
                        */


                    }

                    FingerprintManagerCompat.CryptoObject crypto = new FingerprintManagerCompat.CryptoObject(mCipher());
                    mFingerPrintManager.authenticate(crypto, 0, compatSignal(cs), callback, null);
                }
            });

        } else {
            InternalCallback.requestError(requestId, String.valueOf("No biometric hardware is available"));

        }
        return true;

    }

    private KeyStore mKeyStore() {
        if (mKeyStore == null) {
            try {
                mKeyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
                mKeyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
            } catch (NoSuchProviderException e) {
                throw new RuntimeException("Failed to get an instance of KeyGenerator", e);
            } catch (KeyStoreException e) {
                throw new RuntimeException("Failed to get an instance of KeyStore", e);
            }
        }
        return mKeyStore;
    }

    private KeyGenParameterSpec.Builder decorate(KeyGenParameterSpec.Builder builder) {
        // Bound on EVERY API level, and revoked by a new enrolment. From 1.1.3 to
        // 1.1.5 the binding was skipped on API 33+ to hide issue #8 ("Key user not
        // authenticated"). An unbound key decrypts with no authentication and is never
        // invalidated, so a fingerprint enrolled by anyone who knows the device PIN
        // unlocked every stored password while the prompt still looked like protection.
        // #8's cause was never established: the prompt already carried the cipher as its
        // CryptoObject. The likeliest suspect, cancelling the signal before doFinal, is
        // gone (see onAuthenticationSucceeded).
        builder.setUserAuthenticationRequired(true);
        if (Build.VERSION.SDK_INT >= 24) {
            builder.setInvalidatedByBiometricEnrollment(true);
        }

        return builder;
    }

    /**
     * Creates a symmetric key in the Android Key Store which can only be used after the user has
     * authenticated with fingerprint.
     */
    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean createKey() {
        String errorMessage = "";
        String createKeyExceptionErrorPrefix = "Failed to create key: ";
        boolean isKeyCreated = false;
        // The enrolling flow for fingerprint. This is where you ask the user to set up fingerprint
        // for your flow. Use of keys is necessary if you need to know if the set of
        // enrolled fingerprints has changed.
        try {
            mKeyStore().load(null);
            // Set the alias of the entry in Android KeyStore where the key will appear
            // and the constrains (purposes) in the constructor of the Builder
            mKeyGenerator.init(decorate(new KeyGenParameterSpec.Builder(KEY_ID,
                    KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT).setBlockModes(
                            KeyProperties.BLOCK_MODE_CBC)
                    .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7))
                    .build());
            mKeyGenerator.generateKey();

            isKeyCreated = true;
        } catch (NoSuchAlgorithmException e) {
            errorMessage = createKeyExceptionErrorPrefix + "NoSuchAlgorithmException";
        } catch (InvalidAlgorithmParameterException e) {
            errorMessage = createKeyExceptionErrorPrefix + "InvalidAlgorithmParameterException";
        } catch (CertificateException e) {
            errorMessage = createKeyExceptionErrorPrefix + "CertificateException";
        } catch (IOException e) {
            errorMessage = createKeyExceptionErrorPrefix + "IOException";
        }
        if (!isKeyCreated) {
            Log.p(errorMessage);

        }
        return isKeyCreated;
    }
    // Per thread: initCipher runs getSecretKey on the UI thread while a request thread may
    // sit between its own getSecretKey and reading these. As shared fields, one reset the
    // other's answer -- an unverified key read as absent and was replaced.
    private static final ThreadLocal<boolean[]> KEY_STATE = new ThreadLocal<boolean[]>() {
        @Override
        protected boolean[] initialValue() {
            return new boolean[2];
        }
    };

    private static boolean keyRevokedState() {
        return KEY_STATE.get()[0];
    }

    private static boolean keyUnverifiedState() {
        return KEY_STATE.get()[1];
    }

    private SecretKey getSecretKey() {
        boolean[] state = KEY_STATE.get();
        state[0] = false;
        state[1] = false;
        String errorMessage = "";
        String getSecretKeyExceptionErrorPrefix = "Failed to get SecretKey from KeyStore: ";
        SecretKey key = null;
        try {
            mKeyStore().load(null);
            key = (SecretKey) mKeyStore.getKey(KEY_ID, null);
            if (key == null) {
                // Android deletes a biometric-bound key outright when the user removes
                // EVERY enrolled biometric, instead of failing with
                // KeyPermanentlyInvalidatedException. Both callers that read keyRevoked
                // return first when no password is stored, so an absent key there means
                // a stored password whose key was taken away: revoked, not "No key found".
                // Not wiped here: below API 31 getKey also answers null when the keystore
                // cannot be reached. The passwords are dropped when a new key replaces it.
                state[0] = true;
            } else if (bindingOf(key) == BINDING_UNKNOWN && Build.VERSION.SDK_INT >= 33) {
                // Only 33+ ever had unbound keys: one whose binding cannot be read there is
                // neither used (it may be one) nor deleted (on a guess).
                state[1] = true;
                return null;
            } else if (bindingOf(key) == BINDING_NONE) {
                // Created unbound on API 33+ by 1.1.3 - 1.1.5. It cannot be trusted with
                // what it holds: delete it and report the passwords as revoked, so the app
                // asks the user to set biometric login up again.
                removePermanentlyInvalidatedKey();
                state[0] = true;
                return null;
            }
        } catch (KeyStoreException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "KeyStoreException";
        } catch (CertificateException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "CertificateException";
        } catch (UnrecoverableKeyException e) {
            state[0] = true;
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableKeyException";
        } catch (IOException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "IOException";
        } catch (NoSuchAlgorithmException e) {
            errorMessage = getSecretKeyExceptionErrorPrefix + "NoSuchAlgorithmException";
        } catch (UnrecoverableEntryException e) {
            state[0] = true;
            errorMessage = getSecretKeyExceptionErrorPrefix + "UnrecoverableEntryException";
        }
        if (key == null) {
            Log.p(errorMessage);
        }
        return key;
    }

    private Cipher mCipher() {
        if (mCipher == null) {
            try {
                mCipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                        + "/"
                        + KeyProperties.BLOCK_MODE_CBC
                        + "/"
                        + KeyProperties.ENCRYPTION_PADDING_PKCS7);
            } catch (NoSuchAlgorithmException e) {
                throw new RuntimeException("Failed to get an instance of Cipher", e);
            } catch (NoSuchPaddingException e) {
                throw new RuntimeException("Failed to get an instance of Cipher", e);
            }

        }
        return mCipher;
    }

    @RequiresApi(api = Build.VERSION_CODES.M)
    private static class CipherInitializerM {


        @RequiresApi(api = Build.VERSION_CODES.M)
        private static boolean initCipher(InternalFingerprintImpl impl, int mode, String account) {

            boolean initCipher = false;
            String errorMessage = "";
            String initCipherExceptionErrorPrefix = "Failed to init Cipher: ";
            try {
                SecretKey key = impl.getSecretKey();
                // A new Cipher for every operation. One shared instance re-initialised by
                // a second request while the first prompt was still up handed the first
                // prompt's callback a cipher in the wrong mode or with the wrong IV.
                impl.mCipher = null;

                if (mode == Cipher.ENCRYPT_MODE) {
                    SecureRandom r = new SecureRandom();
                    byte[] ivBytes = new byte[16];
                    r.nextBytes(ivBytes);

                    impl.mCipher().init(mode, key);
                } else {
                    SharedPreferences sharedPref = AndroidNativeUtil.getActivity().getApplicationContext().getSharedPreferences(SHARED_PREFS_NAME,Context.MODE_PRIVATE);
                    byte[] ivBytes =
                            Base64.decode(sharedPref.getString("fing_iv" + account, ""), Base64.DEFAULT);
                    impl.mCipher().init(mode, key, new IvParameterSpec(ivBytes));
                }

                initCipher = true;
            } catch (KeyPermanentlyInvalidatedException e) {
                // Note: on Samsung devices with 8.0.0 this doesn't work... it will initially work
                // and then fail after authentication saying that user was not authenticated.
                // https://issuetracker.google.com/u/0/issues/65578763
                // We'll handle that additional failure there.
                impl.removePermanentlyInvalidatedKey();
                errorMessage = "KeyPermanentlyInvalidatedException";

            } catch (InvalidKeyException e) {
                errorMessage = initCipherExceptionErrorPrefix + "InvalidKeyException";
            } catch (InvalidAlgorithmParameterException e) {
                errorMessage = initCipherExceptionErrorPrefix + "InvalidAlgorithmParameterException";
                e.printStackTrace();
            }
            if (!initCipher) {
                Log.p(errorMessage);
            }
            return initCipher;
        }
    }



    @RequiresApi(api = Build.VERSION_CODES.M)
    private boolean initCipher(int mode, String account) {
        return CipherInitializerM.initCipher(this, mode, account);
    }

    private void removePermanentlyInvalidatedKey() {
        synchronized (KEY_LOCK) {
            removeKeyUnderLock();
        }
    }

    private void removeKeyUnderLock() {
        try {
            mKeyStore().deleteEntry(KEY_ID);
            if (mKeyStore().containsAlias(KEY_ID)) {
                // Still there: so are the passwords it can read. Never wipe them for a
                // key that was not removed.
                Log.p("The invalidated key could not be removed.");
                return;
            }
            Log.p("Permanently invalidated key was removed.");
        } catch (KeyStoreException e) {
            Log.e(e);
            return;
        }
        revokeAllPasswords();
    }

    private static final Object KEY_LOCK = new Object();

    /**
     * Creates a key only when there is none, and drops every password stored under the
     * one that is gone. Never overwrites an existing alias: a key that is present but
     * failed (a keystore hiccup, an UnrecoverableKeyException) still reads every stored
     * password, and replacing it would destroy them on a guess. A key proven invalidated
     * has already been deleted by removePermanentlyInvalidatedKey.
     *
     * <p>Not guarded: an add whose doFinal finished just before another request replaced
     * the key commits ciphertext under the dead key, and that one account then fails to
     * decrypt instead of reporting revoked. Core's SecureStorage closes that window with
     * a key generation; this lib is discontinued in its favour and does not.</p>
     */
    private boolean createReplacementKey() {
        synchronized (KEY_LOCK) {
            // A concurrent request may have created it since this one looked.
            if (getSecretKey() != null) {
                return true;
            }
            try {
                mKeyStore().load(null);
                if (mKeyStore().containsAlias(KEY_ID)) {
                    return false;
                }
            } catch (Exception e) {
                Log.e(e);
                return false;
            }
            if (!createKey()) {
                return false;
            }
            revokeAllPasswords();
            return true;
        }
    }

    /**
     * Revoked markers live in their own file, keyed by the bare account: in the main
     * file a prefix would share the "fing" + account namespace of the values.
     */
    private static final String REVOKED_PREFS_NAME = SHARED_PREFS_NAME + ".revoked";

    private static SharedPreferences revokedPrefs() {
        return AndroidNativeUtil.getActivity().getApplicationContext()
                .getSharedPreferences(REVOKED_PREFS_NAME, Context.MODE_PRIVATE);
    }

    /**
     * The keystore's own failure under doFinal. That is android.security.KeyStoreException
     * (public only from API 33, hidden before) -- not java.security.KeyStoreException,
     * which an instanceof against the imported name tested and so never matched.
     */
    private static boolean isKeystoreError(Throwable t) {
        return t != null && t.getClass().getName().endsWith("KeyStoreException");
    }

    /**
     * Whether a failure says the KEY is finished, as opposed to this one operation.
     * Deleting the key drops every stored password, so only these two shapes do it:
     * the exception Android raises for it, and a keystore error under doFinal.
     */
    private static boolean isKeyInvalidation(Throwable t) {
        Throwable c = t;
        for (int depth = 0; c != null && depth < 8; depth++) {
            if (c instanceof KeyPermanentlyInvalidatedException) {
                return true;
            }
            // The Samsung 8.0.0 quirk, and only there: elsewhere this shape is also "user
            // not authenticated" or a pruned operation, one failed request that must not
            // delete the key every password shares.
            if ((Build.VERSION.SDK_INT == 26 || Build.VERSION.SDK_INT == 27)
                    && c instanceof IllegalBlockSizeException
                    && isKeystoreError(c.getCause())) {
                return true;
            }
            if (c.getCause() == c) {
                break;
            }
            c = c.getCause();
        }
        return false;
    }

    /**
     * Drops every password encrypted under the key, which is gone, leaving a revoked
     * marker. Left in place, the next addPassword creates a new key and every OTHER
     * account's old password then fails to decrypt under it with a padding error,
     * which reads as a generic failure instead of a revocation.
     */
    private void revokeAllPasswords() {
        SharedPreferences sp = AndroidNativeUtil.getActivity().getApplicationContext()
                .getSharedPreferences(SHARED_PREFS_NAME, Context.MODE_PRIVATE);
        SharedPreferences.Editor revoked = revokedPrefs().edit();
        SharedPreferences.Editor values = sp.edit();
        for (String k : sp.getAll().keySet()) {
            if (k.startsWith("fing_iv")) {
                // An account starting "_iv" has its VALUE key here too ("fing" + "_iv..."):
                // only a key with a value under the derived account is an IV.
                String account = k.substring("fing_iv".length());
                if (sp.contains("fing" + account)) {
                    revoked.putBoolean(account, true);
                    values.remove(k).remove("fing" + account);
                }
            }
        }
        // Markers first: a crash between the two commits leaves an account both stored
        // and marked, which a successful read or write clears, rather than gone unmarked.
        revoked.commit();
        values.commit();
    }

    private void revokedOrMissing(int requestId, SharedPreferences sp, String key) {
        if (revokedPrefs().contains(key)) {
            InternalCallback.requestKeyRevokedError(requestId, "Key has been invalidated");
        } else {
            InternalCallback.requestError(requestId, "The specified item could not be found in the keychain.");
        }
    }

    private static final int BINDING_BOUND = 0;
    private static final int BINDING_NONE = 1;
    private static final int BINDING_UNKNOWN = 2;

    /** Whether the keystore enforces user authentication for the key, if it can say. */
    private static int bindingOf(SecretKey k) {
        try {
            SecretKeyFactory f = SecretKeyFactory.getInstance(k.getAlgorithm(), ANDROID_KEY_STORE);
            KeyInfo info = (KeyInfo) f.getKeySpec(k, KeyInfo.class);
            return info.isUserAuthenticationRequired() ? BINDING_BOUND : BINDING_NONE;
        } catch (Throwable t) {
            Log.e(t);
            return BINDING_UNKNOWN;
        }
    }

    public void cancelRequest(final int requestId) {
        runOnUiThreadIfNotAlready(new Runnable() {
            public void run() {
                if (cancellationSignal != null) {
                    cancellationSignal.cancel();
                    cancellationSignal = null;
                    InternalCallback.requestError(requestId, "__CANCELLED__");
                }

            }
        });
    }

    private void runOnUiThreadIfNotAlready(final Runnable r) {
        if (Looper.getMainLooper().getThread() == Thread.currentThread()) {
            // On UI thread.
            r.run();
        } else {
            // Not on UI thread.
            AndroidNativeUtil.getActivity().runOnUiThread(r);
        }
    }
}