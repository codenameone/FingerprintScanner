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
package com.codename1.fingerprint;

import com.codename1.components.SpanLabel;
import com.codename1.fingerprint.impl.InternalCallback;
import com.codename1.fingerprint.impl.InternalFingerprint;
import com.codename1.system.NativeLookup;
import com.codename1.ui.Button;
import com.codename1.ui.CN;
import com.codename1.ui.Container;
import com.codename1.ui.Dialog;
import com.codename1.ui.Display;
import com.codename1.ui.FontImage;
import com.codename1.ui.Label;
import com.codename1.ui.layouts.BorderLayout;
import com.codename1.ui.layouts.BoxLayout;
import com.codename1.util.AsyncResource;
import com.codename1.util.FailureCallback;
import com.codename1.util.SuccessCallback;

/**
 * Implements the fingerprint scanning API, and provides the ability to store passwords
 * in the system keychain protected cryptographically by biometrics.
 */
public class Fingerprint {
    private static final String DISPLAY_KEY = "Fingerprint.types";

    private static InternalFingerprint impl;

    static {
        // prevents the iOS VM optimizer from optimizing away these callbacks...
        InternalCallback.scanFail();
        InternalCallback.scanSuccess();
        InternalCallback.scanSuccess((String)null, (String)null);
        InternalCallback.requestError(0, null);
        InternalCallback.requestComplete(0, true);
        InternalCallback.requestSuccess(0, null);
    }
    
    private static interface PasswordRequest {
        int getRequestId();
    }
    
    private static class BooleanPasswordRequest extends AsyncResource<Boolean> implements PasswordRequest {
        private int requestId;
        private boolean shouldPrompt;
        private boolean didPrompt;

        @Override
        public int getRequestId() {
            return requestId;
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            impl.cancelRequest(requestId);
            return super.cancel(mayInterruptIfRunning);
        }
        
        
        
    }
    
    private static class StringPasswordRequest extends AsyncResource<String> implements PasswordRequest {
        private int requestId;

        @Override
        public int getRequestId() {
            return requestId;
        }

        @Override
        public boolean cancel(boolean mayInterruptIfRunning) {
            impl.cancelRequest(requestId);
            return super.cancel(mayInterruptIfRunning);
        }
        
        
    }

    /**
     * Checks if the platforms supports fingerprint scanning. Currently this will return true on
     * Android and iOS, and false elsewhere.
     * @return 
     */
    public static boolean isAvailable() {
        if (impl == null) {
            impl = NativeLookup.create(InternalFingerprint.class);
            
        }
        return impl != null && impl.isSupported() && impl.isAvailable();
    }
    
    /**
     * Checks if Face ID authentication is available on this device.
     * 
     * <p>Note: On Android 9 and 10, this will always return false even if the device supports facial recognition.  This is because the
     * Android API to query this information wasn't added until Android 11, even though facial recognition is
     * supported as early as Android 9.  Use the {@link #mightFaceIDBeAvailable() } method to check if facial ID
     * might be supported. </p>
     * 
     * @return True if face id auth is available.
     */
    public static boolean isFaceIDAvailable() {
        return isAvailable() && CN.getProperty(DISPLAY_KEY, "").indexOf("face") != -1;
    }
    
    /**
     * This method was added because Android 9 and 10 doesn't provide a way to check if the device supports 
     * facial recognition, therefore, {@link #isFaceIDAvailable() } will always return {@literal false} on 
     * those devices.  This method will return true if face ID might be available.  It will return false
     * if we know that it is not available.
     * 
     * @return True if face ID might be available
     */
    public static boolean mightFaceIDBeAvailable() {
        return isFaceIDAvailable() || (isTouchIDAvailable() && CN.getProperty(DISPLAY_KEY, "").indexOf("biometric") != -1);
    }
    
    /**
     * Checks if touch ID authentication is available on this device.
     * @return True if touch ID is available
     */
    public static boolean isTouchIDAvailable() {
        return isAvailable() && CN.getProperty(DISPLAY_KEY, "").indexOf("touch") != -1;
    }

    /**
     * Scans a fingerprint and will fire the appropriate callback depending on whether 
     * the user was authenticated or not.
     * @param onSuccess Callback fired on successful authentication.
     * @param onFail Callback fired on error or failed authentication.
     * 
     */
    public static void scanFingerprint(SuccessCallback<Object> onSuccess, FailureCallback<Object> onFail) {
        if (!isAvailable()) {
            if (onFail != null) {
                onFail.onError(null, new IllegalStateException("Fingerprint scanning not available"), 0, "Fingerprint scanning not available");
            }
            return;
        }
        InternalCallback.init(null, onSuccess, onFail, true);
        impl.scan(null);
    }

    /**
     * Scans a fingerprint and will fire the appropriate callback depending on whether 
     * the user was authenticated or not.
     * @param reason A message to be displayed in the fingerprint scanning dialog.
     * @param onSuccess Callback fired on successful authentication.
     * @param onFail Callback fired on error or failed authentication.
     * 
     */
    public static void scanFingerprint(String reason, SuccessCallback<Object> onSuccess, FailureCallback<Object> onFail) {
        if (!isAvailable()) {
            if (onFail != null) {
                onFail.onError(null, new IllegalStateException("Fingerprint scanning not available"), 0, "Fingerprint scanning not available");
            }
            return;
        }
        InternalCallback.init(reason, onSuccess, onFail, true);
        impl.scan(reason);
    }
    /**
     * Scans a fingerprint and will fire the appropriate callback depending on whether 
     * the user was authenticated or not.
     * @param onSuccess Callback fired on successful authentication.
     * @param onFail Callback fired on error or failed authentication.
     * @param showDialogOnAndroid False to not show the dialog on android.
     */
    public static void scanFingerprint(SuccessCallback<Object> onSuccess, FailureCallback<Object> onFail, boolean showDialogOnAndroid) {
        if (!isAvailable()) {
            if (onFail != null) {
                onFail.onError(null, new IllegalStateException("Fingerprint scanning not available"), 0, "Fingerprint scanning not available");
            }
            return;
        }
        InternalCallback.init(null, onSuccess, onFail, showDialogOnAndroid);
        impl.scan(null);
    }

    /**
     * Scans a fingerprint and will fire the appropriate callback depending on whether 
     * the user was authenticated or not.
     * @param reason Message to display in the dialog.
     * @param onSuccess Callback fired on successful authentication.
     * @param onFail Callback fired on error or failed authentication.
     * @param showDialogOnAndroid False to not show the dialog on android.
     */
    public static void scanFingerprint(String reason, SuccessCallback<Object> onSuccess, FailureCallback<Object> onFail, boolean showDialogOnAndroid) {
        if (!isAvailable()) {
            if (onFail != null) {
                onFail.onError(null, new IllegalStateException("Fingerprint scanning not available"), 0, "Fingerprint scanning not available");
            }
            return;
        }
        InternalCallback.init(reason, onSuccess, onFail, showDialogOnAndroid);
        impl.scan(reason);
    }
    
    /**
     * Gets a password from the keychain.  This will prompt the user to authenticate using biometrics (fingerprint or face recognition).
     * 
     * <p>Note:  If the user adds any new fingerprints or biometric validations to the device, all passwords
     * stored with the old set of fingerprints (etc..) will be invalidated.
     * @param reason Message to display in fingerprint scanning dialog that appears.
     * @param account The account name whose password we wish to obtain.
     * @return AsyncResource Use onResult() or ready() callback to obtain the password, or error condition.  If the password exists in 
     * the keychain, the result will be the password as a string.  If the password doesn't exist, then it will return an error.
     */
    public static AsyncResource<String> getPassword(String reason, String account) {
        return getPassword(reason, account, showDialogOnAndroid());
    }
    
    private static boolean showDialogOnAndroid() {
        if (CN.getProperty("FingerprintScanner.showDialogOnAndroid.override", null) != null) {
            return "true".equals(CN.getProperty("FingerprintScanner.showDialogOnAndroid.override", null));
        }
        isAvailable();
        return "true".equals(CN.getProperty("FingerprintScanner.showDialogOnAndroid", "false"));
    }
    
    /**
     * Gets a password from the keychain with option to hide android dialog.  
     * 
     * <p>This will prompt the user to authenticate using biometrics (fingerprint or face recognition).</p>
     * 
     * <p>Note:  If the user adds any new fingerprints or biometric validations to the device, all passwords
     * stored with the old set of fingerprints (etc..) will be invalidated.
     * @param reason Message to display in fingerprint scanning dialog that appears.
     * @param account The account name whose password we wish to obtain.
     * @param showDialogOnAndroid Set false to not show a dialog.  User would still need to use biometrics to authenticate
     * so if you set this to false, you should provide your own dialog on Android.
     * @return AsyncResource Use onResult() or ready() callback to obtain the password, or error condition.  If the password exists in 
     * the keychain, the result will be the password as a string.  If the password doesn't exist, then it will return an error.
     */
    public static AsyncResource<String> getPassword(String reason, String account, boolean showDialogOnAndroid) {
        StringPasswordRequest out = new StringPasswordRequest();
        if (!isAvailable()) {
            out.error(new IllegalStateException("Fingerprint scanning not available"));
            return out;
        }
        out.requestId = InternalCallback.addRequest(out);
        if (showDialogOnAndroid) {
            showDialogOnAndroid(reason, out);
        }
        impl.getPassword(out.requestId, reason, account);
        return out;
    }
    
    /**
     * Adds a password to the keychain.  The user will be prompted to authenticate using biometrics.
     * 
     * @param reason A message to display in the fingerprint authentication dialog.
     * @param account The account that the password is for.
     * @param password The password which you wish to store in the keychain.
     * @return AsyncResource that will return success/fail.
     */
    public static AsyncResource<Boolean> addPassword(String reason, String account, String password) {
        return addPassword(reason, account, password, showDialogOnAndroid());
    }
    
    /**
     * Adds a password to the keychain.  Some platforms may prompt the user to authenticate
     * to perform this function.  iOS (at least in iOS 13) will not authenticate the user for
     * this action.  It will only authenticate when the user wants to retrieve the password.
     * This is likely because adding authentication at this point wouldn't add any security
     * since the user could just add their fingerprint in "Settings", return to the app
     * and authenticate.  This same loop-hole doesn't exist for getting passwords because
     * passwords are automatically invalidated when adding additional fingerprints to the device.
     * 
     * <p>Enabling authentication for adding passwords on iOS can be achieved by setting 
     * the "ios.Fingerprint.addPassword.prompt" display property to "true"</p>
     * 
     * @param reason A message to display in the fingerprint authentication dialog.
     * @param account The account that the password is for.
     * @param password The password which you wish to store in the keychain.
     * @param showDialogOnAndroid Set false to not show a dialog.  User would still need to use biometrics to authenticate
     * so if you set this to false, you should provide your own dialog on Android.
     * @return AsyncResource that will return success/fail.
     */
    public static AsyncResource<Boolean> addPassword(String reason, String account, String password, boolean showDialogOnAndroid) {
        BooleanPasswordRequest out = new BooleanPasswordRequest();
        if (isAvailable() && "ios".equals(CN.getPlatformName()) && !CN.isSimulator()) {
            if ("true".equals(CN.getProperty("ios.Fingerprint.addPassword.prompt", "false"))) {
                // This little hook is just for iOS.
                // iOS SecAddItem method doesn't prompt for authentication because
                // it wouldn't add any security (user could just add their their fingerprint
                // in settings and return to app to authenticate).  Client, however, 
                // still wants this feature.
                // This behaviour is disabled by default.  It can be enabled by setting the
                // ios.Fingerprint.addPassword.prompt display property to "true"
                out.shouldPrompt = true;
            }
        }
        return addPassword(out, reason, account, password, showDialogOnAndroid);
    }
    
    private static AsyncResource<Boolean> addPassword(BooleanPasswordRequest out, String reason, String account, String password, boolean showDialogOnAndroid) { 
        if (!isAvailable()) {
            out.error(new IllegalStateException("Fingerprint scanning not available"));
            return out;
        }
        out.requestId = InternalCallback.addRequest(out);
        if (showDialogOnAndroid) {
            showDialogOnAndroid(reason, out);
        }
        if (out.shouldPrompt && !out.didPrompt) {
            // This little hook is just for iOS.
            // iOS SecAddItem method doesn't prompt for authentication because
            // it wouldn't add any security (user could just add their their fingerprint
            // in settings and return to app to authenticate).  Client, however, 
            // still wants this feature.
            // This behaviour is disabled by default.  It can be enabled by setting the
            // ios.Fingerprint.addPassword.prompt display property to "true"
            scanFingerprint(reason, res->{
                out.didPrompt = true;
                addPassword(out, reason, account, password, showDialogOnAndroid);
            }, new FailureCallback<Object>() {
                @Override
                public void onError(Object arg0, Throwable arg1, int arg2, String arg3) {
                    out.didPrompt = true;
                    out.error(arg1);
                }
            });
            return out;
        }
        impl.addPassword(out.requestId, reason, account, password);
        return out;
    }
    
    /**
     * Deletes a password form the keychain
     * @param reason Message to display in authentication dialog if one is shown.
     * @param account The account to delete the password for.
     * @return 
     */
    public static AsyncResource<Boolean> deletePassword(String reason, String account) {
        BooleanPasswordRequest out = new BooleanPasswordRequest();
        if (!isAvailable()) {
            out.error(new IllegalStateException("Fingerprint scanning not available"));
            return out;
        }
        out.requestId = InternalCallback.addRequest(out);
        impl.deletePassword(out.requestId, reason, account);
        return out;
    }
    
    private static void showDialogOnAndroid(String reason, AsyncResource<?> request) {
        if (Display.getInstance().getPlatformName().equals("and")) {
            if (reason == null) {
                reason = "Authenticate for server login";
            }
            Dialog d = new Dialog(new BorderLayout());
            Label fingerprintIcon = new Label("", "DialogBody");
            Container iconWrapper = new Container(BoxLayout.x());
            iconWrapper.add(fingerprintIcon);
            fingerprintIcon.getUnselectedStyle().setFgColor(0xff5722); //Sets icon color to orange
            SpanLabel lblReason = new SpanLabel(reason, "DialogBody");
            FontImage.setMaterialIcon(fingerprintIcon, FontImage.MATERIAL_FINGERPRINT, 7);
            d.add(BorderLayout.CENTER, BoxLayout.encloseY(iconWrapper, lblReason));
            Button cancel = new Button("Cancel");
            cancel.addActionListener(e->{
                if (!request.isDone()) {
                    request.cancel(true);
                }
                d.dispose();
            });
            d.add(BorderLayout.SOUTH, cancel);
            d.showPacked(BorderLayout.CENTER, false);
            request.onResult((res, err)->{
                d.dispose();
            });
        }
    }
    
    
    
    
}
