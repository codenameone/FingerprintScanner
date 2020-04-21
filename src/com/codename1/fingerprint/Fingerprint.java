/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.codename1.fingerprint;

import com.codename1.components.SpanLabel;
import com.codename1.fingerprint.impl.InternalCallback;
import com.codename1.fingerprint.impl.InternalFingerprint;
import com.codename1.system.NativeLookup;
import com.codename1.ui.CN;
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
    
    private static class BooleanPasswordRequest extends AsyncResource<Boolean> {
        private boolean shouldPrompt;
        private boolean didPrompt;
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
     * @return True if face id auth is available.
     */
    public static boolean isFaceIDAvailable() {
        isAvailable(); // Platforms set the DISPLAY_KEY display property in isAvailable()
        return CN.getProperty(DISPLAY_KEY, "").indexOf("face") != -1;
    }
    
    /**
     * Checks if touch ID authentication is available on this device.
     * @return True if touch ID is available
     */
    public static boolean isTouchIDAvailable() {
        isAvailable(); // Platforms set the DISPLAY_KEY display property in isAvailable()
        return CN.getProperty(DISPLAY_KEY, "").indexOf("touch") != -1;
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
        return getPassword(reason, account, true);
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
        AsyncResource<String> out = new AsyncResource<>();
        if (!isAvailable()) {
            out.error(new IllegalStateException("Fingerprint scanning not available"));
            return out;
        }
        int requestId = InternalCallback.addRequest(out);
        if (showDialogOnAndroid) {
            showDialogOnAndroid(reason, out);
        }
        impl.getPassword(requestId, reason, account);
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
        return addPassword(reason, account, password, true);
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
        int requestId = InternalCallback.addRequest(out);
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
        impl.addPassword(requestId, reason, account, password);
        return out;
    }
    
    /**
     * Deletes a password form the keychain
     * @param reason Message to display in authentication dialog if one is shown.
     * @param account The account to delete the password for.
     * @return 
     */
    public static AsyncResource<Boolean> deletePassword(String reason, String account) {
        AsyncResource<Boolean> out = new AsyncResource<>();
        if (!isAvailable()) {
            out.error(new IllegalStateException("Fingerprint scanning not available"));
            return out;
        }
        int requestId = InternalCallback.addRequest(out);
        impl.deletePassword(requestId, reason, account);
        return out;
    }
    
    private static void showDialogOnAndroid(String reason, AsyncResource<?> request) {
        if (Display.getInstance().getPlatformName().equals("and")) {
            if (reason == null) {
                reason = "Authenticate for server login";
            }
            Dialog d = new Dialog(new BorderLayout());
            Label icon = new Label("", "DialogBody");
            icon.getUnselectedStyle().setFgColor(0xff5722); //Sets icon color to orange
            SpanLabel lblReason = new SpanLabel(reason, "DialogBody");
            FontImage.setMaterialIcon(icon, FontImage.MATERIAL_FINGERPRINT, 7);
            d.add(BorderLayout.CENTER, BoxLayout.encloseY(icon, lblReason));
            d.showPacked(BorderLayout.CENTER, false);
            request.onResult((res, err)->{
                d.dispose();
            });
        }
    }
    
    
    
    
}
