package com.codename1.fingerprint.impl;

import android.hardware.fingerprint.FingerprintManager;
import com.codename1.impl.android.AndroidNativeUtil;
import com.codename1.impl.android.AndroidImplementation;
import android.os.CancellationSignal;
import android.hardware.fingerprint.FingerprintManager.AuthenticationCallback;
import android.Manifest;
import android.app.Activity;
import com.codename1.io.Log;

public class InternalFingerprintImpl {
    private FingerprintManager mFingerPrintManager;
    public boolean isAvailable() {
        final boolean[] response = new boolean[1];
        AndroidImplementation.runOnUiThreadAndBlock(new Runnable() {
            public void run() {
                if(!AndroidNativeUtil.checkForPermission(Manifest.permission.USE_FINGERPRINT, "Authorize using fingerprint")){
                    return;
                }
                try {
                    mFingerPrintManager = (FingerprintManager)AndroidNativeUtil.getActivity().
                                                                                            getSystemService(Activity.FINGERPRINT_SERVICE);

                    response[0] = mFingerPrintManager.isHardwareDetected() && 
                        mFingerPrintManager.hasEnrolledFingerprints();
                } catch(Throwable t) {
                    Log.p("This exception could be 100% valid on old devices, we're logging it just to be safe. Older devices might throw NoClassDefFoundError...");
                    Log.e(t);
                }
            }
        });
        return response[0];
    }

    public void scan(String reason) {
        AndroidNativeUtil.getActivity().runOnUiThread(new Runnable() {
            public void run() {
                CancellationSignal cs = new CancellationSignal();
                
                AuthenticationCallback callback = new AuthenticationCallback() {
                    public void onAuthenticationError(int errorCode, CharSequence errString) {
                        InternalCallback.scanFail();
                    }

                    public void onAuthenticationFailed() {
                        InternalCallback.scanFail();
                    }
                    
                    public void onAuthenticationSucceeded(FingerprintManager.AuthenticationResult result) {
                        InternalCallback.scanSuccess();
                    }
                };
                
                mFingerPrintManager.authenticate(null, cs, 0, callback, null);
            }
        });
    }

    public boolean isSupported() {
        return true;
    }

}
