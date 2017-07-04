/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.codename1.fingerprint;

import com.codename1.fingerprint.impl.InternalCallback;
import com.codename1.fingerprint.impl.InternalFingerprint;
import com.codename1.system.NativeLookup;
import com.codename1.ui.Display;
import com.codename1.util.FailureCallback;
import com.codename1.util.SuccessCallback;

/**
 * Implements the fingerprint scanning API
 */
public class Fingerprint {

    private static InternalFingerprint impl;

    static {
        // prevents the iOS VM optimizer from optimizing away these callbacks...
        InternalCallback.scanFail();
        InternalCallback.scanSuccess();
    }

    public static boolean isAvailable() {
        impl = NativeLookup.create(InternalFingerprint.class);
        return impl != null && impl.isSupported() && impl.isAvailable();
    }

    public static void scanFingerprint(SuccessCallback<Object> onSuccess, FailureCallback<Object> onFail) {
        InternalCallback.init(null, onSuccess, onFail);
        impl.scan(null);
    }

    public static void scanFingerprint(String reason, SuccessCallback<Object> onSuccess, FailureCallback<Object> onFail) {
        InternalCallback.init(reason, onSuccess, onFail);
        impl.scan(reason);
    }
}
