package com.codename1.fingerprint.impl;

public class InternalFingerprintImpl implements com.codename1.fingerprint.impl.InternalFingerprint{
    public boolean isAvailable() {
        return false;
    }

    public void scan(String reason) {
    }

    public boolean isSupported() {
        return false;
    }

}
