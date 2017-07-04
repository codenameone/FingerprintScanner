package com.codename1.fingerprint.impl;

import com.codename1.system.NativeInterface;

/**
 * @deprecated internal implementation detail please use {@code Fingerprint}
 */
public interface InternalFingerprint extends NativeInterface {
    public boolean isAvailable();
    public void scan();
    public void scan(String reason);
}
