/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package com.codename1.fingerprint.impl;

import com.codename1.system.NativeInterface;

/**
 * @deprecated internal implementation detail please use {@code Fingerprint}
 */
public interface InternalFingerprint extends NativeInterface {
    public boolean isAvailable();
    public void scan();
}
