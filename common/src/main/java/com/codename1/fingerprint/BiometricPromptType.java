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

/**
 * What an application should call the device's biometric authentication in its own UI: the
 * wording and icon of a "sign in with ..." button. Returned by {@link Fingerprint#getPromptType()}.
 *
 * <p>It is one answer for every platform and OS release, so an application does not need to
 * check either.</p>
 */
public enum BiometricPromptType {
    /**
     * Biometric authentication cannot be used: no hardware, or nothing enrolled.
     */
    NONE,

    /**
     * Ask for a fingerprint (Touch ID on iOS).
     */
    FINGERPRINT,

    /**
     * Ask for the face (Face ID on iOS).
     */
    FACE,

    /**
     * Biometric authentication can be used and there is no single name for it. Use neutral
     * wording ("Use biometrics"); the system prompt directs the user to the right sensor.
     *
     * <p>This is every available case that is not one of the two above: a device that does not
     * say which kind the user enrolled (Android 17 and later with a fingerprint sensor together
     * with face or iris hardware), an iris scanner, and a kind this library has no name for.</p>
     */
    BIOMETRICS;

    /**
     * Token a port adds to the type list when it can authenticate but cannot tell which of its
     * sensors has an enrolment. It deliberately contains none of "touch", "face" or "biometric",
     * which the older availability methods search the same list for.
     */
    static final String UNDETERMINED = "mixed";

    /**
     * Maps the type list a port publishes to the single answer.
     *
     * <p>Without the {@link #UNDETERMINED} token this is exactly "touch, else face, else
     * generic", which is the order an application calling {@code isTouchIDAvailable()} and then
     * {@code isFaceIDAvailable()} already gets. On Android "face" means face hardware plus some
     * enrolled biometric, so a known enrolled fingerprint is preferred to it.</p>
     *
     * <p>The words are searched for, as the older methods do, so a new token must contain none
     * of the existing ones.</p>
     *
     * @param available Whether biometric authentication can be used at all.
     * @param types The space separated type list, may be null.
     * @return The single answer, never null.
     */
    static BiometricPromptType fromTypes(boolean available, String types) {
        if (!available) {
            return NONE;
        }
        if (types == null) {
            return BIOMETRICS;
        }
        if (types.indexOf(UNDETERMINED) != -1) {
            return BIOMETRICS;
        }
        if (types.indexOf("touch") != -1) {
            return FINGERPRINT;
        }
        if (types.indexOf("face") != -1 && types.indexOf("iris") == -1) {
            return FACE;
        }
        return BIOMETRICS;
    }
}
