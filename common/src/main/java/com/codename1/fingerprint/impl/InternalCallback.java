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

import com.codename1.components.SpanLabel;
import com.codename1.fingerprint.Fingerprint;
import com.codename1.fingerprint.KeyRevokedException;
import com.codename1.ui.Dialog;
import com.codename1.ui.Display;
import com.codename1.ui.FontImage;
import com.codename1.ui.Label;
import com.codename1.ui.layouts.BorderLayout;
import com.codename1.ui.layouts.BoxLayout;
import com.codename1.util.AsyncResource;
import com.codename1.util.FailureCallback;
import com.codename1.util.SuccessCallback;
import java.util.HashMap;
import java.util.Map;

/**
 *
 * @deprecated This is an internal implementation detail of the fingerprint
 * scanner
 */
public class InternalCallback {

    private static Map<Integer,AsyncResource<?>> requests = new HashMap<>();
    private static SuccessCallback<Object> onSuccess;
    private static FailureCallback<Object> onFail;
    private static Dialog d;

    public static void init(String reason, SuccessCallback<Object> o1, FailureCallback<Object> o2, boolean showDialogOnAndroid) {
        onSuccess = o1;
        onFail = o2;

        // Android doesn't include a UI for fingerprints
        if (Display.getInstance().getPlatformName().equals("and") && showDialogOnAndroid) {
            if (reason == null) {
                reason = "Authenticate for server login";
            }
            d = new Dialog(new BorderLayout());
            Label icon = new Label("", "DialogBody");
            icon.getUnselectedStyle().setFgColor(0xff5722); //Sets icon color to orange
            SpanLabel lblReason = new SpanLabel(reason, "DialogBody");
            FontImage.setMaterialIcon(icon, FontImage.MATERIAL_FINGERPRINT, 7);
            d.add(BorderLayout.CENTER, BoxLayout.encloseY(icon, lblReason));
            d.showPacked(BorderLayout.CENTER, false);
            d.setDisposeWhenPointerOutOfBounds(true);
        }
    }

    public static void scanSuccess(String publicKey, String privateKey) {
        if (onSuccess != null) {
            Display.getInstance().callSerially(() -> {
                if (d != null) {
                    d.dispose();
                }
                
                onSuccess.onSucess(null);
            });
        }
    }
    
    public static void scanSuccess() {
        if (onSuccess != null) {
            Display.getInstance().callSerially(() -> {
                if (d != null) {
                    d.dispose();
                }
                onSuccess.onSucess(null);
            });
        }
    }

    public static void scanFail() {
        if (onFail != null) {
            Display.getInstance().callSerially(() -> {
                if (d != null) {
                    d.dispose();
                }
                onFail.onError(null, null, 0, null);
            });
        }
    }
    
    public static int addRequest(AsyncResource<?> request) {
        synchronized(requests) {
            int index = requests.size();
            while (requests.containsKey(index)) {
                index++;
            }
            requests.put(index, request);
            return index;
        }
    }
    
    public static void requestSuccess(int requestId, String value) {
        AsyncResource<String> req = (AsyncResource<String>)requests.get(requestId);
        if (req == null) {
            return;
        }
        requests.remove(requestId);
        if (!req.isDone()) {
            req.complete(value);
        }
    }
    
    public static void requestError(int requestId, String message) {
        AsyncResource<?> req = requests.get(requestId);
        if (req == null) {
            return;
        }
        requests.remove(requestId);
        if (!req.isDone()) {
            if ("__CANCELLED__".equals(message)) {
                req.cancel(true);
            } else {
                req.error(new RuntimeException(message));
            }
        }
    }
    
    public static void requestKeyRevokedError(int requestId, String message) {
        AsyncResource<?> req = requests.get(requestId);
        if (req == null) {
            return;
        }
        requests.remove(requestId);
        if (!req.isDone()) {
            if ("__CANCELLED__".equals(message)) {
                req.cancel(true);
            } else {
                req.error(new KeyRevokedException(message));
            }
        } 
    }
    
    public static void requestComplete(int requestId, boolean success) {
        AsyncResource<Boolean> req = (AsyncResource<Boolean>)requests.get(requestId);
        if (req == null) {
            return;
        }
        requests.remove(requestId);
        if (!req.isDone()) {
            req.complete(success);
        }
    }
}
