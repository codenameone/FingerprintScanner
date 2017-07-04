# Fingerprint Scanner

This cn1lib provides basic support for fingerprint scanning on iOS/Android with one API. Due to the difference between the two implementations we chose a simplified approach that just verifies the fingerprint and doesn't delve into the nuanced complexities for this API.

You can see a test application [here](https://github.com/codenameone/FingerprintScannerTest). Usage of this library is as follows:

````java
Fingerprint.scanFingerprint("Use your finger print to unlock AppName.", value -> {
    Log.p("Scan successfull!");
}, (sender, err, errorCode, errorMessage) -> {
    Log.p("Scan Failed!");
});
````

Note that the values passed to value/fail are `null` and don't include any data at this time...
