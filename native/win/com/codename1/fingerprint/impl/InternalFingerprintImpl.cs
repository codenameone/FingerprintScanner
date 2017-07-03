namespace com.codename1.fingerprint.impl{


public class InternalFingerprintImpl : IInternalFingerprintImpl {
    public bool isAvailable() {
        return false;
    }

    public void scan(string reason) {
    }

    public bool isSupported() {
        return false;
    }

}
}
