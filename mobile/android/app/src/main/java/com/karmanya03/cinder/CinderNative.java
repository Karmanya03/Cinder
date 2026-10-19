package com.karmanya03.cinder;

/** JNI boundary; the Rust library owns all archive parsing and safety rules. */
final class CinderNative {
    static {
        System.loadLibrary("cinder_mobile");
    }

    private CinderNative() {}

    static native int compressFd(int inputFd, int outputFd);
}
