# Welcome

This Android app allows to use the Selbstauskunft Service of Ausweisapp2 on an Android smartphone.

All relevant information about the eIDClientCore can be found at:
http://sar.informatik.hu-berlin.de/BeID-lab/eIDClientCore

Warning: This is just proof-of-concept code and should _NOT_ be used in
production environments

# Tested platforms:

* Android 4.4 Kitkat on Nexus 5

We used a modified Android to be able to send extended APDUs, see https://code.google.com/p/android/issues/detail?id=76598 . A tutorial for building Android for Nexus 5 can be found on http://nosemaj.org/howto-build-android-kitkat-nexus-5 .

# Building

We used eclipse to create this app.

To use the app, build it using the makefile in the following way:

```sh
make ANDROID_NDK_ROOT=$ANDROID_NDK_ROOT ANDROID_SDK_ROOT=$ANDROID_SDK_ROOT ANDROID_API=$ANDROID_API
```

We used android-ndk-r10b-target-32-bit as NDK, adt-bundle-linux-x86_64-20140702 as SDK and android-19 as API. The OS on which we build the app is OpenSUSE 13.1 (64 Bit).

Afterwards, you can install the app like this:

```sh
adb install -r bin/MainActivity-debug.apk
```


# TODO

* Make it possible to enable / disable parts of the CHAT