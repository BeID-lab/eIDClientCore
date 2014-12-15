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

To use the app, you need to build eIDCC for Android (see the tutorial on https://github.com/BeID-lab/eIDClientCore ) and copy the generated shared object files to the libs/armeabi folder.

Afterwards, you can import the project to eclipse and build the app.

# TODO

* Add Makefile for building eIDCC for Android and the Android app afterwards
* Make it possible to enable / disable parts of the CHAT