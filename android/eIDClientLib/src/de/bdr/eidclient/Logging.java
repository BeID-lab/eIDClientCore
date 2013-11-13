/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

import android.util.Log;

/**
 * Simple logging class.
 */
public class Logging {

    /**
     * Error logging level
     */
    public static final byte ERR = 0;
    /**
     * Debug logging level
     */
    public static final byte DEB = 1;
    /**
     * Info logging level
     */
    public static final byte INFO = 2;

    /**
     * turn logging on/off
     */
    public static boolean doLog = true;
    /**
     * max logging level
     */
    public static byte logLevel = 2;

    private Logging() {
        // only static
    }

    /**
     * log a error message.
     * 
     * @param tag
     *            tag
     * @param msg
     *            log message
     * @param e
     *            exception
     */
    public static void e(String tag, String msg, Exception e) {
        log(ERR, tag, msg, e);
    }

    /**
     * log a debug message
     * 
     * @param tag
     *            tag
     * @param msg
     *            log message
     */
    public static void d(String tag, String msg) {
        log(DEB, tag, msg, null);
    }

    /**
     * log a info message
     * 
     * @param tag
     *            tag
     * @param msg
     *            log message
     */
    public static void i(String tag, String msg) {
        log(INFO, tag, msg, null);
    }

    private static void log(final byte level, String tag, String msg,
            Exception e) {
        if (!doLog)
            return;

        switch (level) {
        case ERR:
            if (logLevel >= ERR)
                Log.e(tag, msg);
            break;
        case DEB:
            if (logLevel >= DEB)
                Log.d(tag, msg);
            break;
        case INFO:
            if (logLevel >= INFO)
                Log.d(tag, msg);
            break;
        }

        if (e != null)
            e.printStackTrace();
    }
}
