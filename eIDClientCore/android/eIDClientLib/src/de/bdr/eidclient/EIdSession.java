/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

import de.bdr.reader.Reader;

final class EIdSession {

    private Reader mReader;

    private EacCallback mCallback;

    private String mEACServerAddress;
    private String mEACSessionID;
    private String mEACPathSecurityParams;
    private String mEIDRefreshURL;

    // load native libraries
    static {
        System.loadLibrary("stlport_shared");
        System.loadLibrary("eidclient-wrapper");
        System.loadLibrary("externalReader");
    }

    // pipe eid client core native stdout to android log
    public native void pipeStdOut();

    private native long performEAC(Reader reader, String url, String sessionid,
            String pathsecurityparams);

    EIdSession(Reader reader, EacCallback callback, String serverAddress,
            String refreshURL, String sessionID, String pathSecurityParams) {

        // check mandatory parameters
        if (reader == null || serverAddress == null || sessionID == null
                || pathSecurityParams == null)
            throw new NullPointerException();

        mReader = reader;
        mCallback = callback;
        mEACSessionID = sessionID;
        mEACServerAddress = serverAddress;
        mEACPathSecurityParams = pathSecurityParams;
        mEIDRefreshURL = refreshURL;
    }

    long perform() {

        // activate native logging if Logging.doLog is true
        if (Logging.doLog) {
            new Thread(new Runnable() {

                @Override
                public void run() {
                    pipeStdOut();
                }
            }).start();
        }

        return performEAC(mReader, mEACServerAddress, mEACSessionID,
                mEACPathSecurityParams);
    }

    private void updateStatus(final int status, final int error) {
        Logging.d("EIDSession", status + ", " + error);

        if (mCallback != null)
            mCallback.onStatusChange(status, error);
    }

    private boolean userInteractionCallback(SPDescription spDescription,
            UserInput userInput) {
        Logging.d("EIDSession CALL", spDescription.toString());

        if (mCallback != null)
            return mCallback.userInteractionCallback(spDescription, userInput);

        return true;
    }
}
