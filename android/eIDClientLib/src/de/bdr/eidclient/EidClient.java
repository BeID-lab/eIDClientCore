/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

/**
 * EID Client
 */
public class EidClient {

    /**
     * Perform EAC
     * 
     * Call this method NOT in the UI-Thread
     * 
     * NOTE: This method is not thread-safe (no concurrent executions allowed)
     * 
     * @param reader
     *            reader instance
     * @param callback
     *            eac callback
     * @param sessionId
     *            session id
     * @param serverAddress
     *            eid server address
     * @param pathSecurityParams
     *            path security parameters
     * @param refreshURL
     *            refresh URL
     * @return status eidclient status
     */
    public static long performEAC(final Reader reader, EacCallback callback,
            String sessionId, String serverAddress, String pathSecurityParams,
            String refreshURL) {

        EIdSession session = new EIdSession(reader, callback, serverAddress,
                refreshURL, sessionId, pathSecurityParams);
        long res = session.perform();

        return res;
    }
}
