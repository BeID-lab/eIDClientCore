/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

/**
 * This class defines status and error codes. To see all error codes please take
 * a look at the corresponding C header files.
 */
public class EIdStatus {

    private EIdStatus() {
    };

    /**
     * initialization state
     */
    public final static long STATE_INITIALIZE = 1;
    /**
     * got PACE information
     */
    public final static long STATE_GOT_PACE_INFO = 2;
    /**
     * PACE performed
     */
    public final static long STATE_PACE_PERFORMED = 3;
    /**
     * Terminal Authentication (TA) performed.
     */
    public final static long STATE_TA_PERFORMED = 4;
    /**
     * Chip Authentication (CA) performed.
     */
    public final static long STATE_CA_PERFORMED = 5;
    /**
     * Attributes read.
     */
    public final static long STATE_READ_ATTRIBUTES = 6;

    /**
     * success
     */
    public final static long ERROR_SUCCESS = 0;
}
