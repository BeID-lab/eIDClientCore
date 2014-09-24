/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

/**
 * User Input class includes the PIN and selected CHAT.
 */
public class UserInput {

    /**
     * undefined PIN_ID
     */
    public final static byte PIN_ID_UNDEF = 0;
    /**
     * Machine Readable Zone (MRZ) PIN_ID
     */
    public final static byte PIN_ID_MRZ = 1;
    /**
     * Card Access Number (CAN) PIN_ID;
     */
    public final static byte PIN_ID_CAN = 2;
    /**
     * PIN
     */
    public final static byte PIN_ID_PIN = 3;
    /**
     * PUK
     */
    public final static byte PIN_ID_PUK = 4;

    /**
     * indicates whether a pin is required or not.
     */
    public final boolean pinRequired;
    /**
     * pinID
     */
    public final byte pinID;
    /**
     * user-selected CHAT
     */
    public Chat chatSelected;
    /**
     * user-entered pin
     */
    public String pin;

    UserInput(boolean pinRequired, byte pinID, Chat chatSelected, String pin) {
        this.pinRequired = pinRequired;
        this.pinID = pinID;
        this.chatSelected = chatSelected;
        this.pin = pin;
    }

}
