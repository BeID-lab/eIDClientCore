/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.reader;

/**
 * Reader interface
 */
public interface Reader {

    /**
     * Sends the command APDU to the ICC and returns the response APDU.
     * 
     * @param cAPDU
     *            command APDU
     * @return response APDU or null in the case of an error
     */
    public byte[] processAPDU(byte[] cAPDU);

    /**
     * Turns the reader on
     * 
     * @return true, or false in the case of an error
     */
    public boolean powerOn();

    /**
     * Turns the reader off
     */
    public void powerOff();

    /**
     * Returns the answer-to-reset
     * 
     * @return ATR or null in the case of an error
     */
    public byte[] getATR();
}
