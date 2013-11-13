/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

/**
 * EAC Callback Interface which must be implemented by the application.
 */
public interface EacCallback {

    /**
     * This callback is called on protocol status changes. The protocol states
     * and error codes are defined in {@link EIdStatus}.
     * 
     * @param status
     *            protocol status (see {@link EIdStatus})
     * @param error
     *            error code (see {@link EIdStatus})
     */
    public void onStatusChange(long status, long error);

    /**
     * This method is called in the PACE protocol step. The parameters contain
     * the description of the service provider, CHAT and the PIN. If a PIN is
     * required, the application must set the PIN field in the userInput. The
     * selected chat of userInput is initialized with the service provider's
     * required chat.
     * 
     * @param spDescription
     *            description of the service provider and CHAT.
     * @param userInput
     *            description about the PIN. PIN field must be set if required
     * @return false if user aborts, else true
     */
    public boolean userInteractionCallback(SPDescription spDescription,
            UserInput userInput);

}
