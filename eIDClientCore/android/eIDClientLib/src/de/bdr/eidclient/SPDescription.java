/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

import java.util.Date;

/**
 * Service Provider Description
 */
public class SPDescription {
    /**
     * undefined description type
     */
    public static final byte DESCRIPTION_TYPE_UNDEF = 0;
    /**
     * plain description type
     */
    public static final byte DESCRIPTION_TYPE_PLAIN = 1;
    /**
     * HTML description type
     */
    public static final byte DESCRIPTION_TYPE_HTML = 2;
    /**
     * PDF description type
     */
    public static final byte DESCRIPTION_TYPE_PDF = 3;

    /**
     * encoding type of the description
     */
    public final byte descriptionType;
    /**
     * Name of the service provider
     */
    public final String name;
    /**
     * Description of the service provider
     */
    public final String description;
    /**
     * URL of the service provider
     */
    public final String url;
    /**
     * SP's Certificate begin of validation
     */
    public final long validFrom;
    /**
     * SP's Certificate end of validation
     */
    public final long validTo;
    /**
     * required Chat
     */
    public final Chat chatRequired;
    /**
     * optional Chat
     */
    public final Chat chatOptional;

    SPDescription(byte descriptionType, String name, String description,
            String url, long valid_from, long valid_to, Chat chatRequired,
            Chat chatOptional) {
        this.descriptionType = descriptionType;
        this.name = name;
        this.description = description;
        this.url = url;
        this.validFrom = valid_from;
        this.validTo = valid_to;
        this.chatRequired = chatRequired;
        this.chatOptional = chatOptional;
    }

    @Override
    public String toString() {
        return "SPDescription [descriptionType=" + descriptionType + ", name="
                + name + ", description=" + description + ", url=" + url
                + ", validFrom=" + new Date(validFrom * 1000).toString()
                + ", validTo=" + new Date(validTo * 1000).toString()
                + ", chatRequired=" + chatRequired + ", chatOptional="
                + chatOptional + "]";
    }

}
