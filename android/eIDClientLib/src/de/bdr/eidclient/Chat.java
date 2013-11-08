/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.eidclient;

/**
 * CHAT
 */
public interface Chat {

    /**
     * Authentication Terminal Type
     */
    public static final byte TERMINAL_TYPE_AT = 0;
    /**
     * Inspection System Terminal Type
     */
    public static final byte TERMINAL_TYPE_IS = 1;
    /**
     * Signature Terminal Type
     */
    public static final byte TERMINAL_TYPE_ST = 2;
    /**
     * Invalid Terminal Type
     */
    public static final byte TERMINAL_TYPE_INVALID = 3;

    /**
     * Gets CHAT Type
     * 
     * @return CHAT type
     */
    public byte getType();

    /**
     * 
     */
    public static class AT implements Chat {
        /**
         * Age Verification
         */
        public boolean ageVerification;
        /**
         * Community ID Verification
         */
        public boolean communityIdVerification;
        /**
         * Restricted ID
         */
        public boolean restrictedId;
        /**
         * privileged
         */
        public boolean privileged;
        /**
         * can allowed
         */
        public boolean canAllowed;
        /**
         * PIN Management
         */
        public boolean pinManagement;
        /**
         * install Certificate
         */
        public boolean installCert;
        /**
         * install qualified Certificate
         */
        public boolean installQualifiedCert;
        /**
         * Read DG1 (Document Type)
         */
        public boolean readDG1;
        /**
         * Read DG2 (Issuing State)
         */
        public boolean readDG2;
        /**
         * Read DG3 (Date of Expiry)
         */
        public boolean readDG3;
        /**
         * Read DG4 (Given Names)
         */
        public boolean readDG4;
        /**
         * Read DG5 (Family Names)
         */
        public boolean readDG5;
        /**
         * Read DG6 (Religous / Artistic Name)
         */
        public boolean readDG6;
        /**
         * Read DG7 (Academic Title)
         */
        public boolean readDG7;
        /**
         * Read DG8 (Date of Birth)
         */
        public boolean readDG8;
        /**
         * Read DG9 (Place of Birth)
         */
        public boolean readDG9;
        /**
         * Read DG10 (Nationality)
         */
        public boolean readDG10;
        /**
         * Read DG11 (Sex)
         */
        public boolean readDG11;
        /**
         * Read DG12 (Optional Data)
         */
        public boolean readDG12;
        /**
         * Read DG13
         */
        public boolean readDG13;
        /**
         * Read DG14
         */
        public boolean readDG14;
        /**
         * Read DG15
         */
        public boolean readDG15;
        /**
         * Read DG16
         */
        public boolean readDG16;
        /**
         * Read DG17 (Normal Place of Residence)
         */
        public boolean readDG17;
        /**
         * Read DG18 (Community ID)
         */
        public boolean readDG18;
        /**
         * Read DG19 (Residence Permit I)
         */
        public boolean readDG19;
        /**
         * Read DG20 (Residence Permit II)
         */
        public boolean readDG20;
        /**
         * Read DG21 (Optional Data)
         */
        public boolean readDG21;
        /**
         * Write DG17 (Normal Place of Residence)
         */
        public boolean writeDG17;
        /**
         * Write DG18 (Community ID)
         */
        public boolean writeDG18;
        /**
         * Write DG19 (Residence Permit I)
         */
        public boolean writeDG19;
        /**
         * Write DG20 (Residence Permit II)
         */
        public boolean writeDG20;
        /**
         * Write DG21 (Optional Data)
         */
        public boolean writeDG21;
        /**
         * RFU1
         */
        public boolean rFU1;
        /**
         * RFU2
         */
        public boolean rFU2;
        /**
         * RFU3
         */
        public boolean rFU3;
        /**
         * RFU4
         */
        public boolean rFU4;
        /**
         * Role
         */
        public boolean role;

        @Override
        public byte getType() {
            return Chat.TERMINAL_TYPE_AT;
        }

        @Override
        public String toString() {
            return "AT [ageVerification=" + ageVerification
                    + ", communityIdVerification=" + communityIdVerification
                    + ", restrictedId=" + restrictedId + ", privileged="
                    + privileged + ", canAllowed=" + canAllowed
                    + ", pinManagement=" + pinManagement + ", installCert="
                    + installCert + ", installQualifiedCert="
                    + installQualifiedCert + ", readDG1=" + readDG1
                    + ", readDG2=" + readDG2 + ", readDG3=" + readDG3
                    + ", readDG4=" + readDG4 + ", readDG5=" + readDG5
                    + ", readDG6=" + readDG6 + ", readDG7=" + readDG7
                    + ", readDG8=" + readDG8 + ", readDG9=" + readDG9
                    + ", readDG10=" + readDG10 + ", readDG11=" + readDG11
                    + ", readDG12=" + readDG12 + ", readDG13=" + readDG13
                    + ", readDG14=" + readDG14 + ", readDG15=" + readDG15
                    + ", readDG16=" + readDG16 + ", readDG17=" + readDG17
                    + ", readDG18=" + readDG18 + ", readDG19=" + readDG19
                    + ", readDG20=" + readDG20 + ", readDG21=" + readDG21
                    + ", writeDG17=" + writeDG17 + ", writeDG18=" + writeDG18
                    + ", writeDG19=" + writeDG19 + ", writeDG20=" + writeDG20
                    + ", writeDG21=" + writeDG21 + ", rFU1=" + rFU1 + ", rFU2="
                    + rFU2 + ", rFU3=" + rFU3 + ", rFU4=" + rFU4 + ", role="
                    + role + "]";
        }

    }

}
