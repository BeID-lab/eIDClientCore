/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.readerimpl;

import java.math.BigInteger;

/**
 * Util class
 */
public class Util {

	private Util() {
		// only static
	}

	/**
	 * Converts a byte buffer to a hex-string
	 * 
	 * @param b
	 *            byte buffer
	 * @return hex string
	 */
	public static String bytesToHex(byte[] b) {
		String r = "";
		for (int i = 0; i < b.length; i++) {
			r += Integer.toString((b[i] & 0xff) + 0x100, 16).substring(1);
		}
		return r;
	}

	/**
	 * Converts a hex-string to a byte buffer.
	 * 
	 * @param hex
	 *            hex-string
	 * @return byte buffer
	 */
	public static byte[] hexToBytes(String hex) {
		return new BigInteger(hex.replace(" ", ""), 16).toByteArray();
	}

}
