/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.readerimpl;

import com.reinersct.cyberjack.Data;
import com.reinersct.cyberjack.SmartCardReader;

import de.bdr.eidclient.Logging;
import de.bdr.reader.Reader;

public class CyberJackReader implements Reader {

	private static final String TAG = CyberJackReader.class.getSimpleName();

	private SmartCardReader reader;

	public CyberJackReader(SmartCardReader reader) {
		this.reader = reader;
	}

	@Override
	public byte[] processAPDU(byte[] cAPDU) {
		Logging.d(
				TAG,
				"Process APDU (length: " + cAPDU.length + "):"
						+ Util.bytesToHex(cAPDU));

		Data cmd = new Data(Data.DAD_CARD, cAPDU);

		Data rsp = null;
		try {
			rsp = reader.transmit(cmd);
		} catch (Exception e) {
			Logging.e(TAG, "reader transmit failed", e);
		}
		if (rsp == null)
			return null;
		Logging.d(TAG, "Response APDU:" + Util.bytesToHex(rsp.getMessage()));

		return rsp.getMessage();
	}

	@Override
	public boolean powerOn() {
		Logging.d(TAG, "Power On");

		try {
			return reader.connect();
		} catch (Exception e) {
			Logging.e(TAG, "Unable to connect to reader (in power on)", e);
			return false;
		}
	}

	@Override
	public void powerOff() {
		Logging.d(TAG, "Power Off");
		try {
			reader.disconnect();
		} catch (Exception e) {
			Logging.e(TAG, "Failure power off: " + e.getMessage(), e);
		}
	}

	@Override
	public byte[] getATR() {
		Logging.d(TAG, "Reader get ATR");

		try {
			String atrS = reader.cardReset();
			Logging.d(TAG, "ATR: " + atrS);
			return Util.hexToBytes(atrS);
		} catch (Exception e) {
			Logging.e(TAG, "FAILURE ATR: " + e.getMessage(), e);
			return null;
		}
	}
}
