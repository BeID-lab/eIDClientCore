/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.readerimpl;

import java.io.IOException;

import android.nfc.tech.IsoDep;
import de.bdr.eidclient.Logging;
import de.bdr.reader.Reader;

public class NFCReader implements Reader {

	private IsoDep icc;
	private static final String TAG = NFCReader.class.getSimpleName();

	public NFCReader(IsoDep icc) {
		this.icc = icc;

		Logging.d(
				TAG,
				"NFC Reader constructed - supported length: "
						+ icc.getMaxTransceiveLength());
	}

	@Override
	public byte[] processAPDU(byte[] cAPDU) {
		Logging.d(
				TAG,
				"Process APDU (length: " + cAPDU.length + "):"
						+ Util.bytesToHex(cAPDU));

		if (cAPDU[0] == 0x01 && cAPDU[1] == (byte) 0xef) {
			byte[] res = new byte[] { 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
					(byte) 0x90, 0x00 };
			Logging.d(TAG, "Response APDU: " + Util.bytesToHex(res));
			return res;
		}
		try {
			byte[] res = icc.transceive(cAPDU);
			Logging.d(TAG, "Response APDU: " + Util.bytesToHex(res));
			return res;
		} catch (IOException e) {
			Logging.e(TAG, "Process APDU failed: " + e.getMessage(), e);
			return new byte[] { (byte) 0x6F, 0x00 };
		}
	}

	@Override
	public boolean powerOn() {
		Logging.d(TAG, "Power On");

		try {
			icc.connect();
			icc.setTimeout(10500);
		} catch (IOException e) {
			Logging.e(TAG, "unable to connect NFC", e);
			return false;
		}
		return true;
	}

	@Override
	public void powerOff() {
		Logging.d(TAG, "Power Off");
	}

	@Override
	public byte[] getATR() {
		Logging.d(TAG, "Reader get ATR");
		// byte[] atr = icc.getHistoricalBytes();
		byte[] atr = new byte[] { 0 };
		Logging.d(TAG, "ATR: " + Util.bytesToHex(atr));
		return atr;
	}
}
