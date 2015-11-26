/*
 * Copyright (C) 2013 Bundesdruckerei GmbH
 */

package de.bdr.readerimpl;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import de.bdr.eidclient.Logging;
import de.bdr.reader.Reader;

public class NFCReader implements Reader {
	private static final String TAG = NFCReader.class.getSimpleName();
	public static final String NFC_A_STRING = "android.nfc.tech.NfcA";
	public static final String NFC_B_STRING = "android.nfc.tech.NfcB";
	public static final byte NFC_A = 1;
	public static final byte NFC_B = 2;

	private IsoDep icc;
	private byte tech = 0;

	public NFCReader(IsoDep icc) {
		this.icc = icc;

		Tag tag = icc.getTag();

		if (tag != null) {
			List<String> techList = Arrays.asList(tag.getTechList());
			if (techList.contains(NFC_A_STRING)) {
				tech = NFC_A;
			} else if (techList.contains(NFC_B_STRING)) {
				tech = NFC_B;
			}
		}

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
		byte[] atr;
		if (NFC_A == tech) {
			atr = icc.getHistoricalBytes();
		} else if (NFC_B == tech) {
			atr = icc.getHiLayerResponse();
		} else {
			atr = new byte[] { 0 };
		}
		Logging.d(TAG, "ATR: " + Util.bytesToHex(atr));
		return atr;
	}
}
