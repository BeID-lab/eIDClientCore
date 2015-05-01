package de.bdr.eidcc.eidccausweisapp2;

import java.io.IOException;

import android.nfc.Tag;
import android.nfc.tech.IsoDep;
import de.bdr.reader.Reader;

public class NPAReader implements Reader{
	private IsoDep card;
	
	public NPAReader(Tag tag){
		this.card = IsoDep.get(tag);
        card.setTimeout(20000);
        try {
			card.connect();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
     * Sends the command APDU to the ICC and returns the response APDU.
     * 
     * @param cAPDU
     *            command APDU
     * @return response APDU or null in the case of an error
     */
	public byte[] processAPDU(byte[] cAPDU){
		try{
			return card.transceive(cAPDU);
		} catch (IOException e) {
			return null;
		}
	}

    /**
     * Turns the reader on
     * 
     * @return true, or false in the case of an error
     */
    public boolean powerOn(){
    	return true;
    }

    /**
     * Turns the reader off
     */
    public void powerOff(){
    	return;
    }

    /**
     * Returns the answer-to-reset
     * 
     * @return ATR or null in the case of an error
     */
    /* Code taken from remote Smart Card Reader, see
     * http://frankmorgner.github.io/vsmartcard/remote-reader/README.html
     */
    public byte[] getATR(){
    	/* calculation based on https://code.google.com/p/ifdnfc/source/browse/src/atr.c */
    	byte[] historicalBytes = card.getHistoricalBytes();
		if (historicalBytes == null) {
			historicalBytes = new byte[0];
		}

		/* copy historical bytes if available */
		byte[] atr = new byte[4 + historicalBytes.length + 1];
		atr[0] = (byte) 0x3b;
		atr[1] = (byte) (0x80 + historicalBytes.length);
		atr[2] = (byte) 0x80;
		atr[3] = (byte) 0x01;
		System.arraycopy(historicalBytes, 0, atr, 4, historicalBytes.length);

		/* calculate TCK */
		byte tck = atr[1];
		for (int idx = 2; idx < atr.length; idx++) {
			tck ^= atr[idx];
		}
		atr[atr.length - 1] = tck;

		return atr;
    }

    /**
     * Indicates whether the reader supports PACE or not.
     * 
     * If the reader supports PACE, the eidClientCore sends the CT-API commands
     * to perform PACE.
     * 
     * @return true, if reader supports PACE.
     */
    public boolean supportsPACE(){
    	return false;
    }
}
