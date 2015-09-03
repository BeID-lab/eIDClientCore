package de.bdr.eidcc.eidccausweisapp2;

public interface eIDCCTestcase {
	/**
	 * Returns a TcToken, if everything went correct. error contains the empty string then.
	 * Returns null and error message, which will be shown in the app, if something
	 * went wrong. Append error message to error.
	 */
	public TcToken getTcToken(StringBuilder error);
	
	/**
	 * Returns a result page, if everything went correct. error contains the empty string then.
	 * Returns null and error message, which will be shown in the app, if something
	 * went wrong. Append error message to error.
	 */
	public String getResultPage(StringBuilder error);
	
	/**
	 * Gets a webpage as input and provides a string to show to the user in the UI.
	 */
	public String[] parseResult(String result);
}
