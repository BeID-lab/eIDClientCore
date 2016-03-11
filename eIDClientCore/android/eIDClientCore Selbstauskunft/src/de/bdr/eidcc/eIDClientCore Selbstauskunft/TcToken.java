package de.bdr.eidcc.eidclientcore_selbstauskunft;

import java.io.IOException;
import java.io.StringReader;

import javax.xml.parsers.ParserConfigurationException;
import javax.xml.parsers.SAXParser;
import javax.xml.parsers.SAXParserFactory;

import org.xml.sax.Attributes;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;
import org.xml.sax.helpers.DefaultHandler;

public class TcToken extends DefaultHandler{
	public String sessionId;
	public String serverAddress;
	public String pathSecurityParams;
	public String refreshURL;

	private String tempVal;
	
	public TcToken(String toParse) {
		parseDocument(toParse);
		if(sessionId == null || serverAddress == null 
				|| pathSecurityParams == null || refreshURL == null)
			throw new IllegalArgumentException("Could not get everything needed from the given String.");
	}

	private void parseDocument(String xml) {
		// get a factory
		SAXParserFactory spf = SAXParserFactory.newInstance();
		try {
			// get a new instance of parser
			SAXParser sp = spf.newSAXParser();

			// parse the string and also register this class for call backs
			sp.parse(new InputSource(new StringReader(xml)), this);
		} catch (SAXException se) {
			se.printStackTrace();
		} catch (ParserConfigurationException pce) {
			pce.printStackTrace();
		} catch (IOException ie) {
			ie.printStackTrace();
		}
	}

	// Event Handlers
	public void startElement(String uri, String localName, String qName,
			Attributes attributes) throws SAXException {
		// reset
		tempVal = "";
	}
	
	public void characters(char[] ch, int start, int length) throws SAXException {
		tempVal = tempVal.concat(new String(ch,start,length));
	}
	
	public void endElement(String uri, String localName, String qName) throws SAXException {
		if(qName.equalsIgnoreCase("SessionIdentifier")) {
			sessionId = tempVal;
		}else if (qName.equalsIgnoreCase("ServerAddress")) {
			serverAddress = tempVal;
		}else if (qName.equalsIgnoreCase("PSK")) {
			pathSecurityParams = tempVal;
		}else if (qName.equalsIgnoreCase("RefreshAddress")) {
			refreshURL = tempVal;
		}
	}
}
