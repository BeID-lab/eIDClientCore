package de.bdr.eidcc.eidccausweisapp2;

import java.util.ArrayList;

import android.text.Html;

public class eIDCCTestcaseAusweisApp2 implements eIDCCTestcase{
	CookieContext mCookieContext;
	String refreshURL;
	
	public eIDCCTestcaseAusweisApp2(){
		mCookieContext = new CookieContext(
				"https://www.autentapp.de/AusweisAuskunft/WebServiceRequesterServlet?mode=autentappde");
	}
	
	public TcToken getTcToken(StringBuilder error){
		GetWebPage mGetWebPage = new GetWebPage(mCookieContext);
		TcToken mTcToken = null;
		
		try {
			mTcToken = new TcToken(mGetWebPage.execute().get());
		} catch (Exception e) {
			e.printStackTrace();
			error.append("Konnte keinen TcToken erhalten. Bitte stellen Sie sicher, dass eine Internetverbindung besteht.");
			return null;
		}
		
		refreshURL = mTcToken.refreshURL;
		
		error = null;
		return mTcToken;
	}
	
	public String getResultPage(StringBuilder error){
		mCookieContext.setUrl(refreshURL);
		GetWebPage mGetWebPage = new GetWebPage(mCookieContext);
		String result = "";
		try {
			result = mGetWebPage.execute().get();
		} catch (Exception e) {
			e.printStackTrace();
			error.append("Konnte die Ergebnisseite nicht erhalten.");
			return null;
		}
		
		error = null;
		return result;
	}
	
	public static String[] parseResult(String result){		
		String beginOfValueSearchString = "<td>";
		String endOfValueSearchString = "</td>";
		String [] searchStrings = {"<td>Titel:</td>", "<td>K&#252;nstlername:</td>",
				"<td>Vorname:</td>", "<td>Nachname:</td>",
				"<td>Geburtsname:</td>", "<td>Wohnort:</td>",
				"<td>Geburtsort:</td>", "<td>Geburtsdatum:</td>",
				"<td>Dokumententyp:</td>", "<td>Ausstellender Staat:</td>",
				"<td>Staatsangeh&#246;rigkeit:</td>", "<td>Aufenthaltserlaubnis I:</td>",
				};
		
		int copyStart;
		int copyEnd;
		ArrayList<String> stringList = new ArrayList<String>();
		for(int i = 0; i < searchStrings.length; i++){
			copyStart = result.indexOf(searchStrings[i], 0);
			copyStart = result.indexOf(beginOfValueSearchString, copyStart + beginOfValueSearchString.length());
			copyStart += beginOfValueSearchString.length();
			copyEnd = result.indexOf(endOfValueSearchString, copyStart);
			stringList.add(Html.fromHtml(
						searchStrings[i].replace("<td>", "").replace("</td>", "")).toString());
			stringList.add(Html.fromHtml(result.substring(copyStart, copyEnd).toString()).toString());
		}
		
		return stringList.toArray(new String[stringList.size()]);
	}
}
