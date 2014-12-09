package de.bdr.eidcc.eidccausweisapp2;

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
			error.append("Could not get TcToken.");
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
			error.append("Could not get result page.");
			return null;
		}
		
		error = null;
		return result;
	}
}
