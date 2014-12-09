package de.bdr.eidcc.eidccausweisapp2;

import org.apache.http.client.CookieStore;
import org.apache.http.client.protocol.ClientContext;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;

public class CookieContext {
	DefaultHttpClient httpClient;
	HttpContext localContext;
	String url;
	CookieStore cookieStore;
	
	public CookieContext(String url){
		this.httpClient = new DefaultHttpClient();
		this.localContext = new BasicHttpContext();
		this.cookieStore = new BasicCookieStore();
		this.localContext.setAttribute(ClientContext.COOKIE_STORE, this.cookieStore);
		this.url = url;
	}
	
	public void setUrl(String url){
		this.url = url;
	}
}
