package de.bdr.eidcc.eidclientcore_selbstauskunft;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;

import android.os.AsyncTask;

public class GetWebPage extends AsyncTask<Void, Void, String> {
	CookieContext mCookieContext;
	
	public GetWebPage(CookieContext mCookieContext){
		this.mCookieContext = mCookieContext;
	}

	protected String doInBackground(Void... voids) {
		HttpGet get = new HttpGet(mCookieContext.url);
		HttpResponse response = null;
		try {
			response = mCookieContext.httpClient.execute(get, mCookieContext.localContext);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		ByteArrayOutputStream out = new ByteArrayOutputStream();
		try {
			InputStream mInputStream = response.getEntity().getContent();
			int character;
			while ((character = mInputStream.read()) !=  -1) {
				out.write(character);
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		String result = "";
		try{
			result = out.toString("UTF-8");
		} catch (UnsupportedEncodingException e) {
			e.printStackTrace();
		}
		
		return result;
	}
}
