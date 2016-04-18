package de.bdr.eidcc.eidclientcore_selbstauskunft;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TableLayout;

public class ShowResultsActivity extends Activity {

	public final static String EXTRA_STRING_ARRAY = "de.bdr.eidcc.eidclientcore_selbstauskunft.EXTRA_STRING_ARRAY";
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_show_results);
		
		final String[] resultStrings = getIntent().getStringArrayExtra(EXTRA_STRING_ARRAY);
		final Activity mActivity = this;
		
		runOnUiThread(new Runnable(){
			public void run() {
				MainActivity.buildTable((TableLayout) findViewById(R.id.showOutputToUserInShowResultsActivity),
						resultStrings, mActivity);
			}
		});
	}
	
	public void exit(View view) {
		finish();
	}
}
