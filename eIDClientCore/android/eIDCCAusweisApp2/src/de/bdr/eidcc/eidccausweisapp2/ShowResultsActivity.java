package de.bdr.eidcc.eidccausweisapp2;

import android.app.Activity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.widget.TableLayout;

public class ShowResultsActivity extends Activity {

	public final static String EXTRA_STRING_ARRAY = "de.bdr.eidcc.eidccausweisapp2.EXTRA_STRING_ARRAY";
	
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

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.show_results, menu);
		return true;
	}

	@Override
	public boolean onOptionsItemSelected(MenuItem item) {
		// Handle action bar item clicks here. The action bar will
		// automatically handle clicks on the Home/Up button, so long
		// as you specify a parent activity in AndroidManifest.xml.
		int id = item.getItemId();
		if (id == R.id.action_settings) {
			return true;
		}
		return super.onOptionsItemSelected(item);
	}
	
	public void exit(View view) {
		finish();
	}
}
