package de.bdr.eidcc.eidccausweisapp2;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnShowListener;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.text.InputType;
import android.text.method.ScrollingMovementMethod;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.webkit.WebView;
import android.widget.EditText;
import android.widget.TextView;
import de.bdr.eidclient.EacCallback;
import de.bdr.eidclient.EidClient;
import de.bdr.eidclient.SPDescription;
import de.bdr.eidclient.UserInput;
import de.bdr.reader.Reader;

public class MainActivity extends Activity implements EacCallback,
		NfcAdapter.ReaderCallback {

	boolean tagDiscovered = false;
	Tag tag;

	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		TextView mText = (TextView) findViewById(R.id.showOutputToUser);
		mText.setMovementMethod(new ScrollingMovementMethod());
		enableReaderMode();
	}

	@Override
	public boolean onCreateOptionsMenu(Menu menu) {
		// Inflate the menu; this adds items to the action bar if it is present.
		getMenuInflater().inflate(R.menu.main, menu);
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

	@Override
	public void onPause() {
		super.onPause();
	}

	@Override
	public void onResume() {
		super.onResume();
	}

	public void performTestcase() {
		if (tag == null)
			return;
		NPAReader mNPAReader = new NPAReader(tag);
		
		TextView mText = (TextView) findViewById(R.id.showOutputToUser);
		if (mText == null)
			return;
		mText.append("Seems like there is a smartcard.\nTrying to get data from smartcard.\n");

		eIDCCTestcase testcase = new eIDCCTestcaseAusweisApp2();
		StringBuilder error = new StringBuilder();

		//Get TcToken
		TcToken mTcToken = testcase.getTcToken(error);
		if (mTcToken == null) {
			showErrorMessage(error.toString());
			return;
		}

		//Perform EAC
		long status = EidClient.performEAC((Reader) mNPAReader, this,
				mTcToken.sessionId, mTcToken.serverAddress,
				mTcToken.pathSecurityParams, mTcToken.refreshURL);
		if (status != 0) {
			mText.append("Error when trying to do EAC.\nPlease try again by removing your nPA from the smartphone and tapping the smartphone on the nPA again.\n");
			return;
		}

		//Get Result Page
		String result = testcase.getResultPage(error);
		if (result == null) {
			showErrorMessage(error.toString());
			return;
		}

		//Show Result Page to User
		WebView mWebView = new WebView(this);
		mWebView.loadData(result, "text/html", "UTF-8");
		AlertDialog.Builder alert = new AlertDialog.Builder(this);
		alert.setTitle("Results");
		alert.setView(mWebView);
		alert.setNeutralButton("OK", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
			}
		});
		alert.show();
	}

	public void onStatusChange(long status, long error) {
		String info = "Status: " + status + ". Error: " + error + ".\n";
		TextView mText = (TextView) findViewById(R.id.showOutputToUser);
		if (mText != null)
			mText.append(info);
	}

	private void showErrorMessage(String message) {
		// make a text input dialog and show it
		AlertDialog.Builder alert = new AlertDialog.Builder(this);

		alert.setTitle("Error");
		alert.setMessage(message);
		alert.setNeutralButton("OK", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
			}
		});
		alert.show();
	}

	private boolean askForOkResult;

	public boolean userInteractionCallback(SPDescription spDescription,
			UserInput userInput) {

		final Handler handler = new Handler() {
			@Override
			public void handleMessage(Message mesg) {
				throw new RuntimeException();
			}
		};

		// make a text input dialog and show it
		AlertDialog.Builder alert = new AlertDialog.Builder(this);

		alert.setTitle("Permission request");
		alert.setMessage(spDescription.toString());
		alert.setPositiveButton("Yes", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				askForOkResult = true;
				handler.sendMessage(handler.obtainMessage());
			}
		});
		alert.setNegativeButton("No", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				askForOkResult = false;
				handler.sendMessage(handler.obtainMessage());
			}
		});
		alert.show();

		// loop till a runtime exception is triggered.
		try {
			Looper.loop();
		} catch (RuntimeException e2) {
		}

		// Get PIN
		if (askForOkResult == true) {
			AlertDialog.Builder alert2 = new AlertDialog.Builder(this);
			alert2.setTitle("Please enter the PIN");
			// Set view which gets the PIN.
			final EditText input = new EditText(this);
			input.setInputType(InputType.TYPE_CLASS_NUMBER
					| InputType.TYPE_NUMBER_VARIATION_PASSWORD);
			alert2.setView(input);
			alert2.setNeutralButton("OK",
					new DialogInterface.OnClickListener() {
						public void onClick(DialogInterface dialog,
								int whichButton) {
							handler.sendMessage(handler.obtainMessage());
						}
					});
			AlertDialog dialog = alert2.create();
			//Show and hide keyboard automatically
			dialog.setOnShowListener(new OnShowListener() {
			    @Override
			    public void onShow(DialogInterface dialog) {
			        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
			        imm.showSoftInput(input, InputMethodManager.SHOW_IMPLICIT);
			    }
			});
			
			dialog.show();
			try {
				Looper.loop();
			} catch (RuntimeException e2) {
			}
			userInput.pin = input.getText().toString();
		}

		return askForOkResult;
	}

	@Override
	public void onTagDiscovered(Tag tag) {
		System.out.println("onTagDiscovered!");
		tagDiscovered = true;
		this.tag = tag;
	}

	private void enableReaderMode() {
		if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.KITKAT) {
			Bundle bundle = new Bundle();
			bundle.putInt(NfcAdapter.EXTRA_READER_PRESENCE_CHECK_DELAY, /* 2000 */
					20000);
			NfcAdapter.getDefaultAdapter(this).enableReaderMode(
					this,
					this,
					NfcAdapter.FLAG_READER_NFC_A | NfcAdapter.FLAG_READER_NFC_B
							| NfcAdapter.FLAG_READER_SKIP_NDEF_CHECK, bundle);
		}
	}

	public void exit(View view) {
		finish();
		System.exit(0);
	}

	public void startTestcase(View view) {
		if (tagDiscovered) {
			performTestcase();
			tagDiscovered = false;
		} else {
			showErrorMessage("No nPA connected.");
		}
	}
}
