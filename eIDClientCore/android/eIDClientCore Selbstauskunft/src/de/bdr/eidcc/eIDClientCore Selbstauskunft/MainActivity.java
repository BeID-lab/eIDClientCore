package de.bdr.eidcc.eidclientcore_selbstauskunft;

import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Locale;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.content.DialogInterface.OnShowListener;
import android.content.Intent;
import android.graphics.Typeface;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import android.os.Build;
import android.os.Bundle;
import android.os.ConditionVariable;
import android.os.Handler;
import android.os.Looper;
import android.os.Message;
import android.text.InputType;
import android.text.method.ScrollingMovementMethod;
import android.view.Menu;
import android.view.MenuItem;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.ImageView;
import android.widget.TableLayout;
import android.widget.TableRow;
import android.widget.TableRow.LayoutParams;
import android.widget.TextView;
import de.bdr.eidclient.Chat.AT;
import de.bdr.eidclient.EacCallback;
import de.bdr.eidclient.EidClient;
import de.bdr.eidclient.SPDescription;
import de.bdr.eidclient.UserInput;
import de.bdr.reader.Reader;
import android.nfc.NfcManager;

public class MainActivity extends Activity implements EacCallback,
	NfcAdapter.ReaderCallback {

	boolean tagDiscovered = false;
	Tag tag;
	long NPACLIENT_ERROR_GUI_ABORT = 0x33000007;
	AT selectedChat;
	String tapNpa = "Bitte halten Sie Ihren neuen Personalausweis an das Smartphone. Die App wird dann die eID-Funktion Ihres neuen Personalausweises nutzen, um die auf Ihrem neuen Personalausweis gespeicherten Daten anzuzeigen.\n";
	ImageView mImageView;
	//Has to be passed from doUserInteraction to showSp
	View checkBoxView;
	
	@Override
	protected void onCreate(Bundle savedInstanceState) {
		super.onCreate(savedInstanceState);
		setContentView(R.layout.activity_main);
		mImageView = (ImageView) findViewById(R.id.showProgressToUserInMainActivity);
		TextView mText = (TextView) findViewById(R.id.showOutputToUserInMainActivity);
		mText.setMovementMethod(new ScrollingMovementMethod());
		mText.setText(tapNpa);
		checkNfcEnabled();
		enableReaderMode();
	}

	@Override
	public void onPause() {
		super.onPause();
	}

	@Override
	public void onResume() {
		super.onResume();
	}
	
	private void performTestcase() {
		if (tag == null)
			return;
		NPAReader mNPAReader = new NPAReader(tag);
		
		final TextView mText = (TextView) findViewById(R.id.showOutputToUserInMainActivity);
		if (mText == null)
			return;
		setTextAsynchronously(mText, "");
		appendAsynchronously(mText, "Neuer Personalausweis wurde erkannt.\nStarte Selbstauskunft...\n");

		setImageResourceAsynchronously(mImageView, R.drawable.personalausweis_logo_0_completed);
		
		eIDCCTestcase testcase = new eIDCCTestcaseAusweisApp2();
		final StringBuilder error = new StringBuilder();

		//Get TcToken
		TcToken mTcToken = testcase.getTcToken(error);
		if (mTcToken == null) {
			showErrorMessageAsynchronously(error.toString());
			return;
		}

		//Perform EAC
		long status = EidClient.performEAC((Reader) mNPAReader, this,
				mTcToken.sessionId, mTcToken.serverAddress,
				mTcToken.pathSecurityParams, mTcToken.refreshURL);
		
		if (status != 0) {
			if (status == NPACLIENT_ERROR_GUI_ABORT)
				appendAsynchronously(mText, "Sie haben den Vorgang abgebrochen.\nUm einen neuen Vorgang zu starten, entfernen Sie bitte den neuen Personalausweis vom Smartphone und halten ihn danach wieder daran.\n");
			else
				appendAsynchronously(mText, "Fehler bei der Durchführung von EAC.\nBitte versuchen Sie es noch einmal, indem Sie den neuen Personalausweis vom Smartphone entfernen und ihn danach wieder daran halten.\n");
			return;
		}

		//Get Result Page
		final String result = testcase.getResultPage(error);
		if (result == null) {
			showErrorMessageAsynchronously(error.toString());
		} else {
			final String[] parsedResults = testcase.parseResult(result);
			//Show parsed results to User
			Intent intent = new Intent(this, ShowResultsActivity.class);
			intent.putExtra(ShowResultsActivity.EXTRA_STRING_ARRAY, parsedResults);
			startActivity(intent);
			finish();
		}
	}
	
	public static void appendAsynchronously(final TextView mText, final String toAppend){
		if (mText != null){
			mText.post(new Runnable() {
	            public void run() {
	            	mText.append(toAppend);
	            }
	        });
		}
	}
	
	public static void setTextAsynchronously(final TextView mText, final String toSet){
		if (mText != null){
			mText.post(new Runnable() {
	            public void run() {
	            	mText.setText(toSet);
	            }
	        });
		}
	}
	
	public static void setImageResourceAsynchronously(final ImageView mImageView, final int src){
		if (mImageView != null){
			mImageView.post(new Runnable() {
	            public void run() {
	            	mImageView.setImageResource(src);
	            }
	        });
		}
	}
	
	public void onStatusChange(final long status, final long error) {
		if(error == 0){
			switch((int) status){
				case 1:
					setImageResourceAsynchronously(mImageView, R.drawable.personalausweis_logo_1_completed);
					break;
				case 2:
					setImageResourceAsynchronously(mImageView, R.drawable.personalausweis_logo_2_completed);
					break;
				case 3:
					setImageResourceAsynchronously(mImageView, R.drawable.personalausweis_logo_3_completed);
					break;
				case 4:
					setImageResourceAsynchronously(mImageView, R.drawable.personalausweis_logo_4_completed);
					break;
				case 5:
					setImageResourceAsynchronously(mImageView, R.drawable.personalausweis_logo_5_completed);
					break;
				case 6:
					setImageResourceAsynchronously(mImageView, R.drawable.personalausweis_logo_6_completed);
					break;
			}
		} else {
			runOnUiThread(new Runnable(){
				public void run() {
					showEacError(status, error);
				}
			});
		}
	}
	
	//We could also parse the error and see, if the PIN really was not correct, for example.
	private void showEacError(long status, long error){
		// make a text input dialog and show it
		AlertDialog.Builder alert = new AlertDialog.Builder(this);
		alert.setTitle("Fehler");
		//See http://stackoverflow.com/questions/9763643/how-to-add-a-check-box-to-an-alert-dialog
		View errorCheckBoxView = View.inflate(this, R.layout.errors, null);
		switch((int) status){
			case 6: ((CheckBox) errorCheckBoxView.findViewById(R.id.checkboxCA)).setChecked(true);
			case 5: ((CheckBox) errorCheckBoxView.findViewById(R.id.checkboxTA)).setChecked(true);
			case 4: ((CheckBox) errorCheckBoxView.findViewById(R.id.checkboxPinCorrect)).setChecked(true);
			case 3: ((CheckBox) errorCheckBoxView.findViewById(R.id.checkboxConnectionToServiceProvider)).setChecked(true);
		}
		alert.setNeutralButton("OK", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
			}
		});
		alert.setView(errorCheckBoxView);
		alert.show();
	}
	
	private boolean askForOkResult;
	private ConditionVariable resultReady = new ConditionVariable();
	public boolean userInteractionCallback(final SPDescription spDescription,
			final UserInput userInput) {
		
		if(spDescription.chatRequired == null && userInput.chatSelected == null)
			return false;
		
		resultReady.close();
		runOnUiThread(new Runnable(){
			public void run() {
				doUserInteraction(spDescription, userInput);
			}
		});
		resultReady.block();

		return askForOkResult;
	}
	
	private String formatDate(Date mDate){
		DateFormat formatter = new SimpleDateFormat("EEE, dd. MMM yyyy", Locale.GERMANY);
		GregorianCalendar calendar = new GregorianCalendar();
		calendar.setTime(mDate);
		return formatter.format(calendar.getTime());
	}
	
	//Idea taken from http://stackoverflow.com/questions/17899328/this-handler-class-should-be-static-or-leaks-might-occur-com-test-test3-ui-main
	private static class HandlerClass extends Handler {

		public HandlerClass() {
		}

		@Override
		public void handleMessage(Message msg) {
			throw new RuntimeException();
		}

	};
	
	private void doUserInteraction(final SPDescription spDescription,
			final UserInput userInput){
		final HandlerClass handler = new HandlerClass();
		
		// make a text input dialog and show it
		AlertDialog.Builder alert = new AlertDialog.Builder(this);

		alert.setTitle("Auslesebestätigung");
		//See http://stackoverflow.com/questions/9763643/how-to-add-a-check-box-to-an-alert-dialog
		checkBoxView = View.inflate(this, R.layout.chat, null);
		
		setCheckboxes(checkBoxView, (AT) spDescription.chatRequired, (AT) spDescription.chatOptional);
		selectedChat = (AT) userInput.chatSelected;
		
		String[] nameAndValueStrings = {"Name:", spDescription.name, "Beschreibung:",
				spDescription.description, "URL:", spDescription.url, "Gültig von:",
				formatDate(new Date(spDescription.validFrom * 1000)), "Gültig bis:",
				formatDate(new Date(spDescription.validTo * 1000))};
		buildTable((TableLayout) checkBoxView.findViewById(R.id.showSpDescription), nameAndValueStrings, this);
		
		alert.setView(checkBoxView);
		
		alert.setPositiveButton("OK", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				askForOkResult = true;
				handler.sendMessage(handler.obtainMessage());
			}
		});
		alert.setNegativeButton("Abbrechen", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
				askForOkResult = false;
				handler.sendMessage(handler.obtainMessage());
			}
		});
		
		//Show and hide keyboard automatically
		AlertDialog dialog = alert.create();
		final EditText input = (EditText) checkBoxView.findViewById(R.id.pinInput);
		dialog.setOnShowListener(new OnShowListener() {
		    @Override
		    public void onShow(DialogInterface dialog) {
		        InputMethodManager imm = (InputMethodManager) getSystemService(Context.INPUT_METHOD_SERVICE);
		        imm.showSoftInput(input, InputMethodManager.SHOW_IMPLICIT);
		    }
		});
		dialog.show();
		
		// loop till a runtime exception is triggered.
		try {
			Looper.loop();
		} catch (RuntimeException e2) {
		}
		
		userInput.pin = input.getText().toString();
		
		resultReady.open();
	}
	
	public static void buildTable(TableLayout mTableLayout, String[] nameAndValueStrings, Activity mActivity) {
		if (nameAndValueStrings.length % 2 == 1)
			return;
		
		for (int i = 0; i < nameAndValueStrings.length; i++) {
			TableRow mTableRow = new TableRow(mActivity);
			mTableRow.setLayoutParams(new TableRow.LayoutParams(
					TableRow.LayoutParams.MATCH_PARENT,
					TableRow.LayoutParams.WRAP_CONTENT));

			TableRow.LayoutParams tableRowLayoutParams = new LayoutParams(LayoutParams.WRAP_CONTENT, LayoutParams.WRAP_CONTENT);
			tableRowLayoutParams.setMargins(0, 0, 10, 0);
			
			TextView nameTextView = new TextView(mActivity);
			nameTextView.setTypeface(null, Typeface.BOLD);
			nameTextView.setText(nameAndValueStrings[i++]);

			TextView valueTextView = new TextView(mActivity);
			valueTextView.setText(nameAndValueStrings[i]);

			mTableRow.addView(nameTextView, tableRowLayoutParams);
			mTableRow.addView(valueTextView);

			mTableLayout.addView(mTableRow, i / 2);
		}
	}

	private void showErrorMessageAsynchronously(final String message) {
		runOnUiThread(new Runnable(){
			public void run() {
				showErrorMessage(message);
			}
		});
	}
	
	private void showErrorMessage(final String message) {
		// make a text input dialog and show it
		AlertDialog.Builder alert = new AlertDialog.Builder(this);

		alert.setTitle("Fehler");
		alert.setMessage(message);
		alert.setNeutralButton("OK", new DialogInterface.OnClickListener() {
			public void onClick(DialogInterface dialog, int whichButton) {
			}
		});
		alert.show();
	}
	
	//See http://developer.android.com/guide/topics/ui/controls/checkbox.html
	public void onCheckboxClicked(View view) {
		// Is the view now checked?
	    boolean checked = ((CheckBox) view).isChecked();
	    
	    // Check which checkbox was clicked
	    switch(view.getId()) {
	        case R.id.checkboxReadDocumentType:
	        	selectedChat.readDG1 = checked;
	            break;
	        case R.id.checkboxReadIssuingState:
	        	selectedChat.readDG2 = checked;
	            break;
	        case R.id.checkboxReadDateOfExpiry:
	        	selectedChat.readDG3 = checked;
	            break;
	        case R.id.checkboxReadGivenNames:
	        	selectedChat.readDG4 = checked;
	            break;
	        case R.id.checkboxReadFamilyNames:
	        	selectedChat.readDG5 = checked;
	            break;
	        case R.id.checkboxReadArtisticName:
	        	selectedChat.readDG6 = checked;
	            break;
	        case R.id.checkboxReadAcademicTitle:
	        	selectedChat.readDG7 = checked;
	            break;
	        case R.id.checkboxReadDateOfBirth:
	        	selectedChat.readDG8 = checked;
	            break;
	        case R.id.checkboxReadPlaceOfBirth:
	        	selectedChat.readDG9 = checked;
	            break;
	        case R.id.checkboxReadNationality:
	        	selectedChat.readDG10 = checked;
	            break;
	        case R.id.checkboxReadSex:
	        	selectedChat.readDG11 = checked;
	            break;
	        case R.id.checkboxReadDg12:
	        	selectedChat.readDG12 = checked;
	            break;
	        case R.id.checkboxReadDg13:
	        	selectedChat.readDG13 = checked;
	            break;
	        case R.id.checkboxReadDg14:
	        	selectedChat.readDG14 = checked;
	            break;
	        case R.id.checkboxReadDg15:
	        	selectedChat.readDG15 = checked;
	            break;
	        case R.id.checkboxReadDg16:
	        	selectedChat.readDG16 = checked;
	            break;
	        case R.id.checkboxReadPlaceOfResidence:
	        	selectedChat.readDG17 = checked;
	            break;
	        case R.id.checkboxReadCommunityId:
	        	selectedChat.readDG18 = checked;
	            break;
	        case R.id.checkboxReadResidencePermit1:
	        	selectedChat.readDG19 = checked;
	            break;
	        case R.id.checkboxReadResidencePermit2:
	        	selectedChat.readDG20 = checked;
	            break;
	        case R.id.checkboxReadDg21:
	        	selectedChat.readDG21 = checked;
	            break;
	        case R.id.checkboxWritePlaceOfResidence:
	        	selectedChat.writeDG17 = checked;
	            break;
	        case R.id.checkboxWriteCommunityId:
	        	selectedChat.writeDG18 = checked;
	            break;
	        case R.id.checkboxWriteResidencePermit1:
	        	selectedChat.writeDG19 = checked;
	            break;
	        case R.id.checkboxWriteResidencePermit2:
	        	selectedChat.writeDG20 = checked;
	            break;
	        case R.id.checkboxWriteDg21:
	        	selectedChat.writeDG21 = checked;
	            break;
	    }
	}
	
	private void setCheckbox(CheckBox cb, boolean chatRequired, boolean chatOptional){
		if(chatRequired){
			cb.setChecked(true);
			cb.setEnabled(false);
		}
		if(!chatOptional) cb.setEnabled(false);
	}
	
	private void setCheckboxes(View checkBoxView, AT chatRequired, AT chatOptional){
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxAgeVerification), 
				chatRequired.ageVerification, chatOptional == null ? false : chatOptional.ageVerification);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxCommunityIdVerification), 
				chatRequired.communityIdVerification, chatOptional == null ? false : chatOptional.communityIdVerification);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxRestrictedId), 
				chatRequired.restrictedId, chatOptional == null ? false : chatOptional.restrictedId);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxPrivileged), 
				chatRequired.privileged, chatOptional == null ? false : chatOptional.privileged);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxCanAllowed), 
				chatRequired.canAllowed, chatOptional == null ? false : chatOptional.canAllowed);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxPinManagement), 
				chatRequired.pinManagement, chatOptional == null ? false : chatOptional.pinManagement);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxInstallCertificate), 
				chatRequired.installCert, chatOptional == null ? false : chatOptional.installCert);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxInstallQualifiedCert), 
				chatRequired.installQualifiedCert, chatOptional == null ? false : chatOptional.installQualifiedCert);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDocumentType), 
				chatRequired.readDG1, chatOptional == null ? false : chatOptional.readDG1);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadIssuingState), 
				chatRequired.readDG2, chatOptional == null ? false : chatOptional.readDG2);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDateOfExpiry), 
				chatRequired.readDG3, chatOptional == null ? false : chatOptional.readDG3);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadGivenNames), 
				chatRequired.readDG4, chatOptional == null ? false : chatOptional.readDG4);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadFamilyNames), 
				chatRequired.readDG5, chatOptional == null ? false : chatOptional.readDG5);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadArtisticName), 
				chatRequired.readDG6, chatOptional == null ? false : chatOptional.readDG6);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadAcademicTitle), 
				chatRequired.readDG7, chatOptional == null ? false : chatOptional.readDG7);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDateOfBirth), 
				chatRequired.readDG8, chatOptional == null ? false : chatOptional.readDG8);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadPlaceOfBirth), 
				chatRequired.readDG9, chatOptional == null ? false : chatOptional.readDG9);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadNationality), 
				chatRequired.readDG10, chatOptional == null ? false : chatOptional.readDG10);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadSex), 
				chatRequired.readDG11, chatOptional == null ? false : chatOptional.readDG11);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDg12), 
				chatRequired.readDG12, chatOptional == null ? false : chatOptional.readDG12);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDg13), 
				chatRequired.readDG13, chatOptional == null ? false : chatOptional.readDG13);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDg14), 
				chatRequired.readDG14, chatOptional == null ? false : chatOptional.readDG14);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDg15), 
				chatRequired.readDG15, chatOptional == null ? false : chatOptional.readDG15);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDg16), 
				chatRequired.readDG16, chatOptional == null ? false : chatOptional.readDG16);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadPlaceOfResidence), 
				chatRequired.readDG17, chatOptional == null ? false : chatOptional.readDG17);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadCommunityId), 
				chatRequired.readDG18, chatOptional == null ? false : chatOptional.readDG18);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadResidencePermit1), 
				chatRequired.readDG19, chatOptional == null ? false : chatOptional.readDG19);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadResidencePermit2), 
				chatRequired.readDG20, chatOptional == null ? false : chatOptional.readDG20);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxReadDg21), 
				chatRequired.readDG21, chatOptional == null ? false : chatOptional.readDG21);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxWritePlaceOfResidence), 
				chatRequired.writeDG17, chatOptional == null ? false : chatOptional.writeDG17);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxWriteCommunityId), 
				chatRequired.writeDG18, chatOptional == null ? false : chatOptional.writeDG18);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxWriteResidencePermit1), 
				chatRequired.writeDG19, chatOptional == null ? false : chatOptional.writeDG19);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxWriteResidencePermit2), 
				chatRequired.writeDG20, chatOptional == null ? false : chatOptional.writeDG20);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxWriteDg21), 
				chatRequired.writeDG21, chatOptional == null ? false : chatOptional.writeDG21);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxRfu1), 
				chatRequired.rFU1, chatOptional == null ? false : chatOptional.rFU1);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxRfu2), 
				chatRequired.rFU2, chatOptional == null ? false : chatOptional.rFU2);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxRfu3), 
				chatRequired.rFU3, chatOptional == null ? false : chatOptional.rFU3);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxRfu4), 
				chatRequired.rFU4, chatOptional == null ? false : chatOptional.rFU4);
		setCheckbox((CheckBox) checkBoxView.findViewById(R.id.checkboxRole), 
				chatRequired.role, chatOptional == null ? false : chatOptional.role);
	}

	@Override
	public void onTagDiscovered(Tag tag) {
		System.out.println("onTagDiscovered!");
		tagDiscovered = true;
		this.tag = tag;
		new Thread(new Runnable() {
	        public void run() {
	        	performTestcase();
	        }
	    }).start();
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

	public void toggleSp(View view) {
		toggleVisibility(R.id.showSpDescription,
			R.id.buttonShowServiceProviderInformation,
			getResources().getString(R.string.button_show_service_provider_information),
			getResources().getString(R.string.button_hide_service_provider_information));
	}
	
	public void toggleChat(View view) {
		toggleVisibility(R.id.showChat,
			R.id.buttonShowChat,
			getResources().getString(R.string.button_show_chat),
			getResources().getString(R.string.button_hide_chat));
	}
	
	private void toggleVisibility(int tableLayoutId, int buttonId, String showString, String hideString) {
		TableLayout mTableLayout = (TableLayout) checkBoxView.findViewById(tableLayoutId);
		mTableLayout.setVisibility(
				(mTableLayout.getVisibility() == View.VISIBLE) 
                ? View.GONE : View.VISIBLE);
		Button mButton = (Button) checkBoxView.findViewById(buttonId);
		mButton.setText((mTableLayout.getVisibility() == View.GONE)
				? showString : hideString);
	}
	
	private boolean nfcEnabled(){
		NfcManager mNfcManager = (NfcManager) this.getSystemService(Context.NFC_SERVICE);
		NfcAdapter mNfcAdapter = mNfcManager.getDefaultAdapter();
		return (mNfcAdapter != null && mNfcAdapter.isEnabled());
	}
	
	private void checkNfcEnabled(){
		if(!nfcEnabled()){
			// make a text input dialog and show it
			AlertDialog.Builder alert = new AlertDialog.Builder(this);
			alert.setTitle("Fehler");
			alert.setMessage("NFC nicht aktiviert. Bitte aktivieren Sie NFC, bevor Sie fortfahren.");
			alert.setNeutralButton("OK", new DialogInterface.OnClickListener() {
				public void onClick(DialogInterface dialog, int whichButton) {
					checkNfcEnabled();
				}
			});
			alert.show();
		}
	}
	
	public void exit(View view) {
		finish();
	}
}
