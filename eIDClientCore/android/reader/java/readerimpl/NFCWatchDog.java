package de.bdr.readerimpl;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningAppProcessInfo;
import android.content.Context;
import android.os.AsyncTask;
import android.os.Debug.MemoryInfo;
import de.bdr.eidclient.Logging;

public final class NFCWatchDog {

	private static final String NFC_PROCESS = "com.android.nfc";

	private static final String TAG = NFCWatchDog.class.getSimpleName();

	public static final int DEFAULT_INTERVALL = 5000;

	private static WatchDogTask watchDogTask = null;

	public static void startWatchDog(Context context, Listener listener,
			int intervall) {
		stopWatchDog();

		if (intervall <= 0) {
			throw new IllegalArgumentException("intervall must be positive");
		}

		watchDogTask = new WatchDogTask(context, intervall);
		watchDogTask
				.executeOnExecutor(AsyncTask.THREAD_POOL_EXECUTOR, listener);
	}

	public static void stopWatchDog() {
		if (watchDogTask != null) {
			watchDogTask.stopRequest = true;
		}
	}

	private NFCWatchDog() {

	}

	private static class WatchDogTask extends
			AsyncTask<Listener, Boolean, Boolean> {

		private int[] pid = new int[] { 0 };
		private ActivityManager manager;
		private final Context context;
		private final int intervall;
		volatile boolean stopRequest;

		public WatchDogTask(Context context, int intervall) {
			this.context = context;
			this.intervall = intervall;
		}

		@Override
		protected Boolean doInBackground(Listener... listener) {
			Logging.d(TAG, "started");
			if (!setPid()) {
				Logging.d(TAG, "no nfc service process found");
				return false;
			}
			while (!stopRequest) {
				if (processIsAlive()) {
					Logging.d(TAG, "nfc service still alive");

				} else {
					Logging.d(TAG, "nfc service dead");
					if (listener.length > 0 & listener[0] != null) {
						listener[0].onNFCServiceDied();
					}
				}
				try {
					Thread.sleep(intervall);
				} catch (InterruptedException e) {
					Logging.e(TAG, "Thread interrupted", e);
				}
			}
			return true;
		}

		@Override
		protected void onPostExecute(Boolean result) {
			Logging.d(TAG, "Thread terminated with result: " + result);
		}

		private boolean processIsAlive() {
			MemoryInfo[] memInfo = manager.getProcessMemoryInfo(pid);
			if (memInfo[0].getTotalSharedDirty() == 0) {
				return false;
			}
			return true;
		}

		boolean setPid() {
			manager = (ActivityManager) context
					.getSystemService(Context.ACTIVITY_SERVICE);
			for (RunningAppProcessInfo process : manager
					.getRunningAppProcesses()) {
				if (NFC_PROCESS.equals(process.processName)) {
					pid[0] = process.pid;
					return true;
				}
			}
			return false;
		}

	}

	public interface Listener {

		public void onNFCServiceDied();

	}

}
