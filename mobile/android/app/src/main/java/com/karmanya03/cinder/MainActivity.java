package com.karmanya03.cinder;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;
import java.io.FileDescriptor;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Touch-first SAF shell: no raw filesystem permissions or path assumptions. */
public final class MainActivity extends Activity {
    private static final int REQUEST_INPUT = 41;
    private static final int REQUEST_OUTPUT = 42;
    private final ExecutorService jobs = Executors.newSingleThreadExecutor();
    private Uri inputUri;
    private TextView status;

    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(32, 48, 32, 32);
        TextView title = new TextView(this);
        title.setText("Cinder\nLossless snapshots, made mobile.");
        title.setTextSize(24);
        root.addView(title);
        Button open = new Button(this);
        open.setText("Choose source");
        open.setOnClickListener(v -> chooseInput());
        root.addView(open);
        Button save = new Button(this);
        save.setText("Compress to…");
        save.setOnClickListener(v -> chooseOutput());
        root.addView(save);
        status = new TextView(this);
        status.setGravity(Gravity.CENTER_VERTICAL);
        status.setText("Tip: Cinder uses the Android document provider; no storage permission is needed.");
        root.addView(status);
        setContentView(root);
        if (getIntent().getAction() != null && Intent.ACTION_SEND.equals(getIntent().getAction())) {
            inputUri = getIntent().getParcelableExtra(Intent.EXTRA_STREAM);
            status.setText("Shared source received. Choose an output archive.");
        }
    }

    private void chooseInput() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, REQUEST_INPUT);
    }

    private void chooseOutput() {
        if (inputUri == null) {
            status.setText("Choose a source first.");
            return;
        }
        Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("application/octet-stream");
        intent.putExtra(Intent.EXTRA_TITLE, "snapshot.cnd");
        intent.addFlags(Intent.FLAG_GRANT_WRITE_URI_PERMISSION | Intent.FLAG_GRANT_PERSISTABLE_URI_PERMISSION);
        startActivityForResult(intent, REQUEST_OUTPUT);
    }

    @Override protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result != RESULT_OK || data == null || data.getData() == null) return;
        Uri uri = data.getData();
        try { getContentResolver().takePersistableUriPermission(uri, data.getFlags() &
                (Intent.FLAG_GRANT_READ_URI_PERMISSION | Intent.FLAG_GRANT_WRITE_URI_PERMISSION)); }
        catch (SecurityException ignored) { /* provider may not offer persistable grants */ }
        if (request == REQUEST_INPUT) {
            inputUri = uri;
            status.setText("Source selected. Choose an output archive.");
        } else if (request == REQUEST_OUTPUT) {
            compress(inputUri, uri);
        }
    }

    private void compress(Uri input, Uri output) {
        status.setText("Compressing securely in the background…");
        jobs.submit(() -> {
            int resultCode;
            try (android.os.ParcelFileDescriptor in = getContentResolver().openFileDescriptor(input, "r");
                 android.os.ParcelFileDescriptor out = getContentResolver().openFileDescriptor(output, "w")) {
                if (in == null || out == null) throw new IllegalStateException("provider did not open the document");
                resultCode = CinderNative.compressFd(in.getFd(), out.getFd());
            } catch (Throwable error) {
                resultCode = -1;
            }
            final int code = resultCode;
            runOnUiThread(() -> status.setText(code == 0 ? "Archive created successfully." :
                    "Compression failed. The source was not modified."));
        });
    }

    @Override protected void onDestroy() {
        jobs.shutdownNow();
        super.onDestroy();
    }
}
