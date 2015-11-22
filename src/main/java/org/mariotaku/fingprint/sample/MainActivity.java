package org.mariotaku.fingprint.sample;

import android.Manifest;
import android.app.Activity;
import android.content.pm.PackageManager;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Bundle;
import android.os.Handler;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.text.method.ScrollingMovementMethod;
import android.util.Base64;
import android.view.View;
import android.widget.TextView;
import android.widget.Toast;

import java.io.IOException;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends Activity {

    private static final String AES_KEY_NAME = "foobar";
    private static final int REQUEST_PERMISSION = 100;

    private View mGenKeyButton;
    private View mEncryptButton;
    private View mDecryptButton;
    private TextView mLogView;

    private KeyStore mKeyStore;
    private FingerprintManager mFingerprintManager;
    private byte[] mEncrypted, mIV;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        try {
            mKeyStore = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            showErrorAndExit("Device doesn't support AndroidKeyStore");
            return;
        }
        mFingerprintManager = getSystemService(FingerprintManager.class);
        initViews();

        // We should check permission on runtime in Marshmallow
        if (checkSelfPermission(Manifest.permission.USE_FINGERPRINT) == PackageManager.PERMISSION_GRANTED) {
            checkFingerprintAvailable();
        } else {
            final String[] permissions = {Manifest.permission.USE_FINGERPRINT};
            requestPermissions(permissions, REQUEST_PERMISSION);
        }
    }

    @Override
    public void onRequestPermissionsResult(final int requestCode, final String[] permissions, final int[] grantResults) {
        switch (requestCode) {
            case REQUEST_PERMISSION: {
                if (grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                    checkFingerprintAvailable();
                } else {
                    showErrorAndExit("Please give app fingerprint permission");
                }
                break;
            }
        }
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    }

    @Override
    public void onContentChanged() {
        super.onContentChanged();
        mGenKeyButton = findViewById(R.id.genkey);
        mEncryptButton = findViewById(R.id.encrypt);
        mDecryptButton = findViewById(R.id.decrypt);
        mLogView = (TextView) findViewById(R.id.log);
    }

    private void initViews() {
        mGenKeyButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(final View v) {
                writeLog("Generating key......");
                try {
                    generateKey();
                    writeLog("[OK]");
                } catch (Exception e) {
                    writeError(e);
                }
                mLogView.append("\n");
            }
        });
        mEncryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(final View v) {
                writeLog("Encrypting data\n");
                try {
                    if (encryptData()) {
                        writeLog("Touch sensor......");
                    } else {
                        writeLog("[FAILED] key not yet generated\n");
                    }
                } catch (Exception e) {
                    writeError(e);
                }
            }
        });
        mDecryptButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(final View v) {
                writeLog("Decrypting data\n");
                try {
                    if (mEncrypted == null || mIV == null) {
                        writeError("There's no encrypted data\n");
                    } else if (decryptData()) {
                        writeLog("Touch sensor......");
                    } else {
                        writeLog("[FAILED] key not yet generated\n");
                    }
                } catch (Exception e) {
                    writeError(e);
                }
            }
        });
        mLogView.setMovementMethod(ScrollingMovementMethod.getInstance());
    }

    private void showErrorAndExit(final String s) {
        Toast.makeText(this, s, Toast.LENGTH_LONG).show();
        finish();
    }

    private void writeError(final Exception e) {
        mLogView.append("[ERROR]\n");
        try (StringWriter sw = new StringWriter()) {
            e.printStackTrace(new PrintWriter(sw));
            mLogView.append(sw.toString());
        } catch (IOException ioe) {
            ioe.printStackTrace();
        }
    }

    private void writeError(final CharSequence s) {
        mLogView.append("[ERROR]\n");
        mLogView.append(s);
    }

    private void writeLog(final CharSequence s) {
        mLogView.append(s);
    }

    @SuppressWarnings("ResourceType")
    private void checkFingerprintAvailable() {
        if (!mFingerprintManager.isHardwareDetected()) {
            showErrorAndExit("This device doesn't support Fingerprint authentication");
        } else if (!mFingerprintManager.hasEnrolledFingerprints()) {
            showErrorAndExit("You haven't enrolled any fingerprint, go to System Settings -> Security -> Fingerprint");
        }
    }

    private void generateKey() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, IOException, CertificateException {
        // Use AES algorithm. Here we must use AndroidKeyStore for provider.
        final KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        // Reload our keystore
        mKeyStore.load(null);
        // We use this key to encrypt and decrypt data
        final int purposes = KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT;
        final KeyGenParameterSpec.Builder builder = new KeyGenParameterSpec.Builder(AES_KEY_NAME, purposes);
        // Require the user to authenticate with a fingerprint to authorize every use of the key
        builder.setUserAuthenticationRequired(true);

        builder.setBlockModes(KeyProperties.BLOCK_MODE_CBC);
        builder.setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7);
        keyGenerator.init(builder.build());
        keyGenerator.generateKey();
    }

    /**
     * @return false if key not yet generated
     */
    private boolean encryptData() throws CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException, KeyStoreException, NoSuchPaddingException, InvalidKeyException,
            SecurityException {
        mKeyStore.load(null);
        // Load key from KeyStore
        final SecretKey key = (SecretKey) mKeyStore.getKey(AES_KEY_NAME, null);
        // The key is required, notify user to regenerate one.
        if (key == null) return false;
        // When using CBC block mode, an IV is required to decrypt data. Usually IV is generated
        // along with encrypted key.
        final Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        // Use Encrypt mode.
        cipher.init(Cipher.ENCRYPT_MODE, key);
        final FingerprintManager.CryptoObject crypto = new FingerprintManager.CryptoObject(cipher);
        mFingerprintManager.authenticate(crypto, null, 0, new SimpleAuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(final FingerprintManager.AuthenticationResult result) {
                final Cipher cipher = result.getCryptoObject().getCipher();
                final Random random = new Random();
                // Here we generate a random byte array to demonstrate how encryption works.
                final byte[] data = new byte[16];
                random.nextBytes(data);
                writeLog("[OK]\n");
                writeLog("Base 64 of data to encrypt is:\n" + Base64.encodeToString(data, Base64.URL_SAFE) + "\n");
                try {
                    mEncrypted = cipher.doFinal(data);
                    // IV is required for decryption
                    mIV = cipher.getIV();
                    writeLog("Encrypted data is:\n" + Base64.encodeToString(mEncrypted, Base64.URL_SAFE) + "\n");
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    writeError(e);
                }
            }

        }, new Handler());
        return true;
    }

    private boolean decryptData() throws CertificateException, NoSuchAlgorithmException, IOException,
            UnrecoverableKeyException, KeyStoreException, NoSuchPaddingException, InvalidKeyException,
            InvalidAlgorithmParameterException, SecurityException {
        mKeyStore.load(null);
        // Load key from KeyStore
        final SecretKey key = (SecretKey) mKeyStore.getKey(AES_KEY_NAME, null);
        // The key is required, notify user to regenerate one.
        if (key == null) return false;
        // When using CBC block mode, an IV is required to decrypt data. Usually IV is generated
        // along with encrypted key.
        final Cipher cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES + "/"
                + KeyProperties.BLOCK_MODE_CBC + "/" + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        // Use Decrypt mode
        cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(mIV));
        final FingerprintManager.CryptoObject crypto = new FingerprintManager.CryptoObject(cipher);
        mFingerprintManager.authenticate(crypto, null, 0, new SimpleAuthenticationCallback() {
            @Override
            public void onAuthenticationSucceeded(final FingerprintManager.AuthenticationResult result) {
                final Cipher cipher = result.getCryptoObject().getCipher();
                writeLog("[OK]\n");
                writeLog("Base 64 of data to decrypt is:\n" + Base64.encodeToString(mEncrypted, Base64.URL_SAFE) + "\n");
                try {
                    byte[] decrypted = cipher.doFinal(mEncrypted);
                    writeLog("Decrypted data is:\n" + Base64.encodeToString(decrypted, Base64.URL_SAFE) + "\n");
                } catch (IllegalBlockSizeException | BadPaddingException e) {
                    writeError(e);
                }
            }
        }, new Handler());
        return true;
    }

    private class SimpleAuthenticationCallback extends FingerprintManager.AuthenticationCallback {


        @Override
        public void onAuthenticationError(final int errorCode, final CharSequence errString) {
            writeError(errString);
        }

        @Override
        public void onAuthenticationHelp(final int helpCode, final CharSequence helpString) {
            writeError(helpString);
        }

        @Override
        public void onAuthenticationFailed() {
            writeError("Couldn't recognize you");
        }

    }
}
