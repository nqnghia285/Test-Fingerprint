package com.nqnghia.testfingerprint;

import androidx.annotation.RequiresApi;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.core.hardware.fingerprint.FingerprintManagerCompat;
import androidx.core.os.CancellationSignal;

import android.Manifest;
import android.annotation.TargetApi;
import android.app.KeyguardManager;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyPermanentlyInvalidatedException;
import android.security.keystore.KeyProperties;
import android.widget.ImageView;
import android.widget.TextView;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

public class MainActivity extends AppCompatActivity {

    private TextView mHeadingLabel;
    private TextView mParaLabel;
    private ImageView mFingerprintImage;

    private FingerprintManager fingerprintManager;
    private KeyguardManager keyguardManager;

    private KeyStore keyStore;
    private Cipher cipher;
    private String KEY_NAME = "AndroidKey";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        mHeadingLabel = findViewById(R.id.headingLabel);
        mFingerprintImage = findViewById(R.id.fingerprintImage);
        mParaLabel = findViewById(R.id.paraLabel);

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {

            fingerprintManager = (FingerprintManager) getSystemService(FINGERPRINT_SERVICE);
            keyguardManager = (KeyguardManager) getSystemService(KEYGUARD_SERVICE);

            if (!fingerprintManager.isHardwareDetected()) {

                mParaLabel.setText("Fingerprint Scanner not detected in Device.");

            } else if (ContextCompat.checkSelfPermission(this, Manifest.permission.USE_FINGERPRINT)
                    != PackageManager.PERMISSION_GRANTED) {

                mParaLabel.setText("Permission not granted to use Fingerprint Scanner.");

            } else if (!keyguardManager.isKeyguardSecure()) {

                mParaLabel.setText("Add lock to your Phone in Settings.");

            } else if (!fingerprintManager.hasEnrolledFingerprints()) {

                mParaLabel.setText("You should add atleast 1 Fingerprint to use this Feature.");

            } else {

                mParaLabel.setText("Place your Finger on Scanner to Access the App.");

                generateKey();

                if (initCipher()) {

                    FingerprintManager.CryptoObject cryptoObject = new FingerprintManager.CryptoObject(cipher);

                    FingerprintHandler fingerprintHandler = new FingerprintHandler(this);

                    fingerprintHandler.startAuth(fingerprintManager, cryptoObject);

                }

            }

        }

        /*
         * Step 1: Instantiate a FingerprintManagerCompat and call the authenticate method.
         * The authenticate method requires the:
         * 1. cryptoObject
         * 2. The second parameter is always zero.
         *    The Android documentation identifies this as set of flags and is most likely
         *    reserved for future use.
         * 3. The third parameter, cancellationSignal is an object used to turn off the
         *    fingerprint scanner and cancel the current request.
         * 4. The fourth parameteris a class that subclasses the AuthenticationCallback abstract class.
         *    This will be the same as the BiometricAuthenticationCallback
         * 5. The fifth parameter is an optional Handler instance.
         *    If a Handler object is provided, the FingerprintManager will use the Looper from that
         *    object when processing the messages from the fingerprint hardware.
         */
        FingerprintManagerCompat fingerprintManagerCompat = FingerprintManagerCompat.from(getApplicationContext());

        fingerprintManagerCompat.authenticate(cryptoObject, 0, new CancellationSignal(),
                new FingerprintManagerCompat.AuthenticationCallback() {
                    @Override
                    public void onAuthenticationError(int errMsgId, CharSequence errString) {
                        super.onAuthenticationError(errMsgId, errString);
                        updateStatus(String.valueOf(errString));
                        biometricCallback.onAuthenticationError(errMsgId, errString);
                    }

                    @Override
                    public void onAuthenticationHelp(int helpMsgId, CharSequence helpString) {
                        super.onAuthenticationHelp(helpMsgId, helpString);
                        updateStatus(String.valueOf(helpString));
                        biometricCallback.onAuthenticationHelp(helpMsgId, helpString);
                    }

                    @Override
                    public void onAuthenticationSucceeded(FingerprintManagerCompat.AuthenticationResult result) {
                        super.onAuthenticationSucceeded(result);
                        dismissDialog();
                        biometricCallback.onAuthenticationSuccessful();
                    }


                    @Override
                    public void onAuthenticationFailed() {
                        super.onAuthenticationFailed();
                        updateStatus(context.getString(R.string.biometric_failed));
                        biometricCallback.onAuthenticationFailed();
                    }
                }, null);
    }

    @TargetApi(Build.VERSION_CODES.P)
    private void displayBiometricPrompt(final BiometricCallback biometricCallback) {
        new BiometricPrompt.Builder(getApplicationContext())
                .setTitle("Login")
                .setSubtitle("Login to Demo account")
                .setDescription("Place your finger on the device home button to verify your identify")
                .setNegativeButton("CANCEL", getApplicationContext().getMainExecutor(), new DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(DialogInterface dialogInterface, int i) {
                        biometricCallback.onAuthenticationCancelled();
                    }
                })
                .build();
    }

    @TargetApi(Build.VERSION_CODES.M)
    private void generateKey() {

        try {

            keyStore = KeyStore.getInstance("AndroidKeyStore");
            KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

            keyStore.load(null);
            keyGenerator.init(new
                    KeyGenParameterSpec.Builder(KEY_NAME,
                    KeyProperties.PURPOSE_ENCRYPT |
                            KeyProperties.PURPOSE_DECRYPT)
                    .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
                    .setUserAuthenticationRequired(true)
                    .setEncryptionPaddings(
                            KeyProperties.ENCRYPTION_PADDING_PKCS7)
                    .build());
            keyGenerator.generateKey();

        } catch (KeyStoreException | IOException | CertificateException
                | NoSuchAlgorithmException | InvalidAlgorithmParameterException
                | NoSuchProviderException e) {

            e.printStackTrace();

        }

    }

    @TargetApi(Build.VERSION_CODES.M)
    public boolean initCipher() {
        try {
            cipher = Cipher.getInstance(KeyProperties.KEY_ALGORITHM_AES
                    + "/"
                    + KeyProperties.BLOCK_MODE_CBC
                    + "/"
                    + KeyProperties.ENCRYPTION_PADDING_PKCS7);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            throw new RuntimeException("Failed to get Cipher", e);
        }


        try {

            keyStore.load(null);

            SecretKey key = (SecretKey) keyStore.getKey(KEY_NAME,
                    null);

            cipher.init(Cipher.ENCRYPT_MODE, key);

            return true;

        } catch (KeyPermanentlyInvalidatedException e) {
            return false;
        } catch (KeyStoreException
                | CertificateException
                | UnrecoverableKeyException
                | IOException
                | NoSuchAlgorithmException
                | InvalidKeyException e) {
            throw new RuntimeException("Failed to init Cipher", e);
        }

    }
}
