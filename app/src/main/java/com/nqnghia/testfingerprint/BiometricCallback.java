package com.nqnghia.testfingerprint;

import android.app.Activity;
import android.hardware.biometrics.BiometricPrompt;
import android.hardware.fingerprint.FingerprintManager;
import android.os.Build;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.annotation.RequiresApi;
import androidx.core.content.ContextCompat;

@RequiresApi(api = Build.VERSION_CODES.P)
public class BiometricCallback extends BiometricPrompt.AuthenticationCallback {

    public void onAuthenticationSuccessful() {



    }

    public void onAuthenticationCancelled() {



    }

}
