package com.example.zlatko.fingerprintexample;

import android.annotation.TargetApi;
import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Build;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.Toast;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class MainActivity extends AppCompatActivity {

  public static final int SAVE_CREDENTAILS_REQUEST_CODE = 1;
  private static final int LOGIN_WITH_CREDENTAILS_REQUEST_CODE = 2;

  public static final int AUTHENTICATION_DURATION_SECONDS = 30;

  public static final String KEY_NAME = "key";

  public static final String TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/"
          + KeyProperties.ENCRYPTION_PADDING_PKCS7;
  public static final String CHARSET_NAME = "UTF-8";
  public static final String STORAGE_FILE_NAME = "credentials";
  public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
  private KeyguardManager keyguardManager;

  private EditText username;
  private EditText password;
  private CheckBox saveCredentials;

  private View.OnClickListener loginOncLickListener = new View.OnClickListener() {
    @Override
    public void onClick(View v) {
      if (saveCredentials.isChecked()) {
        saveCredentialsAndLogin();
      } else {
        String usernameString = username.getText().toString();
        String passwordString = password.getText().toString();
        simulateLogin(usernameString, passwordString);
      }
    }
  };

  private View.OnClickListener loginWithFingerPrintOncLickListener = new View.OnClickListener() {
    @Override
    public void onClick(View v) {
      loginWithFingerprint();
    }
  };

  private View.OnClickListener clearDataOncLickListener = new View.OnClickListener() {
    @Override
    public void onClick(View v) {
      getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE).edit().clear().apply();
    }
  };


  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);

    username = (EditText) findViewById(R.id.username);
    password = (EditText) findViewById(R.id.password);
    saveCredentials = (CheckBox) findViewById(R.id.saveCredentials);

    findViewById(R.id.login).setOnClickListener(loginOncLickListener);
    findViewById(R.id.loginWithFingerprint).setOnClickListener(loginWithFingerPrintOncLickListener);
    findViewById(R.id.clearData).setOnClickListener(clearDataOncLickListener);
  }

  private void saveCredentialsAndLogin() {
    try {
      String usernameString = username.getText().toString();
      String passwordString = password.getText().toString();
      SecretKey secretKey = createKey();
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      byte[] iv = cipher.getIV();
      String encryptedPassword = Base64.encodeToString(cipher.doFinal(passwordString.getBytes(CHARSET_NAME)), Base64.DEFAULT);

      SharedPreferences.Editor editor = getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE).edit();
      editor.putString("username", usernameString);
      editor.putString("password", encryptedPassword);
      editor.putString("encryptionIV", Base64.encodeToString(iv, Base64.DEFAULT));
      editor.apply();

      simulateLogin(usernameString, passwordString);
    } catch (UserNotAuthenticatedException e) {
      showAuthenticationScreen(SAVE_CREDENTAILS_REQUEST_CODE);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException
            | BadPaddingException | UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public void loginWithFingerprint() {
    try {
      SharedPreferences sharedPreferences = getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE);
      String username = sharedPreferences.getString("username", null);
      String base64EncryptedPassword = sharedPreferences.getString("password", null);
      String base64EncryptionIv = sharedPreferences.getString("encryptionIV", null);
      byte[] encryptionIv = Base64.decode(base64EncryptionIv, Base64.DEFAULT);
      byte[] encryptedPassword = Base64.decode(base64EncryptedPassword, Base64.DEFAULT);

      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
      keyStore.load(null);
      SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionIv));
      byte[] passwordBytes = cipher.doFinal(encryptedPassword);
      String password = new String(passwordBytes, CHARSET_NAME);

      simulateLogin(username, password);
    } catch (UserNotAuthenticatedException e) {
      showAuthenticationScreen(LOGIN_WITH_CREDENTAILS_REQUEST_CODE);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException
            | BadPaddingException | InvalidAlgorithmParameterException
            | UnrecoverableKeyException | KeyStoreException | CertificateException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  private void simulateLogin(String usernameString, String passwordString) {
    String message = String.format("Simulating login with username [%s] and password [%s]", usernameString, passwordString);
    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
  }

  private SecretKey createKey() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
      keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
              KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
              .setUserAuthenticationRequired(true)
                      // Require that the user has unlocked in the last 30 seconds
              .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_DURATION_SECONDS)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
              .build());
      return keyGenerator.generateKey();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
      throw new RuntimeException("Failed to create a symmetric key", e);
    }
  }

  private void showAuthenticationScreen(int requestCode) {
    Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
    if (intent != null) {
      startActivityForResult(intent, requestCode);
    }
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    if (resultCode == Activity.RESULT_OK) {
      if (requestCode == SAVE_CREDENTAILS_REQUEST_CODE) {
        saveCredentialsAndLogin();
      } else if (requestCode == LOGIN_WITH_CREDENTAILS_REQUEST_CODE) {
        loginWithFingerprint();
      }
    } else {
      Toast.makeText(this, "Confirming credentials failed", Toast.LENGTH_SHORT).show();
    }
  }

}
