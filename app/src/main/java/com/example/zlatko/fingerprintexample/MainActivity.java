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
  private KeyguardManager keyguardManager;

  private EditText username;
  private EditText password;
  private CheckBox saveCredentials;
  byte[] iv;

  private View.OnClickListener loginOncLickListener = new View.OnClickListener() {
    @Override
    public void onClick(View v) {
      login();
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
      clearData();
    }
  };


  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    keyguardManager =  (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);

    username = (EditText) findViewById(R.id.username);
    password = (EditText) findViewById(R.id.password);
    saveCredentials = (CheckBox) findViewById(R.id.saveCredentials);

    findViewById(R.id.login).setOnClickListener(loginOncLickListener);
    findViewById(R.id.loginWithFingerprint).setOnClickListener(loginWithFingerPrintOncLickListener);
    findViewById(R.id.clearData).setOnClickListener(clearDataOncLickListener);
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

  public void login() {
    if (saveCredentials.isChecked()) {
      saveCredentialsAndLogin();
    } else {
    String usernameString = username.getText().toString();
    String passwordString = password.getText().toString();
    simulateLogin(usernameString, passwordString);
    }

  }

  public void loginWithFingerprint() {
    if (keyguardManager.isKeyguardLocked()) {
      showAuthenticationScreen(LOGIN_WITH_CREDENTAILS_REQUEST_CODE);
      return;
    }

    SharedPreferences sharedPreferences = getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE);
    String usernameString = sharedPreferences.getString("username", null);
    String encryptedPasswordString = sharedPreferences.getString("password", null);
    String encryptionIV = sharedPreferences.getString("encryptionIV", null);
    String passwordString = decrypt(encryptedPasswordString, Base64.decode(encryptionIV, Base64.DEFAULT));
    simulateLogin(usernameString, passwordString);
  }

  public void clearData() {
    getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE).edit().clear().apply();
  }

  private void saveCredentialsAndLogin() {
    String usernameString = username.getText().toString();
    String passwordString = password.getText().toString();
    String encryptedPassword = encrypt(passwordString);
    if (encryptedPassword == null) {
      return;
    }
    SharedPreferences.Editor editor = getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE).edit();
    editor.putString("username", usernameString);
    editor.putString("password", encryptedPassword);
    editor.putString("encryptionIV", Base64.encodeToString(iv, Base64.DEFAULT));
    editor.apply();
    simulateLogin(usernameString, passwordString);
  }

  private String encrypt(String password) {
    String encryptedPassword = null;
    try {
      SecretKey secretKey = createKey();
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      iv = cipher.getIV();
      encryptedPassword = Base64.encodeToString(cipher.doFinal(password.getBytes(CHARSET_NAME)), Base64.DEFAULT);
    } catch (UserNotAuthenticatedException e) {
      showAuthenticationScreen(SAVE_CREDENTAILS_REQUEST_CODE);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException
            | BadPaddingException | UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
    return encryptedPassword;
  }

  private String decrypt(String encryptedPassword, byte[] encryptionIV) {
    String password = null;
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionIV));
      password = new String(cipher.doFinal(Base64.decode(encryptedPassword, Base64.DEFAULT)), CHARSET_NAME);
    } catch (UserNotAuthenticatedException e) {
      showAuthenticationScreen(LOGIN_WITH_CREDENTAILS_REQUEST_CODE);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException
            | BadPaddingException | InvalidAlgorithmParameterException
            | UnrecoverableKeyException | KeyStoreException | CertificateException | IOException e) {
      throw new RuntimeException(e);
    }
    return password;
  }

  private void simulateLogin(String usernameString, String passwordString) {
    String message = String.format("Simulating login with username [%s] and password [%s]", usernameString, passwordString);
    Toast.makeText(this, message, Toast.LENGTH_LONG).show();
  }

  @TargetApi(Build.VERSION_CODES.M)
  private SecretKey createKey() {
    // Generate a key to decrypt payment credentials, tokens, etc.
    // This will most likely be a registration step for the user when they are setting up your app.
    try {
      KeyStore keyStore = KeyStore.getInstance("AndroidKeyStore");
      keyStore.load(null);
      KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");

      // Set the alias of the entry in Android KeyStore where the key will appear
      // and the constrains (purposes) in the constructor of the Builder
      keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
              KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
              .setUserAuthenticationRequired(true)
                      // Require that the user has unlocked in the last 30 seconds
              .setUserAuthenticationValidityDurationSeconds(AUTHENTICATION_DURATION_SECONDS)
              .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_PKCS7)
              .build());
      return keyGenerator.generateKey();
    } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException | KeyStoreException
            | CertificateException | IOException e) {
      throw new RuntimeException("Failed to create a symmetric key", e);
    }
  }

  @TargetApi(Build.VERSION_CODES.LOLLIPOP)
  private void showAuthenticationScreen(int requestCode) {
    Intent intent = keyguardManager.createConfirmDeviceCredentialIntent(null, null);
    if (intent != null) {
      startActivityForResult(intent, requestCode);
    }
  }

}
