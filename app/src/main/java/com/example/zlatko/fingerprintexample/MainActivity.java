package com.example.zlatko.fingerprintexample;

import android.app.Activity;
import android.app.KeyguardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.UserNotAuthenticatedException;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.view.View;
import android.widget.Button;
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

  public static final int SAVE_CREDENTIALS_REQUEST_CODE = 1;
  private static final int LOGIN_WITH_CREDENTIALS_REQUEST_CODE = 2;

  public static final int AUTHENTICATION_DURATION_SECONDS = 30;

  public static final String KEY_NAME = "key";

  public static final String TRANSFORMATION = KeyProperties.KEY_ALGORITHM_AES + "/" + KeyProperties.BLOCK_MODE_CBC + "/"
          + KeyProperties.ENCRYPTION_PADDING_PKCS7;
  public static final String CHARSET_NAME = "UTF-8";
  public static final String STORAGE_FILE_NAME = "credentials";
  public static final String ANDROID_KEY_STORE = "AndroidKeyStore";
  private KeyguardManager keyguardManager;

  private EditText usernameEditText;
  private EditText passwordEditText;
  private CheckBox saveCredentials;
  private Button loginWithFingerprint;

  private View.OnClickListener loginOncLickListener = new View.OnClickListener() {
    @Override
    public void onClick(View v) {
      if (saveCredentials.isChecked()) {
        saveCredentialsAndLogin();
      } else {
        String usernameString = usernameEditText.getText().toString();
        String passwordString = passwordEditText.getText().toString();
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
      Toast.makeText(MainActivity.this, "Credentials removed", Toast.LENGTH_SHORT).show();
    }
  };


  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    setContentView(R.layout.activity_main);
    keyguardManager = (KeyguardManager) getSystemService(Context.KEYGUARD_SERVICE);

    usernameEditText = (EditText) findViewById(R.id.username);
    passwordEditText = (EditText) findViewById(R.id.password);
    saveCredentials = (CheckBox) findViewById(R.id.saveCredentials);
    loginWithFingerprint = (Button) findViewById(R.id.loginWithFingerprint);

    findViewById(R.id.login).setOnClickListener(loginOncLickListener);
    loginWithFingerprint.setOnClickListener(loginWithFingerPrintOncLickListener);
    findViewById(R.id.clearData).setOnClickListener(clearDataOncLickListener);
  }

  @Override
  protected void onResume() {
    super.onResume();
    if (!keyguardManager.isKeyguardSecure()) {
      Toast.makeText(this,
              "Secure lock screen hasn't set up. Go to 'Settings -> Security -> Screenlock' to set up a lock screen",
              Toast.LENGTH_LONG).show();
    }
    saveCredentials.setEnabled(keyguardManager.isKeyguardSecure());
    loginWithFingerprint.setEnabled(keyguardManager.isKeyguardSecure());
  }

  private void saveCredentialsAndLogin() {
    try {
      // encrypt the password
      String passwordString = passwordEditText.getText().toString();
      SecretKey secretKey = createKey();
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.ENCRYPT_MODE, secretKey);
      byte[] encryptionIv = cipher.getIV();
      byte[] passwordBytes = passwordString.getBytes(CHARSET_NAME);
      byte[] encryptedPasswordBytes = cipher.doFinal(passwordBytes);
      String encryptedPassword = Base64.encodeToString(encryptedPasswordBytes, Base64.DEFAULT);

      // store the login data in the shared preferences
      // only the password is encrypted, IV used for the encryption is stored
      String usernameString = usernameEditText.getText().toString();
      SharedPreferences.Editor editor = getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE).edit();
      editor.putString("username", usernameString);
      editor.putString("password", encryptedPassword);
      editor.putString("encryptionIv", Base64.encodeToString(encryptionIv, Base64.DEFAULT));
      editor.apply();

      simulateLogin(usernameString, passwordString);
    } catch (UserNotAuthenticatedException e) {
      showAuthenticationScreen(SAVE_CREDENTIALS_REQUEST_CODE);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException
            | BadPaddingException | UnsupportedEncodingException e) {
      throw new RuntimeException(e);
    }
  }

  public void loginWithFingerprint() {
    try {
      // load login data from shared preferences (
      // only the password is encrypted, IV used for the encryption is loaded from shared preferences
      SharedPreferences sharedPreferences = getSharedPreferences(STORAGE_FILE_NAME, Activity.MODE_PRIVATE);
      String username = sharedPreferences.getString("username", null);
      if (username == null) {
        Toast.makeText(MainActivity.this, "You must first store credentials.", Toast.LENGTH_SHORT).show();
        return;
      }
      String base64EncryptedPassword = sharedPreferences.getString("password", null);
      String base64EncryptionIv = sharedPreferences.getString("encryptionIv", null);
      byte[] encryptionIv = Base64.decode(base64EncryptionIv, Base64.DEFAULT);
      byte[] encryptedPassword = Base64.decode(base64EncryptedPassword, Base64.DEFAULT);

      // decrypt the password
      KeyStore keyStore = KeyStore.getInstance(ANDROID_KEY_STORE);
      keyStore.load(null);
      SecretKey secretKey = (SecretKey) keyStore.getKey(KEY_NAME, null);
      Cipher cipher = Cipher.getInstance(TRANSFORMATION);
      cipher.init(Cipher.DECRYPT_MODE, secretKey, new IvParameterSpec(encryptionIv));
      byte[] passwordBytes = cipher.doFinal(encryptedPassword);
      String password = new String(passwordBytes, CHARSET_NAME);

      // use the login data
      simulateLogin(username, password);
    } catch (UserNotAuthenticatedException e) {
      showAuthenticationScreen(LOGIN_WITH_CREDENTIALS_REQUEST_CODE);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | IllegalBlockSizeException | InvalidKeyException
            | BadPaddingException | InvalidAlgorithmParameterException
            | UnrecoverableKeyException | KeyStoreException | CertificateException | IOException e) {
      throw new RuntimeException(e);
    }
  }

  private void simulateLogin(String usernameString, String passwordString) {
    String message = String.format("Simulating login with username [%s] and password [%s]", usernameString, passwordString);
    Toast.makeText(this, message, Toast.LENGTH_SHORT).show();
  }

  private SecretKey createKey() {
    try {
      KeyGenerator keyGenerator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, ANDROID_KEY_STORE);
      keyGenerator.init(new KeyGenParameterSpec.Builder(KEY_NAME,
              KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
              .setBlockModes(KeyProperties.BLOCK_MODE_CBC)
              .setUserAuthenticationRequired(true)
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
      if (requestCode == SAVE_CREDENTIALS_REQUEST_CODE) {
        saveCredentialsAndLogin();
      } else if (requestCode == LOGIN_WITH_CREDENTIALS_REQUEST_CODE) {
        loginWithFingerprint();
      }
    } else {
      Toast.makeText(this, "Confirming credentials failed", Toast.LENGTH_SHORT).show();
    }
  }

}
