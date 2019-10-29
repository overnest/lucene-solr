/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.lucene.util.crypto;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Base64;
import java.util.Properties;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.crypto.stream.CtrCryptoInputStream;

public final class Crypto {


  private static SecureRandom rand = null;
  public static String AES_ALGORITHM = "AES";
  public static int AES_KEY_SIZE = 256;
  public static int AES_IV_SIZE = 16;
  public static String CTR_TRANSFORM = "AES/CTR/NoPadding";

  public static volatile AtomicBoolean encryptionOn = new AtomicBoolean(true);

  public static SecretKey TEST_AES_KEY = new SecretKeySpec(
      Base64.getDecoder().decode("4tZ9S+gRYX2F3fm+BIWDDvkcXbkKYXBmB27hixPvSjU="), AES_ALGORITHM);
  public static IvParameterSpec TEST_AES_IV = new IvParameterSpec(
      Base64.getDecoder().decode("fTJyaJjBv7cXL/oxVcLFBQ=="));

  public static boolean setEncryptionOn(boolean on) {
    return encryptionOn.getAndSet(on);
  }

  public static boolean isEncryptionOn() {
    return encryptionOn.get();
  }

  public static void Initialize() throws NoSuchAlgorithmException {
    Security.setProperty("crypto.policy", "unlimited");
    GetSecureRandom();
  }

  public static SecretKey GetAesKey() {
    if (isEncryptionOn()) {
      return TEST_AES_KEY;
    }
    return null;
  }

  public static IvParameterSpec GetAesIV() {
    if (isEncryptionOn()) {
      return TEST_AES_IV;
    }
    return null;
  }

  public static SecretKey GenerateAesKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(AES_KEY_SIZE);
    return keyGen.generateKey();
  }

  public static IvParameterSpec GenerateAesIV() throws NoSuchAlgorithmException {
    byte[] iv = new byte[AES_IV_SIZE];
    GetSecureRandom().nextBytes(iv);
    return new IvParameterSpec(iv);
  }

  public static SecureRandom GetSecureRandom() throws NoSuchAlgorithmException {
    if (rand == null) {
      synchronized(Crypto.class) {
        if (rand == null) {
          rand = SecureRandom.getInstance("NativePRNG");
        }
      }
    }
    return rand;
  }

  public static Cipher InitAesCtrCipherEncrypt(SecretKey key, IvParameterSpec iv)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
      InvalidAlgorithmParameterException {
    if (isEncryptionOn()) {
      Cipher cipher = Cipher.getInstance(CTR_TRANSFORM);
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
      return cipher;
    }
    return null;
  }

  public static byte[] EncryptAesCtr(SecretKey key, IvParameterSpec iv, byte[] plaintext)
      throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
      BadPaddingException, InvalidAlgorithmParameterException {
    if (isEncryptionOn()) {
      Cipher cipher = Cipher.getInstance(CTR_TRANSFORM);
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
      return cipher.doFinal(plaintext);
    }
    return plaintext;
  }

  public static byte[] DecryptAesCtr(SecretKey key, IvParameterSpec iv, byte[] ciphertext)
      throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException,
      NoSuchPaddingException, InvalidAlgorithmParameterException {
    if (isEncryptionOn()) {
      Cipher cipher = Cipher.getInstance(CTR_TRANSFORM);
      cipher.init(Cipher.DECRYPT_MODE, key, iv);
      return cipher.doFinal(ciphertext);
    }
    return ciphertext;
  }

  public static CtrCryptoInputStream GetCtrCryptoInputStream(InputStream stream, byte[] key, byte[] iv)
      throws GeneralSecurityException, IOException {
    Security.setProperty("crypto.policy", "unlimited");
    return new CtrCryptoInputStream(new Properties(), stream, key, iv, 0);
  }

  public static CtrCryptoInputStream GetCtrCryptoInputStream(InputStream stream, byte[] key, byte[] iv, long offset)
      throws GeneralSecurityException, IOException {
    Security.setProperty("crypto.policy", "unlimited");
    return new CtrCryptoInputStream(new Properties(), stream, key, iv, offset);
  }


}
