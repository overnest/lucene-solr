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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public final class Crypto {

  public static boolean LOG = false;

  private static SecureRandom rand = null;
  public static String AES_ALGORITHM = "AES";
  public static int AES_KEY_SIZE = 256;
  public static int AES_BLOCK_SIZE = 16;
  public static String CTR_TRANSFORM = "AES/CTR/NoPadding";
  private static Path INDICES_PATH = Paths.get("indices");

  public static volatile AtomicBoolean encryptionOn = new AtomicBoolean(true);
  public static volatile AtomicBoolean testingOn = new AtomicBoolean(false);

  public static List<SecretKey> TEST_AES_KEYS =  Arrays.asList(
      new SecretKeySpec(
          Base64.getDecoder().decode("4tZ9S+gRYX2F3fm+BIWDDvkcXbkKYXBmB27hixPvSjU="), AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("7C9Q6SnqXwrfI03LPE2J0LEcnnVP/YnF8O3hGvpjs7Q="), AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("UqVyK+sHZQVGJBbTr8UDN5TF/t5f9MgqmVkSxi6uJu0="), AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("pd0fWwS7glXPpbzrPavNx7zpo25DLXa1gAbsijz2pHw="), AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("dtCrOKsvBlgAc3ZAGAxlWHlHK3dNNXjhrCtjXXJavtk="), AES_ALGORITHM)
  );
  
  public static boolean setEncryptionOn(boolean on) {
    return encryptionOn.getAndSet(on);
  }

  public static boolean isEncryptionOn() {
    return encryptionOn.get();
  }
  
  public static boolean setTestingOn(boolean on) {
    return testingOn.getAndSet(on);
  }

  public static boolean isTestingOn() {
    return testingOn.get();
  }

  public static void initialize() throws NoSuchAlgorithmException {
    Security.setProperty("crypto.policy", "unlimited");
    getSecureRandom();
  }
  
  // made public for testing purposes
  public static String getIndexUid(Path path) {
    Iterator<Path> pathIterator = path.iterator();
    while (pathIterator.hasNext()) {
      if (pathIterator.next().equals(INDICES_PATH)) {
        // next segment will contain the index UUID
        return pathIterator.next().toString();
      }
    }
    if (isTestingOn()) {
      // during testing just use the grandparent dir name
      // (so that tests that do renaming and copying would work)
      return path.getParent().getParent().getFileName().toString();      
    }
    throw new IllegalArgumentException("Invalid path for encryption " + path.toString());
  }

  public static SecretKey getAesKey(Path path) { 
    String indexUuid = getIndexUid(path);
    if (isTestingOn()) {
      // This is a mock implementation that will deterministically select a key
      // from a pregenerated set of keys
      return TEST_AES_KEYS.get(Math.abs(indexUuid.hashCode()) % TEST_AES_KEYS.size());
    }
    // TODO fetch company key from API instead
    return TEST_AES_KEYS.get(Math.abs(indexUuid.hashCode()) % TEST_AES_KEYS.size());
  }

  public static SecretKey generateAesKey() throws NoSuchAlgorithmException {
    KeyGenerator keyGen = KeyGenerator.getInstance("AES");
    keyGen.init(AES_KEY_SIZE);
    return keyGen.generateKey();
  }

  public static IvParameterSpec generateAesIV() throws NoSuchAlgorithmException {
    byte[] iv = new byte[AES_BLOCK_SIZE];
    getSecureRandom().nextBytes(iv);
    return new IvParameterSpec(iv);
  }

  private static SecureRandom getSecureRandom() throws NoSuchAlgorithmException {
    if (rand == null) {
      synchronized (Crypto.class) {
        if (rand == null) {
          rand = SecureRandom.getInstance("NativePRNG");
        }
      }
    }
    return rand;
  }

  public static Cipher getCtrEncryptCipher(SecretKey key, IvParameterSpec iv) throws IOException {
    try {
      Cipher cipher = Cipher.getInstance(CTR_TRANSFORM);
      cipher.init(Cipher.ENCRYPT_MODE, key, iv);
      return cipher;
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException
        | InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
  }

  // TODO update tests to test EncryptedFileChannel instead and remove this.
  public static CtrCipher getCtrCipher(SecretKey key, IvParameterSpec iv) throws IOException {
    return new CtrCipher(key, iv);
  }

  // ******************
  // Useful for testing
 
  private static final String HEXES = "0123456789ABCDEF";

  private static String getHex(byte[] bytes) {
    final StringBuilder hex = new StringBuilder(2 * bytes.length);
    for (final byte b : bytes) {
      hex.append(HEXES.charAt((b & 0xF0) >> 4)).append(HEXES.charAt((b & 0x0F)));
    }
    return hex.toString();
  }

  public static void log(String src, String msg) {
    if (LOG) {
      System.out.println(src + ": " + msg);
    }
  }

  public static void logWriteIv(String src, byte[] iv) {
    if (LOG) {
      System.out.println(src + " write IV: " + Base64.getEncoder().encodeToString(iv) + " [" + getHex(iv) + "]");
    }
  }

  public static void logReadIv(String src, byte[] iv) {
    if (LOG) {
      System.out.println(src + " read IV: " + Base64.getEncoder().encodeToString(iv) + " [" + getHex(iv) + "]");
    }
  }

  public static void logWrite(String src, long pos, byte[] plaintext, byte[] cipherText) {
    if (LOG) {
      System.out.println(src + " at " + pos + " write: " + new String(plaintext));
      System.out.println(" as " + "[" + getHex(cipherText) + "] " + new String(cipherText));
    }
  }

  public static void logRead(String src, long pos, byte[] cipherText, byte[] plaintext) {
    if (LOG) {
      System.out.println(src + "at " + pos + " read: " + "[" + getHex(cipherText) + "] " + new String(cipherText));
      System.out.println(" as " + new String(plaintext));
    }
  }

}
