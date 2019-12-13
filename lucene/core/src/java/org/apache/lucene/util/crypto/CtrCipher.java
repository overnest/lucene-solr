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
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

public class CtrCipher {

  private final Cipher cipher;
  private final byte[] initialIv;
  private final SecretKey key;

  protected CtrCipher(SecretKey key, IvParameterSpec iv) throws IOException {
    try {
      this.cipher = Cipher.getInstance("AES/CTR/NoPadding");
    } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
      throw new IOException(e);
    }
    this.initialIv = iv.getIV();
    this.key = key;
  }

  public byte[] decrypt(byte[] bytes) throws IOException {
    return decrypt(bytes, 0);
  }

  public byte[] decrypt(ByteBuffer bb) throws IOException {
    return decrypt(bb, 0);
  }

  public byte[] decrypt(ByteBuffer bb, long offset) throws IOException {
    return decrypt(readBytes(bb), offset);
  }

  public byte[] decrypt(byte[] bytes, long offset) throws IOException {
    return encryptOrDecrypt(Cipher.DECRYPT_MODE, bytes, offset);
  }

  public byte[] encrypt(byte[] bytes) throws IOException {
    return encrypt(bytes, 0);
  }

  public byte[] encrypt(ByteBuffer bb) throws IOException {
    return encrypt(readBytes(bb), 0);
  }

  public byte[] encrypt(ByteBuffer bb, long offset) throws IOException {
    return encrypt(readBytes(bb), offset);
  }

  public byte[] encrypt(byte[] bytes, long offset) throws IOException {
    return encryptOrDecrypt(Cipher.ENCRYPT_MODE, bytes, offset);
  }

  private byte[] encryptOrDecrypt(int operationMode, byte[] bytes, long offset) throws IOException {
    try {
      // org.apache.commons.crypto.stream.CtrCryptoInputStream.java#getCounter
      long counter = offset / this.cipher.getBlockSize();
      byte[] iv = this.initialIv.clone();
      calculateIV(this.initialIv, counter, iv);

      this.cipher.init(operationMode, this.key, new IvParameterSpec(iv));

      // org.apache.commons.crypto.stream.CtrCryptoInputStream.java#getPadding
      byte padding = (byte) (offset % this.cipher.getBlockSize());
      byte[] paddedBytes = padBytes(bytes, padding);

      byte[] result = new byte[paddedBytes.length];
      int n = this.cipher.update(paddedBytes, 0, paddedBytes.length, result, 0);

      return Arrays.copyOfRange(result, padding, n);
    } catch (InvalidKeyException | InvalidAlgorithmParameterException | ShortBufferException e) {
      throw new IOException(e);
    }
  }

  private byte[] padBytes(byte[] arr, byte padding) {
    // pads form start
    if (padding == 0)
      return arr;
    byte[] padded = new byte[padding + arr.length];
    System.arraycopy(arr, 0, padded, padding, arr.length);
    return padded;
  }

  private byte[] readBytes(ByteBuffer bb) {
    byte[] bytes = new byte[bb.limit() - bb.position()];
    // bb.mark();
    bb.get(bytes);
    // bb.reset();
    return bytes;
  }

  // org.apache.commons.crypto.stream.CtrCryptoInputStream.java#calculateIV
  private void calculateIV(byte[] initIV, long counter, byte[] IV) {
    int i = IV.length; // IV length
    int j = 0; // counter bytes index
    int sum = 0;
    while (i-- > 0) {
      // (sum >>> Byte.SIZE) is the carry for addition
      sum = (initIV[i] & 0xff) + (sum >>> Byte.SIZE); // NOPMD
      if (j++ < 8) { // Big-endian, and long is 8 bytes length
        sum += (byte) counter & 0xff;
        counter >>>= 8;
      }
      IV[i] = (byte) sum;
    }
  }
}
