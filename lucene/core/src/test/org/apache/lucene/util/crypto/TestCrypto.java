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

import java.nio.ByteBuffer;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.lucene.util.LuceneTestCase;

public class TestCrypto extends LuceneTestCase {

  public static final String plaintext = "Before the widespread use of message authentication codes and authenticated encryption, "
      +
      "it was common to discuss the \"error propagation\" properties as a selection criterion for " +
      "a mode of operation. It might be observed, for example, that a one-block error in the " +
      "transmitted ciphertext would result in a one-block error in the reconstructed plaintext " +
      "for ECB mode encryption, while in CBC mode such an error would affect two blocks." +
      "Some felt that such resilience was desirable in the face of random errors (e.g., line " +
      "noise), while others argued that error correcting increased the scope for attackers to " +
      "maliciously tamper with a message.\n" +
      "However, when proper integrity protection is used, such an error will result (with high " +
      "probability) in the entire message being rejected. If resistance to random error is " +
      "desirable, error-correcting codes should be applied to the ciphertext before transmission." +
      "Authenticated encryption\n" +
      "Main article: Authenticated encryption\n" +
      "A number of modes of operation have been designed to combine secrecy and authentication in " +
      "a single cryptographic primitive. Examples of such modes are XCBC,[25] IACBC, IAPM,[26] OCB, " +
      "EAX, CWC, CCM, and GCM. Authenticated encryption modes are classified as single-pass modes " +
      "or double-pass modes. Some single-pass authenticated encryption algorithms, such as OCB mode, " +
      "are encumbered by patents, while others were specifically designed and released in a way to " +
      "avoid such encumberment.\n" +
      "In addition, some modes also allow for the authentication of unencrypted associated data, " +
      "and these are called AEAD (authenticated encryption with associated data) schemes. For example, " +
      "EAX mode is a double-pass AEAD scheme while OCB mode is single-pass.";

  public void testGenerateAesKey() throws NoSuchAlgorithmException {
    SecretKey key = Crypto.GenerateAesKey();
    String base64 = Base64.getEncoder().encodeToString(key.getEncoded());
    System.out.println("AES Key: " + base64);
  }

  public void testGeneratedAesIv() throws NoSuchAlgorithmException {
    IvParameterSpec iv = Crypto.GenerateAesIV();
    String base64 = Base64.getEncoder().encodeToString(iv.getIV());
    System.out.println("AES IV: " + base64);
  }

  public void testFullDecrypt() throws Exception {  
    byte[] plainbytes = plaintext.getBytes();
    
    Crypto.Initialize();
    SecretKey key = Crypto.GenerateAesKey();
    IvParameterSpec iv = Crypto.GenerateAesIV();
    
    byte[] ciphertext = Crypto.EncryptAesCtr(key, iv, plainbytes);
    byte[] plaintext = Crypto.getCtrDecryptCipher(key, iv).decrypt(ciphertext);
    
    assertEquals(ciphertext.length, plaintext.length);
    assertEquals(ciphertext.length, plainbytes.length);
    assertArrayEquals(plainbytes, plaintext);
  }
  
  public void testPositionCryptoRead() throws Exception {
    byte[] plainbytes = plaintext.getBytes();

    Crypto.Initialize();
    SecretKey key = Crypto.GenerateAesKey();
    IvParameterSpec iv = Crypto.GenerateAesIV();
    
    byte[] ciphertext = Crypto.EncryptAesCtr(key, iv, plainbytes);
   
    final int totalLength = 100 + random().nextInt(plainbytes.length - 100);
    
    SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel(ciphertext);
    
    int chunkLength = 1 + random().nextInt(totalLength / 5);
    
    byte[] b = new byte[totalLength];
    ByteBuffer bb = ByteBuffer.wrap(b);
    
    int readLength = totalLength;
    long pos = 0;    
    channel.position(pos);

    CtrCipher cipher = Crypto.getCtrDecryptCipher(key, iv);

    try {
      while (readLength > 0) {
        bb.limit(bb.position() + Math.min(chunkLength, readLength));
        assert bb.remaining() == Math.min(chunkLength, readLength);

        bb.mark();
        final int n = channel.read(bb);
        bb.reset();
        if (n == 0) {
          break;
        }

        byte[] plaintextChunk = Arrays.copyOfRange(plainbytes, (int) pos, (int) pos + n);

        // decrypt using CtrCipher#decrypt (non-stream, bytes)
        byte[] bytes = Arrays.copyOfRange(bb.array(), (int) pos, (int) pos + n);
        byte[] resultBytes = cipher.decrypt(bytes, pos);
        
        // System.out.println("decrypt2 " + resultBytes.length + ": " + new String(resultBytes));
        assertArrayEquals(plaintextChunk, resultBytes);
        bb.reset();
        
        // decrypt using CtrCipher#decrypt (non-stream, ByteBuffer)
        byte[] resultBytes2 = cipher.decrypt(bb, pos);
        
        // System.out.println("decrypt3 " + resultBytes2.length + ": " + new String(resultBytes2));
        assertArrayEquals(plaintextChunk, resultBytes2);
        bb.reset();

        bb.put(resultBytes);

        pos += n;
        readLength -= n;
      }
      assert readLength == 0;
    } finally {
      // System.out.println(new String(bb.array()));
      assertArrayEquals(Arrays.copyOfRange(plainbytes, 0, totalLength), bb.array());
      try {
        channel.close();
      } catch (Exception e) {
        // Noop
      }
    }
  }

}
