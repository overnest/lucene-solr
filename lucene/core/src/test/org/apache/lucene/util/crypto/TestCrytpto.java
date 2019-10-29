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
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.commons.compress.utils.SeekableInMemoryByteChannel;
import org.apache.commons.crypto.stream.CtrCryptoInputStream;
import org.apache.lucene.util.LuceneTestCase;

import com.fasterxml.jackson.databind.util.ByteBufferBackedInputStream;


public class TestCrytpto extends LuceneTestCase {

  public static String plaintext = "Before the widespread use of message authentication codes and authenticated encryption, " +
      "it was common to discuss the \"error propagation\" properties as a selection criterion for " +
      "a mode of operation. It might be observed, for example, that a one-block error in the " +
      "transmitted ciphertext would result in a one-block error in the reconstructed plaintext " +
      "for ECB mode encryption, while in CBC mode such an error would affect two blocks." +
      "Some felt that such resilience was desirable in the face of random errors (e.g., line " +
      "noise), while others argued that error correcting increased the scope for attackers to " +
      "maliciously tamper with a message." +
      "However, when proper integrity protection is used, such an error will result (with high " +
      "probability) in the entire message being rejected. If resistance to random error is " +
      "desirable, error-correcting codes should be applied to the ciphertext before transmission." +
      "Authenticated encryption" +
      "Main article: Authenticated encryption" +
      "A number of modes of operation have been designed to combine secrecy and authentication in " +
      "a single cryptographic primitive. Examples of such modes are XCBC,[25] IACBC, IAPM,[26] OCB, " +
      "EAX, CWC, CCM, and GCM. Authenticated encryption modes are classified as single-pass modes " +
      "or double-pass modes. Some single-pass authenticated encryption algorithms, such as OCB mode, " +
      "are encumbered by patents, while others were specifically designed and released in a way to " +
      "avoid such encumberment." +
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


  public void testPositionCryptoRead() throws Exception {
    assertFalse(false);

    byte[] plainbytes = plaintext.getBytes();

    Crypto.Initialize();
    SecretKey key = Crypto.GenerateAesKey();
    IvParameterSpec iv = Crypto.GenerateAesIV();

    byte[] ciphertext = Crypto.EncryptAesCtr(key, iv, plainbytes);
    byte[] plaintext = Crypto.DecryptAesCtr(key, iv, ciphertext);

    assertEquals(ciphertext.length, plaintext.length);
    assertEquals(ciphertext.length, plainbytes.length);
    assertArrayEquals(plainbytes, plaintext);


    byte[] b = new byte[210];
    int readLength = 100;
    int offset = 0;
    long pos = 0;
    SeekableInMemoryByteChannel channel = new SeekableInMemoryByteChannel(ciphertext);
    ByteBuffer bb = ByteBuffer.wrap(b, offset, readLength);

    CtrCryptoInputStream input = null;

    try {
      channel.position(pos);

      while (readLength > 0) {
        final int toRead = 13;
        bb.limit(bb.position() + toRead);
        assert bb.remaining() == toRead;

        bb.mark();
        final int i = channel.read(bb);
        bb.reset();
        bb.mark();

        ByteBufferBackedInputStream bbis = new ByteBufferBackedInputStream(bb);
        input = Crypto.GetCtrCryptoInputStream(bbis, key.getEncoded(), iv.getIV(), pos);
        ByteBuffer buf = ByteBuffer.allocate(i);
        int r = input.read(buf);
        bb.reset();
        bb.put(buf.rewind());

        System.out.println("decrypt " + r + ": " + new String(buf.array()));

        pos += i;
        readLength -= i;
      }
      assert readLength <= 0;
    } catch (IOException ioe) {
      throw new IOException(ioe.getMessage() + ": " + this, ioe);
    } finally {
      try {
        if (input != null) {
          input.close();
        }
      } catch(Exception e) {
        // Noop
      }
    }

    System.out.println(new String(bb.array()));
  }

}
