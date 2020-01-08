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
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.apache.lucene.util.LuceneTestCase;

public class TestCrypto extends LuceneTestCase {

  public final String plaintext = "Before the widespread use of message authentication codes and authenticated encryption, "
      + "it was common to discuss the \"error propagation\" properties as a selection criterion for "
      + "a mode of operation. It might be observed, for example, that a one-block error in the "
      + "transmitted ciphertext would result in a one-block error in the reconstructed plaintext "
      + "for ECB mode encryption, while in CBC mode such an error would affect two blocks."
      + "Some felt that such resilience was desirable in the face of random errors (e.g., line "
      + "noise), while others argued that error correcting increased the scope for attackers to "
      + "maliciously tamper with a message.\n"
      + "However, when proper integrity protection is used, such an error will result (with high "
      + "probability) in the entire message being rejected. If resistance to random error is "
      + "desirable, error-correcting codes should be applied to the ciphertext before transmission."
      + "Authenticated encryption\n" + "Main article: Authenticated encryption\n"
      + "A number of modes of operation have been designed to combine secrecy and authentication in "
      + "a single cryptographic primitive. Examples of such modes are XCBC,[25] IACBC, IAPM,[26] OCB, "
      + "EAX, CWC, CCM, and GCM. Authenticated encryption modes are classified as single-pass modes "
      + "or double-pass modes. Some single-pass authenticated encryption algorithms, such as OCB mode, "
      + "are encumbered by patents, while others were specifically designed and released in a way to "
      + "avoid such encumberment.\n"
      + "In addition, some modes also allow for the authentication of unencrypted associated data, "
      + "and these are called AEAD (authenticated encryption with associated data) schemes. For example, "
      + "EAX mode is a double-pass AEAD scheme while OCB mode is single-pass.";

  /**
   * Helpers
   */
  private byte[] dencryptBytes(int operationMode, SecretKey key, IvParameterSpec iv, byte[] bytes) throws IOException {
    try {
      Cipher cipher = Cipher.getInstance(Crypto.CTR_TRANSFORM);
      cipher.init(operationMode, key, iv);
      return cipher.doFinal(bytes);
    } catch (IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException
        | InvalidKeyException | InvalidAlgorithmParameterException e) {
      throw new IOException(e);
    }
  }
  
  private byte[] encryptBytes(SecretKey key, IvParameterSpec iv, byte[] plaintext) throws IOException {
    return dencryptBytes(Cipher.ENCRYPT_MODE, key, iv, plaintext);
  }

  private byte[] decryptBytes(SecretKey key, IvParameterSpec iv, byte[] ciphertext) throws IOException {
    return dencryptBytes(Cipher.DECRYPT_MODE, key, iv, ciphertext);
  }

  /**
   * Tests
   */
  public void testGenerateAesKey() {
    try {
      SecretKey key = Crypto.generateAesKey();
      String base64 = Base64.getEncoder().encodeToString(key.getEncoded());
      System.out.println("AES Key: " + base64);
    } catch (NoSuchAlgorithmException e) {
      fail(e.getMessage());
    }
  }

  public void testGeneratedAesIv() {
    try {
      IvParameterSpec iv = Crypto.generateAesIV();
      String base64 = Base64.getEncoder().encodeToString(iv.getIV());
      System.out.println("AES IV: " + base64);
    } catch (NoSuchAlgorithmException e) {
      fail(e.getMessage());
    }
  }

  public void testGetIndexUuid() {
    assertTrue(Crypto.isTestingOn()); // on for all lucene tests
    Crypto.setTestingOn(false);
    Path indexShardPath = Paths.get("elasticsearch/distribution/build/cluster/run node0/elasticsearch-7.4.3-SNAPSHOT/data/nodes/0/indices/5hQh3cVjS1Gv1C5ww1m2Bg/0/index/_2.si");
    assertEquals("5hQh3cVjS1Gv1C5ww1m2Bg", Crypto.getIndexUid(indexShardPath));
    Path indexStatePath = Paths.get("elasticsearch/distribution/build/cluster/run node0/elasticsearch-7.4.3-SNAPSHOT/data/nodes/0/indices/meYv1aJjQLCYtyc-pKkfGg/_state/state-1.st");
    assertEquals("meYv1aJjQLCYtyc-pKkfGg", Crypto.getIndexUid(indexStatePath));
    Path translogPath = Paths.get("elasticsearch/distribution/build/cluster/run node0/elasticsearch-7.4.3-SNAPSHOT/data/nodes/0/indices/meYv1aJjQLCYtyc-pKkfGg/0/translog/translog-3.tlog");
    assertEquals("meYv1aJjQLCYtyc-pKkfGg", Crypto.getIndexUid(translogPath));
    
    assertEquals("5hQh3cVjS1Gv1C5ww1m2Bg", Crypto.getIndexUid(Paths.get("nodes/0/indices/5hQh3cVjS1Gv1C5ww1m2Bg/0/index/_2.si")));
    assertEquals("5hQh3cVjS1Gv1C5ww1m2Bg", Crypto.getIndexUid(Paths.get("../0/indices/5hQh3cVjS1Gv1C5ww1m2Bg/0/index/_2.si")));
    assertEquals("5hQh3cVjS1Gv1C5ww1m2Bg", Crypto.getIndexUid(Paths.get("indices/5hQh3cVjS1Gv1C5ww1m2Bg/0/index/_2.si")));
    
    try {
      Crypto.getIndexUid(Paths.get("/tmp/lucene.store.TestNIOFSDirectory_1B2F7698E6054884-001/testString-001/string"));
      fail("Crypto.getIndexUid should fail when missing no 'indices' in path");
    } catch (IllegalArgumentException e) {
      assertEquals("Invalid path for encryption /tmp/lucene.store.TestNIOFSDirectory_1B2F7698E6054884-001/testString-001/string", e.getMessage());
    }
    
    Crypto.setTestingOn(true);
    // tests use ad hoc directory structure without "indices"
    assertEquals("lucene.store.TestNIOFSDirectory_1B2F7698E6054884-001", Crypto.getIndexUid(Paths.get("/tmp/lucene.store.TestNIOFSDirectory_1B2F7698E6054884-001/testString-001/string")));
  }

  public void testFullEncrypt() throws Exception {
    byte[] plainbytes = plaintext.getBytes();

    Crypto.initialize();
    SecretKey key = Crypto.generateAesKey();
    IvParameterSpec iv = Crypto.generateAesIV();

    CtrCipher cipher = Crypto.getCtrCipher(key, iv);
    byte[] ciphertext = cipher.encrypt(plainbytes);
    byte[] plaintext = decryptBytes(key, iv, ciphertext);

    assertEquals(plaintext.length, ciphertext.length);
    assertEquals(plainbytes.length, ciphertext.length);
    assertArrayEquals(plainbytes, plaintext);
  }

  public void testPositionalEncrypt() throws Exception {
    byte[] plainbytes = plaintext.getBytes();

    Crypto.initialize();
    SecretKey key = Crypto.generateAesKey();
    IvParameterSpec iv = Crypto.generateAesIV();

    byte[] cipherbytes = encryptBytes(key, iv, plainbytes);

    final int totalLength = 100 + random().nextInt(plainbytes.length - 100);
    SeekableInMemoryByteChannel outputChannel = new SeekableInMemoryByteChannel(new byte[totalLength]);
    int chunkLength = 13; // 1 + random().nextInt(totalLength / 5);

    int writeLength = totalLength;
    long pos = 0;

    CtrCipher cipher = Crypto.getCtrCipher(key, iv);
    try {
      while (writeLength > 0) {
        byte[] bytes = Arrays.copyOfRange(plainbytes, (int) pos, (int) pos + Math.min(chunkLength, writeLength));
        assertEquals(Math.min(chunkLength, writeLength), bytes.length);

        ByteBuffer bb = ByteBuffer.wrap(cipher.encrypt(bytes, pos));
        bb.mark();

        final int n = outputChannel.write(bb);
        if (n == 0) {
          break;
        }
        bb.reset();

        byte[] cipherTextChunk = Arrays.copyOfRange(cipherbytes, (int) pos, (int) pos + n);
        assertArrayEquals(cipherTextChunk, bb.array());
        // System.out.println("encrypt " + bb.array().length + ": " + new
        // String(bb.array()) + " vs " + new String(cipherTextChunk));

        bb.reset();
        pos += n;
        writeLength -= n;
      }
      assertEquals(0, writeLength);
    } finally {
      try {
        outputChannel.close();
      } catch (Exception e) {
        // Noop
      }
    }
    // System.out.println(new String(outputChannel.array()));
    assertArrayEquals(Arrays.copyOfRange(cipherbytes, 0, totalLength), outputChannel.array());
  }

  public void testFullDecrypt() throws Exception {
    byte[] plainbytes = plaintext.getBytes();

    Crypto.initialize();
    SecretKey key = Crypto.generateAesKey();
    IvParameterSpec iv = Crypto.generateAesIV();

    byte[] ciphertext = encryptBytes(key, iv, plainbytes);
    CtrCipher cipher = Crypto.getCtrCipher(key, iv);
    byte[] plaintext = cipher.decrypt(ciphertext);

    assertEquals(ciphertext.length, plaintext.length);
    assertEquals(ciphertext.length, plainbytes.length);
    assertArrayEquals(plainbytes, plaintext);
  }

  public void testPositionalDecrypt() throws Exception {
    byte[] plainbytes = plaintext.getBytes();

    Crypto.initialize();
    SecretKey key = Crypto.generateAesKey();
    IvParameterSpec iv = Crypto.generateAesIV();

    byte[] ciphertext = encryptBytes(key, iv, plainbytes);

    final int totalLength = 100 + random().nextInt(plainbytes.length - 100);
    SeekableInMemoryByteChannel inputChannel = new SeekableInMemoryByteChannel(ciphertext);
    int chunkLength = 1 + random().nextInt(totalLength / 5);

    ByteBuffer bb = ByteBuffer.wrap(new byte[totalLength]);
    int readLength = totalLength;
    long pos = 0;

    CtrCipher cipher = Crypto.getCtrCipher(key, iv);

    try {
      while (readLength > 0) {
        bb.limit(bb.position() + Math.min(chunkLength, readLength));
        assertEquals(Math.min(chunkLength, readLength), bb.remaining());

        bb.mark();
        final int n = inputChannel.read(bb);
        bb.reset();
        if (n == 0) {
          break;
        }

        byte[] plaintextChunk = Arrays.copyOfRange(plainbytes, (int) pos, (int) pos + n);

        // decrypt using CtrCipher#decrypt (non-stream, bytes)
        byte[] bytes = Arrays.copyOfRange(bb.array(), (int) pos, (int) pos + n);
        byte[] resultBytes = cipher.decrypt(bytes, pos);

        // System.out.println("decrypt " + resultBytes.length + ": " + new
        // String(resultBytes));
        assertArrayEquals(plaintextChunk, resultBytes);
        bb.reset();

        // decrypt using CtrCipher#decrypt (non-stream, ByteBuffer)
        byte[] resultBytes2 = cipher.decrypt(bb, pos);

        // System.out.println("decrypt2 " + resultBytes2.length + ": " + new
        // String(resultBytes2));
        assertArrayEquals(plaintextChunk, resultBytes2);
        bb.reset();

        bb.put(resultBytes);

        pos += n;
        readLength -= n;
      }
      assertEquals(0, readLength);
    } finally {
      try {
        inputChannel.close();
      } catch (Exception e) {
        // Noop
      }
    }
    // System.out.println(new String(bb.array()));
    assertArrayEquals(Arrays.copyOfRange(plainbytes, 0, totalLength), bb.array());
  }

}
