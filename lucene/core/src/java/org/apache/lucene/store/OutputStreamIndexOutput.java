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
package org.apache.lucene.store;


import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.zip.CRC32;
import java.util.zip.Checksum;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import org.apache.lucene.util.crypto.Crypto;

/** Implementation class for buffered {@link IndexOutput} that writes to an {@link OutputStream}. */
public class OutputStreamIndexOutput extends IndexOutput {

  private final BufferedOutputStream os;

  private long bytesWritten = 0L;
  private boolean flushedOnClose = false;
  private Cipher cipher = null;
  private Checksum digest;

  /**
   * Creates a new {@link OutputStreamIndexOutput} with the given buffer size.
   * @param bufferSize the buffer size in bytes used to buffer writes internally.
   * @throws IllegalArgumentException if the given buffer size is less or equal to <tt>0</tt>
   */
  public OutputStreamIndexOutput(String resourceDescription, String name, OutputStream out, int bufferSize) {
    super(resourceDescription, name);
    try {
      cipher = Crypto.InitAesCtrCipherEncrypt(Crypto.GetAesKey(), Crypto.GetAesIV());
    } catch (InvalidKeyException | NoSuchAlgorithmException | NoSuchPaddingException
        | InvalidAlgorithmParameterException e) {
      cipher = null;
    }
    this.digest = new BufferedChecksum(new CRC32());
    this.os = new BufferedOutputStream(out, bufferSize);
  }

  @Override
  public final void writeByte(byte b) throws IOException {
    if (cipher != null) {
      byte[] ciphertext = cipher.update(new byte[]{b});
      os.write(ciphertext[0]);
    } else {
      os.write(b);
    }
    this.digest.update(b);
    bytesWritten++;
  }

  @Override
  public final void writeBytes(byte[] b, int offset, int length) throws IOException {
    if (cipher != null && length > 0) {
      byte[] ciphertext = cipher.update(b, offset, length);
      os.write(ciphertext);
    } else {
      os.write(b, offset, length);
    }
    this.digest.update(b, offset, length);
    bytesWritten += length;
  }

  @Override
  public void close() throws IOException {
    try (final OutputStream o = os) {
      // We want to make sure that os.flush() was running before close:
      // BufferedOutputStream may ignore IOExceptions while flushing on close().
      // We keep this also in Java 8, although it claims to be fixed there,
      // because there are more bugs around this! See:
      // # https://bugs.openjdk.java.net/browse/JDK-7015589
      // # https://bugs.openjdk.java.net/browse/JDK-8054565
      if (!flushedOnClose) {
        flushedOnClose = true; // set this BEFORE calling flush!
        o.flush();
      }

      if (cipher != null) {
        try {
          cipher.doFinal();
        } catch (Exception e) {
          // Noop
        }
      }
    }
  }

  @Override
  public final long getFilePointer() {
    return bytesWritten;
  }

  @Override
  public final long getChecksum() throws IOException {
    os.flush();
    return this.digest.getValue();
  }
}
