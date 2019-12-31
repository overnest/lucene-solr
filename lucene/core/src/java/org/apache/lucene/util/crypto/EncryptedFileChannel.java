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

import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.MappedByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.channels.ReadableByteChannel;
import java.nio.channels.WritableByteChannel;
import java.nio.file.OpenOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.spec.IvParameterSpec;

public class EncryptedFileChannel extends FileChannel {
  private final int MAX_TRANSFER_BUFFER_SIZE = 8192;
  public final static int IV_LENGTH = Crypto.AES_BLOCK_SIZE;

  private final FileChannel channel;
  
  private final boolean mappable;
  private final CtrCipher cipher;
  private long ivLength = 0;
  private boolean ivWritten = false;

  public static FileChannel open(Path path, OpenOption... options) throws IOException {
    return new EncryptedFileChannel(path, false, options);
  }

  public static FileChannel openMappable(Path path, OpenOption... options) throws IOException {
    return new EncryptedFileChannel(path, true, options);
  }

  private EncryptedFileChannel(Path path, boolean mappable, OpenOption... origOptions) throws IOException {
    this.mappable = mappable;
    OpenOption[] options = mappable ? addWrite(origOptions) : origOptions;
    try {
      this.channel = FileChannel.open(path, options);
      
      IvParameterSpec iv = getIv(origOptions);
      this.cipher = iv != null ? new CtrCipher(Crypto.getAesKey(), iv) : null;
      
    } catch (FileNotFoundException ex) {
      throw new IOException(ex);
    }
  }

  private final OpenOption[] addWrite(OpenOption[] options) {
    // WRITE is needed to be able to to EncryptedFileChannel#map
    List<OpenOption> optList = new ArrayList<OpenOption>(Arrays.asList(options));
    if (optList.contains(StandardOpenOption.WRITE)) {
      return options;
    }
    optList.add(StandardOpenOption.WRITE);
    return optList.toArray(new OpenOption[optList.size()]);
  }

  private final IvParameterSpec getIv(OpenOption... options) throws IOException {
    if (this.channel.size() >= IV_LENGTH) {
      // non-empty file, assume IV is present at the beginning
      ByteBuffer tmp = ByteBuffer.allocate(IV_LENGTH);
      this.channel.read(tmp);
      
      this.ivLength = IV_LENGTH;
      return new IvParameterSpec(tmp.array());
    } else if (Arrays.asList(options).contains(StandardOpenOption.WRITE)) {
      // empty file, generate IV
      IvParameterSpec iv;
      try {
        iv = Crypto.generateAesIV();
      } catch (NoSuchAlgorithmException e) {
        throw new IOException(e);
      }
      // Don't write IV yet (so in case this channel is newer written it will remain completely empty)
      this.ivLength = 0;
      return iv;
    } else {
      // empty file but not writable (can happen in tests etc.)
      return null;
    }
  }
  
  private void ensureIv() throws IOException {
    if (cipher == null || ivWritten) {
      return;
    }
    assert this.channel.position() == 0 : "Bytes written before IV! " + this.channel.position();
    this.ivWritten = true;
    ByteBuffer tmp = ByteBuffer.allocate(IV_LENGTH);
    tmp.put(cipher.getIV());
    tmp.flip();
    this.channel.write(tmp);
    this.ivLength = IV_LENGTH;
  }

  @Override
  public int read(ByteBuffer dst) throws IOException {
    ByteBuffer tmp = ByteBuffer.allocate(dst.limit() - dst.position());
    long position = this.position();
    // Note that cipher may be null but only when the channel is empty so we expect
    // to never come here.
    assert cipher == null || position >= 0 : "Cannot read EncryptedFileChannel before IV: " + this.channel.position();
    int read = this.channel.read(tmp);
    if (read <= 0) {
      return read;
    }
    tmp.flip();
    dst.put(this.cipher.decrypt(tmp, position), 0, read);

    return read;
  }

  @Override
  public int read(ByteBuffer dst, long position) throws IOException {
    ByteBuffer tmp = ByteBuffer.allocate(dst.limit() - dst.position());
    int read = this.channel.read(tmp, position + ivLength);
    if (read <= 0) {
      return read;
    }
    tmp.flip();
    dst.put(this.cipher.decrypt(tmp, position), 0, read);

    return read;
  }

  @Override
  public long read(ByteBuffer[] dsts, int offset, int length) throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public int write(ByteBuffer src) throws IOException {
    if (this.cipher == null) {
      // in case of empty readonly channel - let it crash on write
      return this.channel.write(src);
    }
    ensureIv();
    long position = this.position();
    assert position >= 0 : "Cannot write EncryptedFileChannel before IV: " + this.channel.position();
    byte[] tmp = this.cipher.encrypt(src, position);
    
    return this.channel.write(ByteBuffer.wrap(tmp));
  }

  @Override
  public int write(ByteBuffer src, long position) throws IOException {
    if (this.cipher == null) {
      // in case of empty readonly channel - let it crash on write
      return this.channel.write(src, position);
    }
    ensureIv();
    byte[] tmp = this.cipher.encrypt(src, position);
    
    return this.channel.write(ByteBuffer.wrap(tmp), position + ivLength);
  }

  @Override
  public long write(ByteBuffer[] srcs, int offset, int length) throws IOException {
    throw new UnsupportedOperationException();
  }

  @Override
  public long position() throws IOException {
    return this.channel.position() - ivLength;
  }

  @Override
  public FileChannel position(long newPosition) throws IOException {
    this.channel.position(newPosition + ivLength);      
    return this;
  }

  @Override
  public long size() throws IOException {
    long size = this.channel.size() - ivLength;
    assert size >= 0: "Invalid channel state, size is " + size;
    return size;
  }

  @Override
  public FileChannel truncate(long size) throws IOException {
    this.channel.truncate(size + ivLength);      
    return this;
  }

  @Override
  public void force(boolean metaData) throws IOException {
    this.channel.force(metaData);
  }

  @Override
  public long transferTo(long position, long count, WritableByteChannel target) throws IOException {
    long tmpPosition = position;
    long tmpCount = count;
    long transferCount = 0;
    ByteBuffer bb = ByteBuffer.allocate(MAX_TRANSFER_BUFFER_SIZE);

    while (tmpCount > 0) {
      int read = this.read(bb, tmpPosition);
      if (read <= 0) {
        break;
      }

      int dataSize = tmpCount < read ? (int) tmpCount : read;
      tmpCount -= dataSize;

      bb.flip();
      byte[] data = new byte[dataSize];
      bb.get(data, 0, dataSize);
      bb.flip();

      int write = target.write(ByteBuffer.wrap(data));
      tmpPosition += write;
      transferCount += write;
    }

    return transferCount;
  }

  @Override
  public long transferFrom(ReadableByteChannel src, long position, long count) throws IOException {
    long tmpPosition = position;
    long tmpCount = count;
    long transferCount = 0;
    ByteBuffer bb = ByteBuffer.allocate(MAX_TRANSFER_BUFFER_SIZE);

    while (tmpCount > 0) {
      if (tmpCount < MAX_TRANSFER_BUFFER_SIZE) {
        bb.limit((int) tmpCount);
      }

      int read = src.read(bb);
      if (read <= 0) {
        break;
      }

      int dataSize = tmpCount < read ? (int) tmpCount : read;
      tmpCount -= dataSize;

      bb.flip();
      byte[] data = new byte[dataSize];
      bb.get(data, 0, dataSize);
      bb.flip();

      int write = this.write(ByteBuffer.wrap(data), tmpPosition);
      tmpPosition += write;
      transferCount += write;
    }

    return transferCount;
  }

  @Override
  public MappedByteBuffer map(MapMode mode, long position, long size) throws IOException {
    // READ_WRITE is not supported as writing to MappedByteBuffer would need to
    // encrypt the bytes before piping them into the file (a custom nontrivial
    // implementation of MappedByteBuffer would be needed)
    if (!mappable || mode != MapMode.READ_ONLY) {
      throw new UnsupportedOperationException("This EncryptedFileChannel cannot be mapped with mode " + mode);
    }
    if (cipher == null) {
      // in case of empty readonly channel
      return this.channel.map(mode, position, size);
    }
    
    // We actually use `PRIVATE` mode as it allows *writing* to buffer but does not
    // propagate changes to the file which is what we need here.
    MappedByteBuffer mbb = this.channel.map(MapMode.PRIVATE, position + ivLength, size);
    byte[] tmp = this.cipher.decrypt(mbb, position);
    mbb.rewind();
    mbb.put(tmp);

    return mbb;
  }

  @Override
  public FileLock lock(long position, long size, boolean shared) throws IOException {
    return this.channel.lock(position + ivLength, size, shared);
  }

  @Override
  public FileLock tryLock(long position, long size, boolean shared) throws IOException {
    return this.channel.tryLock(position + ivLength, size, shared);
  }

  @Override
  protected void implCloseChannel() throws IOException {
    this.channel.close();
  }
}
