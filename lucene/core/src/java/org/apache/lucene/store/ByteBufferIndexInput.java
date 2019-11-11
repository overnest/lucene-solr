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


import java.io.EOFException;
import java.io.IOException;
import java.nio.BufferUnderflowException;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.util.Arrays;

import org.apache.lucene.util.crypto.Crypto;
import org.apache.lucene.util.crypto.CtrCipher;

/**
 * Base IndexInput implementation that uses an array
 * of ByteBuffers to represent a file.
 * <p>
 * Because Java's ByteBuffer uses an int to address the
 * values, it's necessary to access a file greater
 * Integer.MAX_VALUE in size using multiple byte buffers.
 * <p>
 * For efficiency, this class requires that the buffers
 * are a power-of-two (<code>chunkSizePower</code>).
 */
public abstract class ByteBufferIndexInput extends IndexInput implements RandomAccessInput {
  protected final long length;
  protected final long chunkSizeMask;
  protected final int chunkSizePower;
  protected final ByteBufferGuard guard;

  protected ByteBuffer[] buffers;
  protected int curBufIndex = -1;
  protected ByteBuffer curBuf; // redundant for speed: buffers[curBufIndex]

  protected boolean isClone = false;
  protected long sliceOffset = 0;

  protected final boolean isMmap;
  protected final CtrCipher cipher;

  public static ByteBufferIndexInput newInstance(String resourceDescription, ByteBuffer[] buffers, long length, int chunkSizePower, ByteBufferGuard guard) {
    if (buffers.length == 1) {
      return new SingleBufferImpl(resourceDescription, buffers[0], length, chunkSizePower, guard);
    } else {
      return new MultiBufferImpl(resourceDescription, buffers, 0, length, chunkSizePower, guard);
    }
  }

  ByteBufferIndexInput(String resourceDescription, ByteBuffer[] buffers, long length, int chunkSizePower, ByteBufferGuard guard) {
    super(resourceDescription);
    this.buffers = buffers;
    this.length = length;
    this.chunkSizePower = chunkSizePower;
    this.chunkSizeMask = (1L << chunkSizePower) - 1L;
    this.guard = guard;
    this.isMmap = (resourceDescription != null && resourceDescription.contains("MMapIndexInput("));
    
    if (this.isMmap && Crypto.isEncryptionOn()) {
      try {
        this.cipher = Crypto.getCtrDecryptCipher(Crypto.GetAesKey(), Crypto.GetAesIV());
      } catch (IOException e) {
        throw new RuntimeException(e);
      }      
    } else {
      this.cipher = null;
    }

    assert chunkSizePower >= 0 && chunkSizePower <= 30;
    assert (length >>> chunkSizePower) < Integer.MAX_VALUE;
  }

  public byte decryptByte(byte b, long pos) throws GeneralSecurityException, IOException {
    if (cipher != null) {
      byte[] decrypted = cipher.decrypt(new byte[]{b}, pos + sliceOffset);
      return decrypted[0];
    }
    return b;
  }

  public void decryptBytes(byte[] b, int offset, int len, long pos) throws GeneralSecurityException, IOException {
    if (cipher != null) {
      byte[] decrypted = cipher.decrypt(Arrays.copyOfRange(b, offset, offset + len), pos + sliceOffset);
      System.arraycopy(decrypted, 0, b, offset, len);
    }
  }

  public short decryptShort(short s, long pos) throws GeneralSecurityException, IOException {
    if (isMmap) {
      byte[] bytes = new byte[] {
          (byte) (s >> 8 & 0xFF),
          (byte) (s & 0xFF)};

      decryptBytes(bytes, 0, bytes.length, pos);

      return (short) (
          ((short)bytes[0] & 0xFF) << 8 |
          ((short)bytes[1] & 0xFF));
    }

    return s;
  }

  public int decryptInt(int i, long pos) throws GeneralSecurityException, IOException {
    if (isMmap) {
      byte[] bytes = new byte[] {
          (byte) (i >> 24 & 0xFF),
          (byte) (i >> 16 & 0xFF),
          (byte) (i >> 8 & 0xFF),
          (byte) (i & 0xFF)};

      decryptBytes(bytes, 0, bytes.length, pos);

      return (
          ((int)bytes[0] & 0xFF) << 24 |
          ((int)bytes[1] & 0xFF) << 16 |
          ((int)bytes[2] & 0xFF) << 8 |
          ((int)bytes[3] & 0xFF));
    }
    return i;
  }

  public long decryptLong(long l, long pos) throws GeneralSecurityException, IOException {
    if (isMmap) {
      byte[] bytes = new byte[] {
          (byte) (l >> 56 & 0xFF),
          (byte) (l >> 48 & 0xFF),
          (byte) (l >> 40 & 0xFF),
          (byte) (l >> 32 & 0xFF),
          (byte) (l >> 24 & 0xFF),
          (byte) (l >> 16 & 0xFF),
          (byte) (l >> 8 & 0xFF),
          (byte) (l & 0xFF)};

      decryptBytes(bytes, 0, bytes.length, pos);

      return (
          ((long)bytes[0] & 0xFF) << 56 |
          ((long)bytes[1] & 0xFF) << 48 |
          ((long)bytes[2] & 0xFF) << 40 |
          ((long)bytes[3] & 0xFF) << 32 |
          ((long)bytes[4] & 0xFF) << 24 |
          ((long)bytes[5] & 0xFF) << 16 |
          ((long)bytes[6] & 0xFF) << 8 |
          ((long)bytes[7] & 0xFF));
    }
    return l;
  }

  @Override
  public final byte readByte() throws IOException {
    long pos = getFilePointer();
    try {
      return decryptByte(guard.getByte(curBuf), pos);
    } catch (BufferUnderflowException e) {
      do {
        curBufIndex++;
        if (curBufIndex >= buffers.length) {
          throw new EOFException("read past EOF: " + this);
        }
        curBuf = buffers[curBufIndex];
        curBuf.position(0);
      } while (!curBuf.hasRemaining());
      try {
        return decryptByte(guard.getByte(curBuf), pos);
      } catch (GeneralSecurityException e1) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public final void readBytes(byte[] b, int offset, int len) throws IOException {
    long pos = getFilePointer();
    int coff = offset;
    int clen = len;
    try {
      guard.getBytes(curBuf, b, offset, len);
      decryptBytes(b, offset, len, pos);
    } catch (BufferUnderflowException e) {
      int curAvail = curBuf.remaining();
      while (len > curAvail) {
        guard.getBytes(curBuf, b, offset, curAvail);
        len -= curAvail;
        offset += curAvail;
        curBufIndex++;
        if (curBufIndex >= buffers.length) {
          throw new EOFException("read past EOF: " + this);
        }
        curBuf = buffers[curBufIndex];
        curBuf.position(0);
        curAvail = curBuf.remaining();
      }
      guard.getBytes(curBuf, b, offset, len);
      try {
        decryptBytes(b, coff, clen, pos);
      } catch (GeneralSecurityException e1) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public final short readShort() throws IOException {
    long pos = getFilePointer();
    try {
      return decryptShort(guard.getShort(curBuf), pos);
    } catch (BufferUnderflowException e) {
      return super.readShort();
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public final int readInt() throws IOException {
    long pos = getFilePointer();
    try {
      return decryptInt(guard.getInt(curBuf), pos);
    } catch (BufferUnderflowException e) {
      return super.readInt();
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public final long readLong() throws IOException {
    long pos = getFilePointer();
    try {
      return decryptLong(guard.getLong(curBuf), pos);
    } catch (BufferUnderflowException e) {
      return super.readLong();
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public long getFilePointer() {
    try {
      return (((long) curBufIndex) << chunkSizePower) + curBuf.position();
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    }
  }

  @Override
  public void seek(long pos) throws IOException {
    // we use >> here to preserve negative, so we will catch AIOOBE,
    // in case pos + offset overflows.
    final int bi = (int) (pos >> chunkSizePower);
    try {
      if (bi == curBufIndex) {
        curBuf.position((int) (pos & chunkSizeMask));
      } else {
        final ByteBuffer b = buffers[bi];
        b.position((int) (pos & chunkSizeMask));
        // write values, on exception all is unchanged
        this.curBufIndex = bi;
        this.curBuf = b;
      }
    } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException e) {
      throw new EOFException("seek past EOF: " + this);
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    }
  }

  @Override
  public byte readByte(long pos) throws IOException {
    try {
      final int bi = (int) (pos >> chunkSizePower);
      return decryptByte(guard.getByte(buffers[bi], (int) (pos & chunkSizeMask)), pos);
    } catch (IndexOutOfBoundsException ioobe) {
      throw new EOFException("seek past EOF: " + this);
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  // used only by random access methods to handle reads across boundaries
  protected void setPos(long pos, int bi) throws IOException {
    try {
      final ByteBuffer b = buffers[bi];
      b.position((int) (pos & chunkSizeMask));
      this.curBufIndex = bi;
      this.curBuf = b;
    } catch (ArrayIndexOutOfBoundsException | IllegalArgumentException aioobe) {
      throw new EOFException("seek past EOF: " + this);
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    }
  }

  @Override
  public short readShort(long pos) throws IOException {
    final int bi = (int) (pos >> chunkSizePower);
    try {
      return decryptShort(guard.getShort(buffers[bi], (int) (pos & chunkSizeMask)), pos);
    } catch (IndexOutOfBoundsException ioobe) {
      // either it's a boundary, or read past EOF, fall back:
      setPos(pos, bi);
      return readShort();
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public int readInt(long pos) throws IOException {
    final int bi = (int) (pos >> chunkSizePower);
    try {
      return decryptInt(guard.getInt(buffers[bi], (int) (pos & chunkSizeMask)), pos);
    } catch (IndexOutOfBoundsException ioobe) {
      // either it's a boundary, or read past EOF, fall back:
      setPos(pos, bi);
      return readInt();
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public long readLong(long pos) throws IOException {
    final int bi = (int) (pos >> chunkSizePower);
    try {
      return decryptLong(guard.getLong(buffers[bi], (int) (pos & chunkSizeMask)), pos);
    } catch (IndexOutOfBoundsException ioobe) {
      // either it's a boundary, or read past EOF, fall back:
      setPos(pos, bi);
      return readLong();
    } catch (NullPointerException npe) {
      throw new AlreadyClosedException("Already closed: " + this);
    } catch (GeneralSecurityException e) {
      throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
    }
  }

  @Override
  public final long length() {
    return length;
  }

  @Override
  public final ByteBufferIndexInput clone() {
    final ByteBufferIndexInput clone = buildSlice((String) null, 0L, this.length);
    try {
      clone.seek(getFilePointer());
    } catch(IOException ioe) {
      throw new AssertionError(ioe);
    }

    return clone;
  }

  /**
   * Creates a slice of this index input, with the given description, offset, and length. The slice is seeked to the beginning.
   */
  @Override
  public final ByteBufferIndexInput slice(String sliceDescription, long offset, long length) {
    if (offset < 0 || length < 0 || offset+length > this.length) {
      throw new IllegalArgumentException("slice() " + sliceDescription + " out of bounds: offset=" + offset + ",length=" + length + ",fileLength="  + this.length + ": "  + this);
    }

    return buildSlice(sliceDescription, offset, length);
  }

  /** Builds the actual sliced IndexInput (may apply extra offset in subclasses). **/
  protected ByteBufferIndexInput buildSlice(String sliceDescription, long offset, long length) {
    if (buffers == null) {
      throw new AlreadyClosedException("Already closed: " + this);
    }

    final ByteBuffer newBuffers[] = buildSlice(buffers, offset, length);
    final int ofs = (int) (offset & chunkSizeMask);

    final ByteBufferIndexInput clone = newCloneInstance(getFullSliceDescription(sliceDescription), newBuffers, ofs, length);
    clone.isClone = true;
    clone.sliceOffset = this.sliceOffset + offset;

    return clone;
  }

  /** Factory method that creates a suitable implementation of this class for the given ByteBuffers. */
  @SuppressWarnings("resource")
  protected ByteBufferIndexInput newCloneInstance(String newResourceDescription, ByteBuffer[] newBuffers, int offset, long length) {
    if (newBuffers.length == 1) {
      newBuffers[0].position(offset);
      return new SingleBufferImpl(newResourceDescription, newBuffers[0].slice(), length, chunkSizePower, this.guard);
    } else {
      return new MultiBufferImpl(newResourceDescription, newBuffers, offset, length, chunkSizePower, guard);
    }
  }

  /** Returns a sliced view from a set of already-existing buffers:
   *  the last buffer's limit() will be correct, but
   *  you must deal with offset separately (the first buffer will not be adjusted) */
  private ByteBuffer[] buildSlice(ByteBuffer[] buffers, long offset, long length) {
    final long sliceEnd = offset + length;

    final int startIndex = (int) (offset >>> chunkSizePower);
    final int endIndex = (int) (sliceEnd >>> chunkSizePower);

    // we always allocate one more slice, the last one may be a 0 byte one
    final ByteBuffer slices[] = new ByteBuffer[endIndex - startIndex + 1];

    for (int i = 0; i < slices.length; i++) {
      slices[i] = buffers[startIndex + i].duplicate();
    }

    // set the last buffer's limit for the sliced view.
    slices[slices.length - 1].limit((int) (sliceEnd & chunkSizeMask));

    return slices;
  }

  @Override
  public final void close() throws IOException {
    try {
      if (buffers == null) return;

      // make local copy, then un-set early
      final ByteBuffer[] bufs = buffers;
      unsetBuffers();

      if (isClone) return;

      // tell the guard to invalidate and later unmap the bytebuffers (if supported):
      guard.invalidateAndUnmap(bufs);
    } finally {
      unsetBuffers();
    }
  }

  /**
   * Called to remove all references to byte buffers, so we can throw AlreadyClosed on NPE.
   */
  private void unsetBuffers() {
    buffers = null;
    curBuf = null;
    curBufIndex = 0;
  }

  /** Optimization of ByteBufferIndexInput for when there is only one buffer */
  static final class SingleBufferImpl extends ByteBufferIndexInput {

    SingleBufferImpl(String resourceDescription, ByteBuffer buffer, long length, int chunkSizePower, ByteBufferGuard guard) {
      super(resourceDescription, new ByteBuffer[] { buffer }, length, chunkSizePower, guard);
      this.curBufIndex = 0;
      this.curBuf = buffer;
      buffer.position(0);
    }

    // TODO: investigate optimizing readByte() & Co?

    @Override
    public void seek(long pos) throws IOException {
      try {
        curBuf.position((int) pos);
      } catch (IllegalArgumentException e) {
        if (pos < 0) {
          throw new IllegalArgumentException("Seeking to negative position: " + this, e);
        } else {
          throw new EOFException("seek past EOF: " + this);
        }
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      }
    }

    @Override
    public long getFilePointer() {
      try {
        return curBuf.position();
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      }
    }

    @Override
    public byte readByte(long pos) throws IOException {
      try {
        return decryptByte(guard.getByte(curBuf, (int) pos), pos);
      } catch (IllegalArgumentException e) {
        if (pos < 0) {
          throw new IllegalArgumentException("Seeking to negative position: " + this, e);
        } else {
          throw new EOFException("seek past EOF: " + this);
        }
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }

    @Override
    public short readShort(long pos) throws IOException {
      try {
        return decryptShort(guard.getShort(curBuf, (int) pos), pos);
      } catch (IllegalArgumentException e) {
        if (pos < 0) {
          throw new IllegalArgumentException("Seeking to negative position: " + this, e);
        } else {
          throw new EOFException("seek past EOF: " + this);
        }
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }

    @Override
    public int readInt(long pos) throws IOException {
      try {
        return decryptInt(guard.getInt(curBuf, (int) pos), pos);
      } catch (IllegalArgumentException e) {
        if (pos < 0) {
          throw new IllegalArgumentException("Seeking to negative position: " + this, e);
        } else {
          throw new EOFException("seek past EOF: " + this);
        }
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }

    @Override
    public long readLong(long pos) throws IOException {
      try {
        return decryptLong(guard.getLong(curBuf, (int) pos), pos);
      } catch (IllegalArgumentException e) {
        if (pos < 0) {
          throw new IllegalArgumentException("Seeking to negative position: " + this, e);
        } else {
          throw new EOFException("seek past EOF: " + this);
        }
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }
  }

  /** This class adds offset support to ByteBufferIndexInput, which is needed for slices. */
  static final class MultiBufferImpl extends ByteBufferIndexInput {
    private final int offset;

    MultiBufferImpl(String resourceDescription, ByteBuffer[] buffers, int offset, long length, int chunkSizePower,
        ByteBufferGuard guard) {
      super(resourceDescription, buffers, length, chunkSizePower, guard);
      this.offset = offset;
      try {
        seek(0L);
      } catch (IOException ioe) {
        throw new AssertionError(ioe);
      }
    }

    @Override
    public void seek(long pos) throws IOException {
      assert pos >= 0L;
      super.seek(pos + offset);
    }

    @Override
    public long getFilePointer() {
      return super.getFilePointer() - offset;
    }

    private byte readBytePriv(long pos) throws IOException {
      try {
        final int bi = (int) (pos >> chunkSizePower);
        return decryptByte(guard.getByte(buffers[bi], (int) (pos & chunkSizeMask)), pos-offset);
      } catch (IndexOutOfBoundsException ioobe) {
        throw new EOFException("seek past EOF: " + this);
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }

    @Override
    public byte readByte(long pos) throws IOException {
      return readBytePriv(pos + offset);
    }

    private short readShortPriv(long pos) throws IOException {
      final int bi = (int) (pos >> chunkSizePower);
      try {
        return decryptShort(guard.getShort(buffers[bi], (int) (pos & chunkSizeMask)), pos-offset);
      } catch (IndexOutOfBoundsException ioobe) {
        // either it's a boundary, or read past EOF, fall back:
        setPos(pos, bi);
        return readShort();
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }

    @Override
    public short readShort(long pos) throws IOException {
      return readShortPriv(pos + offset);
    }

    private int readIntPriv(long pos) throws IOException {
      final int bi = (int) (pos >> chunkSizePower);
      try {
        return decryptInt(guard.getInt(buffers[bi], (int) (pos & chunkSizeMask)), pos-offset);
      } catch (IndexOutOfBoundsException ioobe) {
        // either it's a boundary, or read past EOF, fall back:
        setPos(pos, bi);
        return readInt();
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }

    @Override
    public int readInt(long pos) throws IOException {
      return readIntPriv(pos + offset);
    }

    private long readLongPriv(long pos) throws IOException {
      final int bi = (int) (pos >> chunkSizePower);
      try {
        return decryptLong(guard.getLong(buffers[bi], (int) (pos & chunkSizeMask)), pos-offset);
      } catch (IndexOutOfBoundsException ioobe) {
        // either it's a boundary, or read past EOF, fall back:
        setPos(pos, bi);
        return readLong();
      } catch (NullPointerException npe) {
        throw new AlreadyClosedException("Already closed: " + this);
      } catch (GeneralSecurityException e) {
        throw new AlreadyClosedException("Can not decrypt. Already closed: " + this);
      }
    }

    @Override
    public long readLong(long pos) throws IOException {
      return readLongPriv(pos + offset);
    }

    @Override
    protected ByteBufferIndexInput buildSlice(String sliceDescription, long ofs, long length) {
      if (buffers == null) {
        throw new AlreadyClosedException("Already closed: " + this);
      }

      long noffset = this.offset + ofs;
      final ByteBuffer newBuffers[] = super.buildSlice(buffers, noffset, length);
      final int nofs = (int) (noffset & chunkSizeMask);

      final ByteBufferIndexInput clone = newCloneInstance(getFullSliceDescription(sliceDescription), newBuffers, nofs, length);
      clone.isClone = true;
      clone.sliceOffset = this.sliceOffset + ofs;

      return clone;

      //return super.buildSlice(sliceDescription, this.offset + ofs, length);
    }
  }
}
