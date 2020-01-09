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

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.Iterator;
import java.util.NoSuchElementException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

class StrongDocKeyProvider extends KeyProvider {
  
  private static Path INDICES_PATH = Paths.get("indices");

  private static SecretKey SAMPLE_AES_KEY = new SecretKeySpec(
          Base64.getDecoder().decode("4tZ9S+gRYX2F3fm+BIWDDvkcXbkKYXBmB27hixPvSjU="), Crypto.AES_ALGORITHM);
  
  // made public for testing purposes
  public String getIndexUid(Path path) throws IllegalArgumentException {
    Iterator<Path> pathIterator = path.iterator();
    try {
      while (pathIterator.hasNext()) {
        if (pathIterator.next().equals(INDICES_PATH)) {
          // next segment will contain the index UUID
          return pathIterator.next().toString();
        }
      } 
    } catch (NoSuchElementException e) {
      // throw IllegalArgumentException:
    }
    throw new IllegalArgumentException("Invalid path for encryption, must contain \"indices\" segment followed by the index uuid, " + path.toString());
  }
    
  @Override
  public SecretKey getAesKey(Path path) {
    // String indexUuid = getIndexUid(path);
    // TODO: Use indexUuid to fetch company key from API instead
    return SAMPLE_AES_KEY;
  }

}
