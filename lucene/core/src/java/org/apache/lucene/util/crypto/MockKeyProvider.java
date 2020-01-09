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
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class MockKeyProvider extends KeyProvider {

  private static List<SecretKey> TEST_AES_KEYS =  Arrays.asList(
      new SecretKeySpec(
          Base64.getDecoder().decode("4tZ9S+gRYX2F3fm+BIWDDvkcXbkKYXBmB27hixPvSjU="), Crypto.AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("7C9Q6SnqXwrfI03LPE2J0LEcnnVP/YnF8O3hGvpjs7Q="), Crypto.AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("UqVyK+sHZQVGJBbTr8UDN5TF/t5f9MgqmVkSxi6uJu0="), Crypto.AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("pd0fWwS7glXPpbzrPavNx7zpo25DLXa1gAbsijz2pHw="), Crypto.AES_ALGORITHM),
      new SecretKeySpec(
          Base64.getDecoder().decode("dtCrOKsvBlgAc3ZAGAxlWHlHK3dNNXjhrCtjXXJavtk="), Crypto.AES_ALGORITHM)
  );
  
  @Override
  public SecretKey getAesKey(Path path) {
    // This mock implementation will deterministically select a key
    // from a pregenerated set of keys

    // Use the grandparent dir name (so that tests that do renaming and copying would work)
    String grandparent = path.getParent().getParent().getFileName().toString();
    return TEST_AES_KEYS.get(Math.abs(grandparent.hashCode()) % TEST_AES_KEYS.size());
  }

}
