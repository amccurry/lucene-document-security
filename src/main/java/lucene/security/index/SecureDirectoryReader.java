/**
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
package lucene.security.index;

import java.io.IOException;
import java.util.Collection;
import java.util.Set;

import org.apache.lucene.index.AtomicReader;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.FilterDirectoryReader;

public class SecureDirectoryReader extends FilterDirectoryReader {

  public static SecureDirectoryReader create(DirectoryReader in, Collection<String> readAuthorizations,
      Collection<String> discoverAuthorizations, Set<String> discoverableFields) throws IOException {
    return create(in, readAuthorizations, discoverAuthorizations, AccessLookup.READ_FIELD,
        AccessLookup.DISCOVER_FIELD, discoverableFields);
  }

  public static SecureDirectoryReader create(DirectoryReader in, Collection<String> readAuthorizations,
      Collection<String> discoverAuthorizations, String readField, String discoverField, Set<String> discoverableFields)
      throws IOException {
    DocValueAccessLookup accessLookup = new DocValueAccessLookup(readAuthorizations, discoverAuthorizations, readField,
        discoverField, discoverableFields);
    return new SecureDirectoryReader(in, accessLookup);
  }

  public SecureDirectoryReader(DirectoryReader in, final AccessLookup accessLookup) {
    super(in, new SubReaderWrapper() {

      @Override
      public AtomicReader wrap(AtomicReader reader) {
        try {
          return new SecureAtomicReader(reader, accessLookup);
        } catch (IOException e) {
          throw new RuntimeException(e);
        }
      }
    });
  }

  @Override
  protected DirectoryReader doWrapDirectoryReader(DirectoryReader in) {
    System.out.println(in.getClass());
    if (in instanceof SecureDirectoryReader) {
      return in;
    }
    throw new RuntimeException("Not allowed.");
  }

}