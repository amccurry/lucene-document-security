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

import org.apache.lucene.index.AtomicReader;

public interface AccessLookup extends Cloneable {

  public enum TYPE {
    LIVEDOCS, DOCUMENT_FETCH_READ, DOCUMENT_FETCH_DISCOVER, NUMERIC_DOC_VALUE, BINARY_DOC_VALUE, SORTED_DOC_VALUE, NORM_VALUE, SORTED_SET_DOC_VALUE, DOCS_ENUM
  }

  boolean hasAccess(TYPE type, int docID) throws IOException;

  boolean canDiscoverField(String name);
  
  AccessLookup clone(AtomicReader in) throws IOException;

}
