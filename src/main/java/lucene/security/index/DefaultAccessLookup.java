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
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import lucene.security.DocumentAuthorizations;
import lucene.security.DocumentVisibility;
import lucene.security.DocumentVisibilityEvaluator;
import lucene.security.document.DocumentVisiblityUtil;

import org.apache.lucene.index.AtomicReader;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.util.BytesRef;

import com.googlecode.concurrentlinkedhashmap.ConcurrentLinkedHashMap;

public class DefaultAccessLookup implements AccessLookup {

  private final DocumentAuthorizations _readUnionDiscoverAuthorizations;
  private final DocumentAuthorizations _readAuthorizations;
  private final String _readField;
  private final String _discoverField;
  private final DocumentVisibilityEvaluator _readUnionDiscoverVisibilityEvaluator;
  private final DocumentVisibilityEvaluator _readAuthorizationsVisibilityEvaluator;
  private final ConcurrentLinkedHashMap<Integer, DocumentVisibility> _readOrdToDocumentVisibility;
  private final ConcurrentLinkedHashMap<Integer, DocumentVisibility> _discoverOrdToDocumentVisibility;
  private final Set<String> _discoverableFields;
  private final ThreadLocal<BytesRef> _ref = new ThreadLocal<BytesRef>() {
    @Override
    protected BytesRef initialValue() {
      return new BytesRef();
    }
  };

  private SortedDocValues _readFieldSortedDocValues;
  private SortedDocValues _discoverFieldSortedDocValues;

  public DefaultAccessLookup(Collection<String> readAuthorizations, Collection<String> discoverAuthorizations,
      Set<String> discoverableFields) {
    this(readAuthorizations, discoverAuthorizations, DocumentVisiblityUtil.READ_FIELD,
        DocumentVisiblityUtil.DISCOVER_FIELD, discoverableFields);
  }

  public DefaultAccessLookup(Collection<String> readAuthorizations, Collection<String> discoverAuthorizations,
      String readField, String discoverField, Set<String> discoverableFields) {
    _discoverableFields = new HashSet<String>(discoverableFields);
    // TODO need to pass in the discover code to change document if needed
    List<String> termAuth = new ArrayList<String>();
    termAuth.addAll(readAuthorizations);
    termAuth.addAll(discoverAuthorizations);
    _readUnionDiscoverAuthorizations = new DocumentAuthorizations(termAuth);
    _readUnionDiscoverVisibilityEvaluator = new DocumentVisibilityEvaluator(_readUnionDiscoverAuthorizations);
    _readAuthorizations = new DocumentAuthorizations(readAuthorizations);
    _readAuthorizationsVisibilityEvaluator = new DocumentVisibilityEvaluator(_readAuthorizations);
    _readField = readField;
    _discoverField = discoverField;
    _readOrdToDocumentVisibility = new ConcurrentLinkedHashMap.Builder<Integer, DocumentVisibility>()
        .maximumWeightedCapacity(1000).build();
    _discoverOrdToDocumentVisibility = new ConcurrentLinkedHashMap.Builder<Integer, DocumentVisibility>()
        .maximumWeightedCapacity(1000).build();
  }

  @Override
  public AccessLookup clone(AtomicReader in) throws IOException {
    try {
      DefaultAccessLookup clone = (DefaultAccessLookup) super.clone();
      clone._discoverFieldSortedDocValues = in.getSortedDocValues(_discoverField);
      clone._readFieldSortedDocValues = in.getSortedDocValues(_readField);
      return clone;
    } catch (CloneNotSupportedException e) {
      throw new IOException(e);
    }
  }

  @Override
  public boolean hasAccess(TYPE type, int docID) throws IOException {
    BytesRef ref = _ref.get();
    switch (type) {
    case DOCS_ENUM:
    case LIVEDOCS:
      return readOrDiscoverAccess(ref, docID);
    case DOCUMENT_FETCH_DISCOVER:
      return discoverAccess(ref, docID);
    case BINARY_DOC_VALUE:
    case DOCUMENT_FETCH_READ:
    case NORM_VALUE:
    case NUMERIC_DOC_VALUE:
    case SORTED_DOC_VALUE:
    case SORTED_SET_DOC_VALUE:
      return readAccess(ref, docID);
    default:
      throw new IOException("Unknown type [" + type + "]");
    }
  }

  private boolean readOrDiscoverAccess(BytesRef ref, int doc) throws IOException {
    if (readAccess(ref, doc)) {
      return true;
    }
    if (discoverAccess(ref, doc)) {
      return true;
    }
    return false;
  }

  private boolean discoverAccess(BytesRef ref, int doc) throws IOException {
    SortedDocValues discoverFieldSortedDocValues = _discoverFieldSortedDocValues;
    // Checking discovery access
    int ord = discoverFieldSortedDocValues.getOrd(doc);
    if (ord >= 0) {
      // If < 0 means there is no value.
      DocumentVisibility discoverDocumentVisibility = _discoverOrdToDocumentVisibility.get(ord);
      if (discoverDocumentVisibility == null) {
        discoverFieldSortedDocValues.get(doc, ref);
        discoverDocumentVisibility = new DocumentVisibility(ref.utf8ToString());
        _discoverOrdToDocumentVisibility.put(ord, discoverDocumentVisibility);
      }
      if (_readUnionDiscoverVisibilityEvaluator.evaluate(discoverDocumentVisibility)) {
        return true;
      }
    }
    return false;
  }

  private boolean readAccess(BytesRef ref, int doc) throws IOException {
    SortedDocValues readFieldSortedDocValues = _readFieldSortedDocValues;
    // Checking read access
    int ord = readFieldSortedDocValues.getOrd(doc);
    if (ord >= 0) {
      // If < 0 means there is no value.
      DocumentVisibility readDocumentVisibility = _readOrdToDocumentVisibility.get(ord);
      if (readDocumentVisibility == null) {
        readFieldSortedDocValues.get(doc, ref);
        readDocumentVisibility = new DocumentVisibility(ref.utf8ToString());
        _readOrdToDocumentVisibility.put(ord, readDocumentVisibility);
      }

      if (_readAuthorizationsVisibilityEvaluator.evaluate(readDocumentVisibility)) {
        return true;
      }
    }
    return false;
  }

  @Override
  public boolean canDiscoverField(String name) {
    return _discoverableFields.contains(name);
  }

}
