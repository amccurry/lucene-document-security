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

import lucene.security.DocumentAuthorizations;
import lucene.security.document.DocumentVisiblityField;
import lucene.security.query.DocumentVisibilityFilter;

import org.apache.lucene.document.Field.Store;
import org.apache.lucene.index.AtomicReader;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.util.Bits;

public class FilterAccessControlFactory extends AccessControlFactory {

  public static final String DISCOVER_FIELD = "_discover_";
  public static final String READ_FIELD = "_read_";

  @Override
  public String getDiscoverFieldName() {
    return DISCOVER_FIELD;
  }

  @Override
  public String getReadFieldName() {
    return READ_FIELD;
  }

  @Override
  public AccessControlWriter getWriter() {
    return new FilterAccessControlWriter();
  }

  @Override
  public AccessControlReader getReader(Collection<String> readAuthorizations,
      Collection<String> discoverAuthorizations, Set<String> discoverableFields) {
    return new FilterAccessControlReader(readAuthorizations, discoverAuthorizations, discoverableFields);
  }

  public static class FilterAccessControlReader extends AccessControlReader {

    private final Set<String> _discoverableFields;
    private final DocumentVisibilityFilter _readDocumentVisibilityFilter;
    private final DocumentVisibilityFilter _discoverDocumentVisibilityFilter;

    private Bits _readBits;
    private Bits _discoverBits;

    public FilterAccessControlReader(Collection<String> readAuthorizations, Collection<String> discoverAuthorizations,
        Set<String> discoverableFields) {
      _readDocumentVisibilityFilter = new DocumentVisibilityFilter(READ_FIELD, new DocumentAuthorizations(
          readAuthorizations));
      _discoverDocumentVisibilityFilter = new DocumentVisibilityFilter(DISCOVER_FIELD, new DocumentAuthorizations(
          discoverAuthorizations));
      _discoverableFields = discoverableFields;
    }

    @Override
    public boolean hasAccess(ReadType type, int docID) throws IOException {
      switch (type) {
      case DOCS_ENUM:
      case LIVEDOCS:
        return readOrDiscoverAccess(docID);
      case DOCUMENT_FETCH_DISCOVER:
        return discoverAccess(docID);
      case BINARY_DOC_VALUE:
      case DOCUMENT_FETCH_READ:
      case NORM_VALUE:
      case NUMERIC_DOC_VALUE:
      case SORTED_DOC_VALUE:
      case SORTED_SET_DOC_VALUE:
        return readAccess(docID);
      default:
        throw new IOException("Unknown type [" + type + "]");
      }
    }

    private boolean readAccess(int docID) {
      return _readBits.get(docID);
    }

    private boolean discoverAccess(int docID) {
      return _discoverBits.get(docID);
    }

    private boolean readOrDiscoverAccess(int docID) {
      if (readAccess(docID)) {
        return true;
      } else {
        return discoverAccess(docID);
      }
    }

    @Override
    public boolean canDiscoverField(String name) {
      return _discoverableFields.contains(name);
    }

    @Override
    public AccessControlReader clone(AtomicReader in) throws IOException {
      try {
        FilterAccessControlReader filterAccessControlReader = (FilterAccessControlReader) super.clone();
        filterAccessControlReader._readBits = _readDocumentVisibilityFilter.getDocIdSet(in.getContext(),
            in.getLiveDocs()).bits();
        filterAccessControlReader._discoverBits = _discoverDocumentVisibilityFilter.getDocIdSet(in.getContext(),
            in.getLiveDocs()).bits();
        return filterAccessControlReader;
      } catch (CloneNotSupportedException e) {
        throw new IOException(e);
      }
    }
  }

  public static class FilterAccessControlWriter extends AccessControlWriter {

    @Override
    public Iterable<IndexableField> addReadVisiblity(String read, Iterable<IndexableField> fields) {
      return addField(fields, new DocumentVisiblityField(READ_FIELD, read, Store.YES));
    }

    @Override
    public Iterable<IndexableField> addDiscoverVisiblity(String discover, Iterable<IndexableField> fields) {
      return addField(fields, new DocumentVisiblityField(DISCOVER_FIELD, discover, Store.YES));
    }

  }

}
