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
import lucene.security.search.BitSetDocumentVisibilityFilterCacheStrategy;
import lucene.security.search.DocumentVisibilityFilter;
import lucene.security.search.DocumentVisibilityFilterCacheStrategy;

import org.apache.lucene.document.Field.Store;
import org.apache.lucene.index.AtomicReader;
import org.apache.lucene.index.AtomicReaderContext;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.search.DocIdSet;
import org.apache.lucene.search.Filter;
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
    private final DocumentVisibilityFilterCacheStrategy _filterCacheStrategy;

    private Bits _readBits;
    private Bits _discoverBits;
    private boolean _noReadAccess;
    private boolean _noDiscoverAccess;
    private DocIdSet _readDocIdSet;
    private DocIdSet _discoverDocIdSet;
    private boolean _isClone;

    public FilterAccessControlReader(Collection<String> readAuthorizations, Collection<String> discoverAuthorizations,
        Set<String> discoverableFields) {
      this(readAuthorizations, discoverAuthorizations, discoverableFields,
          BitSetDocumentVisibilityFilterCacheStrategy.INSTANCE);
    }

    public FilterAccessControlReader(Collection<String> readAuthorizations, Collection<String> discoverAuthorizations,
        Set<String> discoverableFields, DocumentVisibilityFilterCacheStrategy filterCacheStrategy) {
      _filterCacheStrategy = filterCacheStrategy;

      if (readAuthorizations == null || readAuthorizations.isEmpty()) {
        _noReadAccess = true;
        _readDocumentVisibilityFilter = null;
      } else {
        _readDocumentVisibilityFilter = new DocumentVisibilityFilter(READ_FIELD, new DocumentAuthorizations(
            readAuthorizations), _filterCacheStrategy);
      }

      if (discoverAuthorizations == null || discoverAuthorizations.isEmpty()) {
        _noDiscoverAccess = true;
        _discoverDocumentVisibilityFilter = null;
      } else {
        _discoverDocumentVisibilityFilter = new DocumentVisibilityFilter(DISCOVER_FIELD, new DocumentAuthorizations(
            discoverAuthorizations), _filterCacheStrategy);
      }
      _discoverableFields = discoverableFields;
    }

    @Override
    protected boolean readAccess(int docID) throws IOException {
      checkClone();
      if (_noReadAccess) {
        return false;
      }
      return _readBits.get(docID);
    }

    private void checkClone() throws IOException {
      if (!_isClone) {
        throw new IOException("No AtomicReader set.");
      }
    }

    @Override
    protected boolean discoverAccess(int docID) throws IOException {
      checkClone();
      if (_noDiscoverAccess) {
        return false;
      }
      return _discoverBits.get(docID);
    }

    @Override
    protected boolean readOrDiscoverAccess(int docID) throws IOException {
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
        filterAccessControlReader._isClone = true;
        if (_readDocumentVisibilityFilter == null) {
          filterAccessControlReader._noReadAccess = true;
        } else {
          DocIdSet readDocIdSet = _readDocumentVisibilityFilter.getDocIdSet(in.getContext(), in.getLiveDocs());
          if (readDocIdSet == DocIdSet.EMPTY_DOCIDSET || readDocIdSet == null) {
            filterAccessControlReader._noReadAccess = true;
          } else {
            filterAccessControlReader._readBits = readDocIdSet.bits();
            if (filterAccessControlReader._readBits == null) {
              throw new IOException("Read Bits can not be null.");
            }
          }
          filterAccessControlReader._readDocIdSet = readDocIdSet;
        }

        if (_discoverDocumentVisibilityFilter == null) {
          filterAccessControlReader._noDiscoverAccess = true;
        } else {
          DocIdSet discoverDocIdSet = _discoverDocumentVisibilityFilter.getDocIdSet(in.getContext(), in.getLiveDocs());
          if (discoverDocIdSet == DocIdSet.EMPTY_DOCIDSET || discoverDocIdSet == null) {
            filterAccessControlReader._noDiscoverAccess = true;
          } else {
            filterAccessControlReader._discoverBits = discoverDocIdSet.bits();
            if (filterAccessControlReader._discoverBits == null) {
              throw new IOException("Read Bits can not be null.");
            }
          }
          filterAccessControlReader._discoverDocIdSet = discoverDocIdSet;
        }
        return filterAccessControlReader;
      } catch (CloneNotSupportedException e) {
        throw new IOException(e);
      }
    }

    @Override
    public Filter getQueryFilter() throws IOException {
      return new Filter() {
        @Override
        public DocIdSet getDocIdSet(AtomicReaderContext context, Bits acceptDocs) throws IOException {
          FilterAccessControlReader accessControlReader = (FilterAccessControlReader) FilterAccessControlReader.this
              .clone(context.reader());
          DocIdSet readDocIdSet = accessControlReader._readDocIdSet;
          DocIdSet discoverDocIdSet = accessControlReader._discoverDocIdSet;
          if (isEmptyOrNull(discoverDocIdSet) && isEmptyOrNull(readDocIdSet)) {
            return DocIdSet.EMPTY_DOCIDSET;
          } else if (isEmptyOrNull(discoverDocIdSet)) {
            return readDocIdSet;
          } else if (isEmptyOrNull(readDocIdSet)) {
            return discoverDocIdSet;
          } else {
            return DocumentVisibilityFilter.getLogicalOr(readDocIdSet, discoverDocIdSet);
          }
        }

        private boolean isEmptyOrNull(DocIdSet docIdSet) {
          if (docIdSet == null || docIdSet == DocIdSet.EMPTY_DOCIDSET) {
            return true;
          }
          return false;
        }
      };
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
