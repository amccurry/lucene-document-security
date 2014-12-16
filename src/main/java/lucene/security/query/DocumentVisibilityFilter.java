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
package lucene.security.query;

import java.io.IOException;

import lucene.security.DocumentAuthorizations;
import lucene.security.DocumentVisibility;
import lucene.security.DocumentVisibilityEvaluator;

import org.apache.lucene.index.AtomicReader;
import org.apache.lucene.index.AtomicReaderContext;
import org.apache.lucene.index.DocsEnum;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.search.DocIdSet;
import org.apache.lucene.search.Filter;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.OpenBitSet;

public class DocumentVisibilityFilter extends Filter {

  private final String _fieldName;
  private final DocumentAuthorizations _authorizations;

  public DocumentVisibilityFilter(String fieldName, DocumentAuthorizations authorizations) {
    _fieldName = fieldName;
    _authorizations = authorizations;
  }

  @Override
  public DocIdSet getDocIdSet(AtomicReaderContext context, Bits acceptDocs) throws IOException {
    AtomicReader reader = context.reader();
    Fields fields = reader.fields();
    Terms terms = fields.terms(_fieldName);
    if (terms == null) {
      if (acceptDocs instanceof DocIdSet) {
        return (DocIdSet) acceptDocs;
      } else {
        return wrap(acceptDocs);
      }
    }
    OpenBitSet bitSet = new OpenBitSet(reader.maxDoc());
    TermsEnum iterator = terms.iterator(null);
    BytesRef bytesRef;
    DocumentVisibilityEvaluator visibilityEvaluator = new DocumentVisibilityEvaluator(_authorizations);
    while ((bytesRef = iterator.next()) != null) {
      if (isVisible(visibilityEvaluator, bytesRef)) {
        // System.out.println("Yep Term [" + bytesRef.utf8ToString() + "]");
        makeVisible(terms, iterator, bytesRef, bitSet, acceptDocs);
      } else {
        // System.out.println("Nope Term [" + bytesRef.utf8ToString() + "]");
      }
    }
    return bitSet;
  }

  private void makeVisible(Terms terms, TermsEnum iterator, BytesRef bytesRef, OpenBitSet bitSet, Bits liveDocs)
      throws IOException {
    DocsEnum docsEnum = iterator.docs(liveDocs, null);
    int doc;
    while ((doc = docsEnum.nextDoc()) != DocsEnum.NO_MORE_DOCS) {
      bitSet.set(doc);
    }
  }

  private boolean isVisible(DocumentVisibilityEvaluator visibilityEvaluator, BytesRef bytesRef) throws IOException {
    DocumentVisibility visibility = new DocumentVisibility(trim(bytesRef));
    return visibilityEvaluator.evaluate(visibility);
  }

  private byte[] trim(BytesRef bytesRef) {
    byte[] buf = new byte[bytesRef.length];
    System.arraycopy(bytesRef.bytes, bytesRef.offset, buf, 0, bytesRef.length);
    return buf;
  }

  private DocIdSet wrap(Bits acceptDocs) {
    throw new RuntimeException("not implemented");
  }

}