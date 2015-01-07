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

import static lucene.security.index.AccessLookup.DISCOVER_FIELD;
import static lucene.security.index.AccessLookup.READ_FIELD;
import static lucene.security.index.DocValueAccessLookup.addDiscoverVisiblity;
import static lucene.security.index.DocValueAccessLookup.addReadVisiblity;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import org.apache.lucene.analysis.core.KeywordAnalyzer;
import org.apache.lucene.document.BinaryDocValuesField;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field.Store;
import org.apache.lucene.document.NumericDocValuesField;
import org.apache.lucene.document.SortedDocValuesField;
import org.apache.lucene.document.SortedSetDocValuesField;
import org.apache.lucene.document.StringField;
import org.apache.lucene.index.AtomicReader;
import org.apache.lucene.index.AtomicReaderContext;
import org.apache.lucene.index.BinaryDocValues;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.DocsEnum;
import org.apache.lucene.index.Fields;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.index.NumericDocValues;
import org.apache.lucene.index.SortedDocValues;
import org.apache.lucene.index.SortedSetDocValues;
import org.apache.lucene.index.Terms;
import org.apache.lucene.index.TermsEnum;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.DocIdSetIterator;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.RAMDirectory;
import org.apache.lucene.util.Bits;
import org.apache.lucene.util.BytesRef;
import org.apache.lucene.util.Version;
import org.junit.Test;

public class SecureAtomicReaderTest {

  @Test
  public void testLiveDocs() throws IOException {
    SecureAtomicReader secureReader = getSecureReader();
    Bits liveDocs = secureReader.getLiveDocs();
    assertEquals(4, liveDocs.length());
    assertTrue(liveDocs.get(0));
    assertTrue(liveDocs.get(1));
    assertTrue(liveDocs.get(2));
    assertFalse(liveDocs.get(3));
    secureReader.close();
  }

  @Test
  public void testDocumentFetch() throws IOException {
    SecureAtomicReader secureReader = getSecureReader();
    {
      Document document = secureReader.document(0);
      Set<String> allowed = new HashSet<String>();
      allowed.add("test");
      allowed.add("info");
      allowed.add(DISCOVER_FIELD);
      allowed.add(READ_FIELD);
      for (IndexableField field : document) {
        assertTrue(allowed.contains(field.name()));
      }
    }
    {
      Document document = secureReader.document(1);
      Set<String> allowed = new HashSet<String>();
      allowed.add("info");
      for (IndexableField field : document) {
        assertTrue(allowed.contains(field.name()));
      }
    }
    {
      Document document = secureReader.document(2);
      Set<String> allowed = new HashSet<String>();
      allowed.add("test");
      allowed.add("info");
      allowed.add(DISCOVER_FIELD);
      allowed.add(READ_FIELD);
      for (IndexableField field : document) {
        assertTrue(allowed.contains(field.name()));
      }
    }
    {
      Document document = secureReader.document(3);
      Iterator<IndexableField> iterator = document.iterator();
      assertFalse(iterator.hasNext());
    }

    secureReader.close();
  }

  @Test
  public void testNumericDocValues() throws IOException {
    SecureAtomicReader secureReader = getSecureReader();
    NumericDocValues numericDocValues = secureReader.getNumericDocValues("number");
    assertEquals(0, numericDocValues.get(0));
    assertEquals(0, numericDocValues.get(1));
    assertEquals(2, numericDocValues.get(2));
    assertEquals(0, numericDocValues.get(3));
  }

  @Test
  public void testBinaryDocValues() throws IOException {
    SecureAtomicReader secureReader = getSecureReader();
    BinaryDocValues binaryDocValues = secureReader.getBinaryDocValues("bin");
    BytesRef result = new BytesRef();
    binaryDocValues.get(0, result);
    assertEquals(new BytesRef("0".getBytes()), result);

    binaryDocValues.get(1, result);
    assertEquals(new BytesRef(), result);

    binaryDocValues.get(2, result);
    assertEquals(new BytesRef("2".getBytes()), result);

    binaryDocValues.get(3, result);
    assertEquals(new BytesRef(), result);
  }

  @Test
  public void testSortedDocValues() throws IOException {
    SecureAtomicReader secureReader = getSecureReader();
    SortedDocValues sortedDocValues = secureReader.getSortedDocValues("sorted");
    {
      BytesRef result = new BytesRef();
      sortedDocValues.get(0, result);
      assertEquals(new BytesRef("0".getBytes()), result);
    }
    {
      BytesRef result = new BytesRef();
      sortedDocValues.get(1, result);
      assertEquals(new BytesRef(), result);
    }
    {
      BytesRef result = new BytesRef();
      sortedDocValues.get(2, result);
      assertEquals(new BytesRef("2".getBytes()), result);
    }
    {
      BytesRef result = new BytesRef();
      sortedDocValues.get(3, result);
      assertEquals(new BytesRef(), result);
    }
  }

  @Test
  public void testSortedSetDocValues() throws IOException {
    SecureAtomicReader secureReader = getSecureReader();
    SortedSetDocValues sortedSetDocValues = secureReader.getSortedSetDocValues("sortedset");
    {
      BytesRef result = new BytesRef();
      int docID = 0;
      sortedSetDocValues.setDocument(docID);
      long ord = -1;
      assertTrue((ord = sortedSetDocValues.nextOrd()) != SortedSetDocValues.NO_MORE_ORDS);
      sortedSetDocValues.lookupOrd(ord, result);
      assertEquals(new BytesRef(Integer.toString(docID)), result);

      assertTrue((ord = sortedSetDocValues.nextOrd()) != SortedSetDocValues.NO_MORE_ORDS);
      sortedSetDocValues.lookupOrd(ord, result);
      assertEquals(new BytesRef("0" + Integer.toString(docID)), result);

      assertTrue((ord = sortedSetDocValues.nextOrd()) == SortedSetDocValues.NO_MORE_ORDS);
    }

    {
      int docID = 1;
      sortedSetDocValues.setDocument(docID);
      assertTrue(sortedSetDocValues.nextOrd() == SortedSetDocValues.NO_MORE_ORDS);
    }

    {
      BytesRef result = new BytesRef();
      int docID = 2;
      sortedSetDocValues.setDocument(docID);
      long ord = -1;
      assertTrue((ord = sortedSetDocValues.nextOrd()) != SortedSetDocValues.NO_MORE_ORDS);
      sortedSetDocValues.lookupOrd(ord, result);
      assertEquals(new BytesRef("0" + Integer.toString(docID)), result);

      assertTrue((ord = sortedSetDocValues.nextOrd()) != SortedSetDocValues.NO_MORE_ORDS);
      sortedSetDocValues.lookupOrd(ord, result);
      assertEquals(new BytesRef(Integer.toString(docID)), result);

      assertTrue((ord = sortedSetDocValues.nextOrd()) == SortedSetDocValues.NO_MORE_ORDS);
    }

    {
      int docID = 3;
      sortedSetDocValues.setDocument(docID);
      assertTrue(sortedSetDocValues.nextOrd() == SortedSetDocValues.NO_MORE_ORDS);
    }
  }

  @Test
  public void testTermWalk() throws IOException, ParseException {
    SecureAtomicReader secureReader = getSecureReader();
    Fields fields = secureReader.fields();
    for (String field : fields) {
      Terms terms = fields.terms(field);
      TermsEnum termsEnum = terms.iterator(null);
      BytesRef ref;
      while ((ref = termsEnum.next()) != null) {
        System.out.println(field + " " + ref.utf8ToString());
        DocsEnum docsEnum = termsEnum.docs(null, null);
        int doc;
        while ((doc = docsEnum.nextDoc()) != DocIdSetIterator.NO_MORE_DOCS) {
          System.out.println(field + " " + ref.utf8ToString() + " " + doc);
        }
      }
    }
    secureReader.close();
  }

  @Test
  public void testQuery() throws IOException, ParseException {
    SecureAtomicReader secureReader = getSecureReader();
    QueryParser parser = new QueryParser(Version.LUCENE_43, "nothing", new KeywordAnalyzer());
    Query query = parser.parse("test:test");
    IndexSearcher searcher = new IndexSearcher(secureReader);
    TopDocs topDocs = searcher.search(query, 10);
    assertEquals(3, topDocs.totalHits);
    {
      int doc = topDocs.scoreDocs[0].doc;
      assertEquals(0, doc);
      Document document = searcher.doc(doc);
      assertEquals("test", document.get("test"));
      assertEquals("info", document.get("info"));
    }
    {
      int doc = topDocs.scoreDocs[1].doc;
      assertEquals(1, doc);
      Document document = searcher.doc(doc);
      assertNull(document.get("test"));
      assertEquals("info", document.get("info"));
    }
    {
      int doc = topDocs.scoreDocs[2].doc;
      assertEquals(2, doc);
      Document document = searcher.doc(doc);
      assertEquals("test", document.get("test"));
      assertEquals("info", document.get("info"));
    }

    secureReader.close();
  }

  private SecureAtomicReader getSecureReader() throws IOException {
    AtomicReader baseReader = createReader();
    Set<String> dicoverableFields = new HashSet<String>();
    dicoverableFields.add("info");

    DocValueAccessLookup accessLookup = new DocValueAccessLookup(Arrays.asList("r1"), Arrays.asList("d1"),
        dicoverableFields);
    return new SecureAtomicReader(baseReader, accessLookup);
  }

  private AtomicReader createReader() throws IOException {
    IndexWriterConfig conf = new IndexWriterConfig(Version.LUCENE_43, new KeywordAnalyzer());
    Directory dir = new RAMDirectory();
    IndexWriter writer = new IndexWriter(dir, conf);
    writer.addDocument(addDiscoverVisiblity("d1", addReadVisiblity("r1", getDoc(0))));
    writer.addDocument(addDiscoverVisiblity("d1", addReadVisiblity("r2", getDoc(1))));
    writer.addDocument(addDiscoverVisiblity("d2", addReadVisiblity("r1", getDoc(2))));
    writer.addDocument(addDiscoverVisiblity("d2", addReadVisiblity("r2", getDoc(3))));
    writer.close();

    DirectoryReader reader = DirectoryReader.open(dir);
    List<AtomicReaderContext> leaves = reader.leaves();
    return leaves.get(0).reader();
  }

  // private Iterable<? extends IndexableField> debug(Iterable<IndexableField>
  // doc) {
  // System.out.println(doc);
  // return doc;
  // }

  private Iterable<IndexableField> getDoc(int i) {
    Document document = new Document();
    document.add(new StringField("test", "test", Store.YES));
    document.add(new StringField("info", "info", Store.YES));
    if (i == 3) {
      document.add(new StringField("shouldnotsee", "shouldnotsee", Store.YES));
    }
    document.add(new NumericDocValuesField("number", i));
    document.add(new BinaryDocValuesField("bin", new BytesRef(Integer.toString(i).getBytes())));
    document.add(new SortedDocValuesField("sorted", new BytesRef(Integer.toString(i).getBytes())));
    document.add(new SortedSetDocValuesField("sortedset", new BytesRef(Integer.toString(i).getBytes())));
    document.add(new SortedSetDocValuesField("sortedset", new BytesRef(("0" + Integer.toString(i)).getBytes())));
    return document;
  }
}
