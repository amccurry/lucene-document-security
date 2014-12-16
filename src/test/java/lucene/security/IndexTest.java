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
package lucene.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.IOException;

import lucene.security.DocumentAuthorizations;
import lucene.security.DocumentVisibility;
import lucene.security.DocumentVisibilityEvaluator;
import lucene.security.document.DocumentVisiblityField;
import lucene.security.query.DocumentVisibilityFilter;

import org.apache.lucene.analysis.standard.StandardAnalyzer;
import org.apache.lucene.document.Document;
import org.apache.lucene.document.Field.Store;
import org.apache.lucene.document.StringField;
import org.apache.lucene.document.TextField;
import org.apache.lucene.index.DirectoryReader;
import org.apache.lucene.index.IndexWriter;
import org.apache.lucene.index.IndexWriterConfig;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.queryparser.classic.ParseException;
import org.apache.lucene.queryparser.classic.QueryParser;
import org.apache.lucene.search.Filter;
import org.apache.lucene.search.IndexSearcher;
import org.apache.lucene.search.Query;
import org.apache.lucene.search.TopDocs;
import org.apache.lucene.store.Directory;
import org.apache.lucene.store.RAMDirectory;
import org.apache.lucene.util.Version;
import org.junit.Test;

public class IndexTest {

  @Test
  public void test1() throws ParseException, IOException {
    DocumentAuthorizations authorizations = new DocumentAuthorizations("d", "a", "b");
    runTest(authorizations, 1);
  }

  @Test
  public void test2() throws ParseException, IOException {
    DocumentAuthorizations authorizations = new DocumentAuthorizations("c", "a", "b");
    runTest(authorizations, 2);
  }

  @Test
  public void test3() throws ParseException, IOException {
    DocumentAuthorizations authorizations = new DocumentAuthorizations("x");
    runTest(authorizations, 0);
  }

  private void runTest(DocumentAuthorizations authorizations, int expected) throws IOException, ParseException {
    IndexWriterConfig conf = new IndexWriterConfig(Version.LUCENE_43, new StandardAnalyzer(Version.LUCENE_43));
    Directory dir = new RAMDirectory();
    IndexWriter writer = new IndexWriter(dir, conf);
    writer.addDocument(getDoc("visible", "(a&b)|d"));
    writer.addDocument(getDoc("notvisible", "a&b&c"));
    writer.close();

    DirectoryReader reader = DirectoryReader.open(dir);
    IndexSearcher searcher = new IndexSearcher(reader);

    String queryStr = "cool";
    Query query = new QueryParser(Version.LUCENE_43, "body", new StandardAnalyzer(Version.LUCENE_43)).parse(queryStr);
    TopDocs topDocs = searcher.search(query, getFilter(authorizations), 10);

    assertEquals(expected, topDocs.totalHits);
    DocumentVisibilityEvaluator visibilityEvaluator = new DocumentVisibilityEvaluator(authorizations);
    for (int i = 0; i < topDocs.totalHits & i < topDocs.scoreDocs.length; i++) {
      Document doc = searcher.doc(topDocs.scoreDocs[i].doc);
      String vis = doc.get("visibility");
      assertTrue(visibilityEvaluator.evaluate(new DocumentVisibility(vis)));
    }
  }

  private Filter getFilter(DocumentAuthorizations authorizations) {
    return new DocumentVisibilityFilter("visibility", authorizations);
  }

  private Iterable<? extends IndexableField> getDoc(String value, String visibility) {
    Document doc = new Document();
    doc.add(new DocumentVisiblityField("visibility", new DocumentVisibility(visibility)));
    doc.add(new StringField("value", value, Store.YES));
    doc.add(new TextField("body", "cool beans", Store.YES));
    return doc;
  }

}