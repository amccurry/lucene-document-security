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
package lucene.security.document;

import java.util.ArrayList;
import java.util.List;

import org.apache.lucene.document.Document;
import org.apache.lucene.document.SortedDocValuesField;
import org.apache.lucene.document.StoredField;
import org.apache.lucene.index.IndexableField;
import org.apache.lucene.util.BytesRef;

public class DocumentVisiblityUtil {

  public static final String DISCOVER_FIELD = "_discover_";
  public static final String READ_FIELD = "_read_";

  public static Iterable<IndexableField> addReadVisiblity(String read, Iterable<IndexableField> fields) {
    BytesRef value = new BytesRef(read);
    SortedDocValuesField docValueField = new SortedDocValuesField(READ_FIELD, value);
    StoredField storedField = new StoredField(READ_FIELD, value);
    return addField(fields, docValueField, storedField);
  }

  public static Iterable<IndexableField> addDiscoverVisiblity(String discover, Iterable<IndexableField> fields) {
    BytesRef value = new BytesRef(discover);
    SortedDocValuesField docValueField = new SortedDocValuesField(DISCOVER_FIELD, value);
    StoredField storedField = new StoredField(DISCOVER_FIELD, value);
    return addField(fields, docValueField, storedField);
  }

  private static Iterable<IndexableField> addField(Iterable<IndexableField> fields, SortedDocValuesField field,
      StoredField storedField) {
    if (fields instanceof Document) {
      Document document = (Document) fields;
      document.add(field);
      document.add(storedField);
      return document;
    }
    List<IndexableField> list = new ArrayList<IndexableField>();
    for (IndexableField indexableField : fields) {
      list.add(indexableField);
    }
    list.add(field);
    list.add(storedField);
    return list;
  }

}
