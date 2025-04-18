/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.maven.impl;

import java.util.AbstractList;
import java.util.List;
import java.util.function.Function;

import static java.util.Objects.requireNonNull;

public class MappedList<U, V> extends AbstractList<U> {
    private final List<V> list;
    private final Function<V, U> mapper;

    public MappedList(List<V> list, Function<V, U> mapper) {
        this.list = requireNonNull(list, "list");
        this.mapper = requireNonNull(mapper, "mapper");
    }

    @Override
    public U get(int index) {
        return mapper.apply(list.get(index));
    }

    @Override
    public int size() {
        return list.size();
    }
}
