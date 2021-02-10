package org.apache.maven.plugin.internal;

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

import java.util.List;
import java.util.Set;

import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.graph.DependencyFilter;
import org.eclipse.aether.graph.DependencyNode;

/**
 * Assists in resolving the dependencies of a plugin by filtering out core dependencies.
 *
 * @since TBD
 */
public final class PluginDependencyFilter
    implements DependencyFilter
{
    private final Set<String> coreArtifacts;

    public PluginDependencyFilter( final Set<String> coreArtifacts )
    {
        this.coreArtifacts = coreArtifacts;
    }

    @Override
    public boolean accept( final DependencyNode dependencyNode, final List<DependencyNode> list )
    {
        Artifact artifact = dependencyNode.getArtifact();
        return !coreArtifacts.contains( artifact.getGroupId() + ":" + artifact.getArtifactId() );
    }
}
