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

import java.util.Set;

import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.collection.DependencyCollectionContext;
import org.eclipse.aether.collection.DependencySelector;
import org.eclipse.aether.graph.Dependency;

/**
 * Assists in resolving the dependencies of a plugin by filtering out core dependencies.
 *
 * @since TBD
 */
public final class PluginDependencySelector
    implements DependencySelector
{
    private final Set<String> coreArtifacts;

    public PluginDependencySelector( final Set<String> coreArtifacts )
    {
        this.coreArtifacts = coreArtifacts;
    }

    @Override
    public boolean selectDependency( final Dependency dependency )
    {
        Artifact artifact = dependency.getArtifact();
        return !coreArtifacts.contains( artifact.getGroupId() + ":" + artifact.getArtifactId() );
    }

    @Override
    public DependencySelector deriveChildSelector( final DependencyCollectionContext dependencyCollectionContext )
    {
        return this;
    }

    @Override
    public boolean equals( Object obj )
    {
        if ( obj == this )
        {
            return true;
        }
        else if ( obj == null || !getClass().equals( obj.getClass() ) )
        {
            return false;
        }

        PluginDependencySelector that = (PluginDependencySelector) obj;
        return coreArtifacts.equals( that.coreArtifacts );
    }

    @Override
    public int hashCode()
    {
        return getClass().hashCode() * 31 + coreArtifacts.hashCode();
    }
}
