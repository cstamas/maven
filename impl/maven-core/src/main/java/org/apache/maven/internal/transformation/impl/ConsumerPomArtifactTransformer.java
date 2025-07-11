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
package org.apache.maven.internal.transformation.impl;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;
import javax.xml.stream.XMLStreamException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.concurrent.CopyOnWriteArraySet;

import org.apache.maven.api.feature.Features;
import org.apache.maven.api.model.Model;
import org.apache.maven.api.services.ModelBuilderException;
import org.apache.maven.project.MavenProject;
import org.apache.maven.project.artifact.ProjectArtifact;
import org.eclipse.aether.RepositorySystemSession;
import org.eclipse.aether.artifact.Artifact;
import org.eclipse.aether.artifact.DefaultArtifact;
import org.eclipse.aether.deployment.DeployRequest;
import org.eclipse.aether.installation.InstallRequest;
import org.eclipse.sisu.PreDestroy;

/**
 * Consumer POM transformer.
 *
 * @since TBD
 */
@Singleton
@Named
class ConsumerPomArtifactTransformer extends TransformerSupport {
    private static final String CONSUMER_POM_CLASSIFIER = "consumer";

    private static final String BUILD_POM_CLASSIFIER = "build";

    private final Set<Path> toDelete = new CopyOnWriteArraySet<>();

    private final PomBuilder builder;

    @Inject
    ConsumerPomArtifactTransformer(PomBuilder builder) {
        this.builder = builder;
    }

    @SuppressWarnings("deprecation")
    @Override
    public void injectTransformedArtifacts(RepositorySystemSession session, MavenProject project) throws IOException {
        if (project.getFile() == null) {
            // If there is no build POM there is no reason to inject artifacts for the consumer POM.
            return;
        }
        if (Features.consumerPom(session.getConfigProperties())) {
            Path buildDir =
                    project.getBuild() != null ? Paths.get(project.getBuild().getDirectory()) : null;
            if (buildDir != null) {
                Files.createDirectories(buildDir);
            }
            Path consumer = buildDir != null
                    ? Files.createTempFile(buildDir, CONSUMER_POM_CLASSIFIER + "-", ".pom")
                    : Files.createTempFile(CONSUMER_POM_CLASSIFIER + "-", ".pom");
            deferDeleteFile(consumer);

            project.addAttachedArtifact(createConsumerPomArtifact(project, consumer, session));
        } else if (project.getModel().getDelegate().isRoot()) {
            throw new IllegalStateException(
                    "The use of the root attribute on the model requires the buildconsumer feature to be active");
        }
    }

    TransformedArtifact createConsumerPomArtifact(
            MavenProject project, Path consumer, RepositorySystemSession session) {
        return new TransformedArtifact(
                this,
                project,
                consumer,
                session,
                new ProjectArtifact(project),
                () -> project.getFile().toPath(),
                CONSUMER_POM_CLASSIFIER,
                "pom");
    }

    @Override
    public void transform(MavenProject project, RepositorySystemSession session, Path src, Path tgt)
            throws ModelBuilderException, XMLStreamException, IOException {
        Model model = builder.build(session, project, src);
        write(model, tgt);
    }

    private void deferDeleteFile(Path generatedFile) {
        toDelete.add(generatedFile.toAbsolutePath());
    }

    @PreDestroy
    private void doDeleteFiles() {
        for (Path file : toDelete) {
            try {
                Files.delete(file);
            } catch (IOException e) {
                // ignore, we did our best...
            }
        }
    }

    @Override
    public InstallRequest remapInstallArtifacts(RepositorySystemSession session, InstallRequest request) {
        if (consumerPomPresent(request.getArtifacts())) {
            // For install, we always include build POMs as they may be needed locally
            request.setArtifacts(replacePom(request.getArtifacts(), true));
        }
        return request;
    }

    @Override
    public DeployRequest remapDeployArtifacts(RepositorySystemSession session, DeployRequest request) {
        if (consumerPomPresent(request.getArtifacts())) {
            boolean deployBuildPom = Features.deployBuildPom(session.getConfigProperties());
            request.setArtifacts(replacePom(request.getArtifacts(), deployBuildPom));
        }
        return request;
    }

    private boolean consumerPomPresent(Collection<Artifact> artifacts) {
        return artifacts.stream()
                .anyMatch(a -> "pom".equals(a.getExtension()) && CONSUMER_POM_CLASSIFIER.equals(a.getClassifier()));
    }

    private Collection<Artifact> replacePom(Collection<Artifact> artifacts, boolean deployBuildPom) {
        List<Artifact> consumers = new ArrayList<>();
        List<Artifact> mains = new ArrayList<>();
        for (Artifact artifact : artifacts) {
            if ("pom".equals(artifact.getExtension()) || artifact.getExtension().startsWith("pom.")) {
                if (CONSUMER_POM_CLASSIFIER.equals(artifact.getClassifier())) {
                    consumers.add(artifact);
                } else if ("".equals(artifact.getClassifier())) {
                    mains.add(artifact);
                }
            }
        }
        if (!mains.isEmpty() && !consumers.isEmpty()) {
            ArrayList<Artifact> result = new ArrayList<>(artifacts);
            for (Artifact main : mains) {
                result.remove(main);
                if (deployBuildPom) {
                    // Add the main POM as a build POM with "build" classifier
                    result.add(new DefaultArtifact(
                            main.getGroupId(),
                            main.getArtifactId(),
                            BUILD_POM_CLASSIFIER,
                            main.getExtension(),
                            main.getVersion(),
                            main.getProperties(),
                            main.getPath()));
                }
                // If deployBuildPom is false, we simply don't add the build POM to the result
            }
            for (Artifact consumer : consumers) {
                result.remove(consumer);
                // Replace the consumer POM as the main POM (no classifier)
                result.add(new DefaultArtifact(
                        consumer.getGroupId(),
                        consumer.getArtifactId(),
                        "",
                        consumer.getExtension(),
                        consumer.getVersion(),
                        consumer.getProperties(),
                        consumer.getPath()));
            }
            artifacts = result;
        }
        return artifacts;
    }
}
