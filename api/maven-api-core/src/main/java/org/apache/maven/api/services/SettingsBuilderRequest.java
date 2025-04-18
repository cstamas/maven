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
package org.apache.maven.api.services;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Objects;
import java.util.Optional;
import java.util.function.UnaryOperator;

import org.apache.maven.api.ProtoSession;
import org.apache.maven.api.annotations.Experimental;
import org.apache.maven.api.annotations.Immutable;
import org.apache.maven.api.annotations.Nonnull;
import org.apache.maven.api.annotations.NotThreadSafe;
import org.apache.maven.api.annotations.Nullable;

import static java.util.Objects.requireNonNull;

/**
 * Collects settings that control the building of effective settings.
 */
@Experimental
@Immutable
public interface SettingsBuilderRequest extends Request<ProtoSession> {

    /**
     * Gets the installation settings source.
     *
     * @return the installation settings source or {@code null} if none
     */
    @Nonnull
    Optional<Source> getInstallationSettingsSource();

    /**
     * Gets the project settings source.
     *
     * @return the project settings source or {@code null} if none
     */
    @Nonnull
    Optional<Source> getProjectSettingsSource();

    /**
     * Gets the user settings source.
     *
     * @return the user settings source or {@code null} if none
     */
    @Nonnull
    Optional<Source> getUserSettingsSource();

    /**
     * The optional interpolation source used for interpolation.
     *
     * @return the interpolation source for interpolation
     */
    @Nonnull
    Optional<UnaryOperator<String>> getInterpolationSource();

    @Nonnull
    static SettingsBuilderRequest build(
            @Nonnull ProtoSession session,
            @Nonnull Source installationSettingsSource,
            @Nonnull Source userSettingsSource) {
        return build(session, installationSettingsSource, null, userSettingsSource);
    }

    @Nonnull
    static SettingsBuilderRequest build(
            @Nonnull ProtoSession session, @Nonnull Path installationSettingsPath, @Nonnull Path userSettingsPath) {
        return build(session, Sources.fromPath(installationSettingsPath), null, Sources.fromPath(userSettingsPath));
    }

    @Nonnull
    static SettingsBuilderRequest build(
            @Nonnull ProtoSession session,
            @Nullable Source installationSettingsSource,
            @Nullable Source projectSettingsSource,
            @Nullable Source userSettingsSource) {
        return builder()
                .session(requireNonNull(session, "session cannot be null"))
                .installationSettingsSource(installationSettingsSource)
                .projectSettingsSource(projectSettingsSource)
                .userSettingsSource(userSettingsSource)
                .build();
    }

    @Nonnull
    static SettingsBuilderRequest build(
            @Nonnull ProtoSession session,
            @Nullable Path installationSettingsPath,
            @Nullable Path projectSettingsPath,
            @Nullable Path userSettingsPath) {
        return builder()
                .session(requireNonNull(session, "session cannot be null"))
                .installationSettingsSource(
                        installationSettingsPath != null && Files.exists(installationSettingsPath)
                                ? Sources.fromPath(installationSettingsPath)
                                : null)
                .projectSettingsSource(
                        projectSettingsPath != null && Files.exists(projectSettingsPath)
                                ? Sources.fromPath(projectSettingsPath)
                                : null)
                .userSettingsSource(
                        userSettingsPath != null && Files.exists(userSettingsPath)
                                ? Sources.fromPath(userSettingsPath)
                                : null)
                .build();
    }

    @Nonnull
    static SettingsBuilderRequestBuilder builder() {
        return new SettingsBuilderRequestBuilder();
    }

    @NotThreadSafe
    class SettingsBuilderRequestBuilder {
        ProtoSession session;
        RequestTrace trace;
        Source installationSettingsSource;
        Source projectSettingsSource;
        Source userSettingsSource;
        UnaryOperator<String> interpolationSource;

        public SettingsBuilderRequestBuilder session(ProtoSession session) {
            this.session = session;
            return this;
        }

        public SettingsBuilderRequestBuilder trace(RequestTrace trace) {
            this.trace = trace;
            return this;
        }

        public SettingsBuilderRequestBuilder installationSettingsSource(Source installationSettingsSource) {
            this.installationSettingsSource = installationSettingsSource;
            return this;
        }

        public SettingsBuilderRequestBuilder projectSettingsSource(Source projectSettingsSource) {
            this.projectSettingsSource = projectSettingsSource;
            return this;
        }

        public SettingsBuilderRequestBuilder userSettingsSource(Source userSettingsSource) {
            this.userSettingsSource = userSettingsSource;
            return this;
        }

        public SettingsBuilderRequestBuilder interpolationSource(UnaryOperator<String> interpolationSource) {
            this.interpolationSource = interpolationSource;
            return this;
        }

        public SettingsBuilderRequest build() {
            return new DefaultSettingsBuilderRequest(
                    session,
                    trace,
                    installationSettingsSource,
                    projectSettingsSource,
                    userSettingsSource,
                    interpolationSource);
        }

        private static class DefaultSettingsBuilderRequest extends BaseRequest<ProtoSession>
                implements SettingsBuilderRequest {
            private final Source installationSettingsSource;
            private final Source projectSettingsSource;
            private final Source userSettingsSource;
            private final UnaryOperator<String> interpolationSource;

            @SuppressWarnings("checkstyle:ParameterNumber")
            DefaultSettingsBuilderRequest(
                    @Nonnull ProtoSession session,
                    @Nullable RequestTrace trace,
                    @Nullable Source installationSettingsSource,
                    @Nullable Source projectSettingsSource,
                    @Nullable Source userSettingsSource,
                    @Nullable UnaryOperator<String> interpolationSource) {
                super(session, trace);
                this.installationSettingsSource = installationSettingsSource;
                this.projectSettingsSource = projectSettingsSource;
                this.userSettingsSource = userSettingsSource;
                this.interpolationSource = interpolationSource;
            }

            @Nonnull
            @Override
            public Optional<Source> getInstallationSettingsSource() {
                return Optional.ofNullable(installationSettingsSource);
            }

            @Nonnull
            @Override
            public Optional<Source> getProjectSettingsSource() {
                return Optional.ofNullable(projectSettingsSource);
            }

            @Nonnull
            @Override
            public Optional<Source> getUserSettingsSource() {
                return Optional.ofNullable(userSettingsSource);
            }

            @Nonnull
            @Override
            public Optional<UnaryOperator<String>> getInterpolationSource() {
                return Optional.ofNullable(interpolationSource);
            }

            @Override
            public boolean equals(Object o) {
                return o instanceof DefaultSettingsBuilderRequest that
                        && Objects.equals(installationSettingsSource, that.installationSettingsSource)
                        && Objects.equals(projectSettingsSource, that.projectSettingsSource)
                        && Objects.equals(userSettingsSource, that.userSettingsSource)
                        && Objects.equals(interpolationSource, that.interpolationSource);
            }

            @Override
            public int hashCode() {
                return Objects.hash(
                        installationSettingsSource, projectSettingsSource, userSettingsSource, interpolationSource);
            }

            @Override
            public String toString() {
                return "SettingsBuilderRequest[" + "installationSettingsSource="
                        + installationSettingsSource + ", projectSettingsSource="
                        + projectSettingsSource + ", userSettingsSource="
                        + userSettingsSource + ", interpolationSource="
                        + interpolationSource + ']';
            }
        }
    }
}
