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
package org.apache.maven.cling.invoker.mvnenc;

import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.ParseException;
import org.apache.maven.api.cli.Options;
import org.apache.maven.api.cli.ParserRequest;
import org.apache.maven.api.cli.mvnenc.EncryptOptions;
import org.apache.maven.cling.invoker.CommonsCliOptions;

/**
 * Implementation of {@link EncryptOptions} (base + mvnenc).
 */
public class CommonsCliEncryptOptions extends CommonsCliOptions implements EncryptOptions {
    public static CommonsCliEncryptOptions parse(String[] args) throws ParseException {
        CLIManager cliManager = new CLIManager();
        return new CommonsCliEncryptOptions(Options.SOURCE_CLI, cliManager, cliManager.parse(args));
    }

    protected CommonsCliEncryptOptions(String source, CLIManager cliManager, CommandLine commandLine) {
        super(source, cliManager, commandLine);
    }

    @Override
    public Optional<Boolean> force() {
        if (commandLine.hasOption(CLIManager.FORCE)) {
            return Optional.of(Boolean.TRUE);
        }
        return Optional.empty();
    }

    @Override
    public Optional<Boolean> yes() {
        if (commandLine.hasOption(CLIManager.YES)) {
            return Optional.of(Boolean.TRUE);
        }
        return Optional.empty();
    }

    @Override
    public Optional<List<String>> goals() {
        if (!commandLine.getArgList().isEmpty()) {
            return Optional.of(commandLine.getArgList());
        }
        return Optional.empty();
    }

    @Override
    public void displayHelp(ParserRequest request, Consumer<String> printStream) {
        super.displayHelp(request, printStream);
        printStream.accept("");
        // we have no DI here (to discover)
        printStream.accept("Goals:");
        printStream.accept("  diag - display encryption configuration diagnostic");
        printStream.accept("  init - wizard to configure encryption (interactive only)");
        printStream.accept("  encrypt - encrypts input");
        printStream.accept("  decrypt - decrypts encrypted input");
        printStream.accept("");
    }

    @Override
    protected CommonsCliEncryptOptions copy(
            String source, CommonsCliOptions.CLIManager cliManager, CommandLine commandLine) {
        return new CommonsCliEncryptOptions(source, (CLIManager) cliManager, commandLine);
    }

    protected static class CLIManager extends CommonsCliOptions.CLIManager {
        public static final String FORCE = "f";
        public static final String YES = "y";

        @Override
        protected void prepareOptions(org.apache.commons.cli.Options options) {
            super.prepareOptions(options);
            options.addOption(Option.builder(FORCE)
                    .longOpt("force")
                    .desc("Should overwrite without asking any configuration?")
                    .build());
            options.addOption(Option.builder(YES)
                    .longOpt("yes")
                    .desc("Should imply user answered \"yes\" to all incoming questions?")
                    .build());
        }
    }
}
