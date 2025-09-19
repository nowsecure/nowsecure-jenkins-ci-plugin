package com.nowsecure.plugin;

import static org.junit.jupiter.api.Assertions.*;

import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.CredentialsStore;
import com.cloudbees.plugins.credentials.domains.Domain;
import com.nowsecure.models.AnalysisType;
import com.nowsecure.models.LogLevel;

import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.util.FormValidation;
import hudson.util.Secret;
import java.io.IOException;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

@WithJenkins
class NowSecurePluginTest {

    final String binaryFilePath = "./";
    final String group = "group";

    public void setupCredentials(JenkinsRule jenkins, String secretId, String secretText) throws IOException {
        var secret = Secret.fromString(secretText);
        StringCredentialsImpl credential =
                new StringCredentialsImpl(CredentialsScope.GLOBAL, secretId, "Test plain text credential", secret);
        CredentialsStore store =
                CredentialsProvider.lookupStores(jenkins.jenkins).iterator().next();
        store.addCredentials(Domain.global(), credential);
    }

    @Test
    void invalidCredentialIdShouldFail(JenkinsRule jenkins) throws Exception {
        FreeStyleProject project = jenkins.createFreeStyleProject();
        var builder = new NowSecurePlugin(binaryFilePath, group, "bad token credential id");
        project.getBuildersList().add(builder);
        var build = jenkins.buildAndAssertStatus(Result.FAILURE, project);
        jenkins.assertLogContains("Could not find a TextCredential matching the specified credentialId", build);
    }

    @Test
    void validCredentialIdShouldSucceed(JenkinsRule jenkins) throws Exception {
        FreeStyleProject project = jenkins.createFreeStyleProject();
        var id = "some-id";
        setupCredentials(jenkins, id, "some-text");
        var builder = new NowSecurePlugin(binaryFilePath, group, id);
        project.getBuildersList().add(builder);
        var build = jenkins.buildAndAssertStatus(Result.SUCCESS, project);
        jenkins.assertLogContains("Finished: SUCCESS", build);
    }

    @Test
    void shouldAllowUsersToOverrideURLs(JenkinsRule jenkins) throws Exception {
        var id = "some-id";
        setupCredentials(jenkins, id, "some-text");
        var nsStep = new NowSecurePlugin(binaryFilePath, group, id);

        var apiUrl = "https://httpbin.org/api";
        var uiUrl = "https://httpbin.org/ui";

        nsStep.setApiHost(apiUrl);
        nsStep.setUiHost(uiUrl);

        Assertions.assertEquals(apiUrl, nsStep.getApiHost());
        Assertions.assertEquals(uiUrl, nsStep.getUiHost());
    }

    @Test
    void shouldPersistUserConfigs(JenkinsRule jenkins) throws Exception {
        FreeStyleProject project = jenkins.createFreeStyleProject();
        var id = "some-id";
        setupCredentials(jenkins, id, "some-text");
        var nsStep = new NowSecurePlugin(binaryFilePath, group, id);

        var apiUrl = "https://httpbin.org/api";
        var uiUrl = "https://httpbin.org/ui";
        var artifactDir = "dir";
        var logLevel = LogLevel.WARN;
        var analysisType = AnalysisType.FULL;
        var minimumScore = 20;
        var pollingDurationMinutes = 30;

        nsStep.setApiHost(apiUrl);
        nsStep.setUiHost(uiUrl);
        nsStep.setArtifactDir(artifactDir);
        nsStep.setLogLevel(logLevel);
        nsStep.setAnalysisType(analysisType);
        nsStep.setMinimumScore(minimumScore);
        nsStep.setPollingDurationMinutes(pollingDurationMinutes);

        project.getBuildersList().add(nsStep);
        project = jenkins.configRoundtrip(project);

        NowSecurePlugin reloadedStep = project.getBuildersList().get(NowSecurePlugin.class);
        assertNotNull(reloadedStep);

        // Data bound constructor fields
        assertEquals(binaryFilePath, reloadedStep.getBinaryFilePath());
        assertEquals(group, reloadedStep.getGroup());
        assertEquals(id, reloadedStep.getTokenCredentialId());
        // Data bound setter fields
        assertEquals(apiUrl, reloadedStep.getApiHost());
        assertEquals(uiUrl, reloadedStep.getUiHost());
        assertEquals(artifactDir, reloadedStep.getArtifactDir());
        assertEquals(logLevel, reloadedStep.getLogLevel());
        assertEquals(analysisType, reloadedStep.getAnalysisType());
        assertEquals(minimumScore, reloadedStep.getMinimumScore());
        assertEquals(pollingDurationMinutes, reloadedStep.getPollingDurationMinutes());
    }

    // Descriptor Tests

    @Test
    void shouldErrorWhenInvalidURLsAreProvided(JenkinsRule jenkins) throws Exception {
        var descriptor = (NowSecurePlugin.DescriptorImpl) jenkins.jenkins.getDescriptor(NowSecurePlugin.class);
        var apiValidation = descriptor.doCheckApiHost("notAnApiUrl");
        var uiValidation = descriptor.doCheckUiHost("notaUiUrl");
        assertEquals(FormValidation.error("").kind, apiValidation.kind);
        assertEquals(FormValidation.error("").kind, uiValidation.kind);
    }
}
