package com.nowsecure.plugin;

import com.cloudbees.plugins.credentials.CredentialsMatchers;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import com.cloudbees.plugins.credentials.common.StandardCredentials;
import com.cloudbees.plugins.credentials.common.StandardListBoxModel;
import com.cloudbees.plugins.credentials.domains.DomainRequirement;
import com.nowsecure.models.AnalysisType;
import com.nowsecure.models.LogLevel;
import com.nowsecure.models.NowSecureBinary;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Util;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.FormValidation;
import hudson.util.ListBoxModel;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.util.Collections;
import java.util.Optional;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;
import org.kohsuke.stapler.verb.POST;
import org.apache.commons.lang3.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.QueryParameter;

public class NowSecurePlugin extends Builder implements SimpleBuildStep {
    // Required
    private final String binaryFilePath;
    private final String group;
    // Note: this is a Credential ID, not the actual token
    // For information on Credentials see the following
    // https://github.com/jenkinsci/credentials-plugin/blob/master/docs/consumer.adoc
    private final String tokenCredentialId;

    private String artifactDir = "nowsecure";
    private String apiHost = "https://lab-api.nowsecure.com";
    private String uiHost = "https://app.nowsecure.com";
    private String nowsecureCIVersion;

    private LogLevel logLevel = LogLevel.INFO;
    private AnalysisType analysisType = AnalysisType.STATIC;

    private int minimumScore = -1;
    private int pollingDurationMinutes = 20;

    @DataBoundConstructor
    public NowSecurePlugin(String binaryFilePath, String group, String tokenCredentialId) {
        this.binaryFilePath = Util.fixEmptyAndTrim(binaryFilePath);
        this.group = Util.fixEmptyAndTrim(group);
        this.tokenCredentialId = Util.fixEmptyAndTrim(tokenCredentialId);
    }

    private Optional<StringCredentials> getCredentials(String credentialsId) {
        return CredentialsMatchers.filter(
                        CredentialsProvider.lookupCredentialsInItemGroup(
                                StringCredentials.class,
                                Jenkins.get(),
                                hudson.security.ACL.SYSTEM2,
                                Collections.<DomainRequirement>emptyList()),
                        CredentialsMatchers.withId(credentialsId))
                .stream()
                .findFirst();
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
            throws InterruptedException, IOException {
        final var arch = System.getProperty("os.arch");
        final var osName = System.getProperty("os.name");
        final var binaryFile = workspace.child(binaryFilePath);
        final var optionalCredentials = getCredentials(tokenCredentialId);

        if (!binaryFile.exists()) {
            var errorMessage = String.format("Cannot find binary file at path: %s", binaryFile.toURI());
            listener.error(errorMessage);
            run.setResult(hudson.model.Result.FAILURE);
            throw new AbortException(errorMessage);
        }

        if (optionalCredentials.isEmpty()) {
            var errorMessage = "Could not find a TextCredential matching the specified credentialId";
            listener.error(errorMessage);
            run.setResult(hudson.model.Result.FAILURE);
            throw new AbortException(errorMessage);
        }

        // According to docs, this is our responsibility to do for credential tracking:
        // https://github.com/jenkinsci/credentials-plugin/blob/master/docs/consumer.adoc#track-usage-of-a-credential-against-specific-jenkins-context-objects
        final var credential = optionalCredentials.get();
        CredentialsProvider.track(run, credential);

        final var token = credential.getSecret().getPlainText();

        final var tool = new NowSecureBinary(arch, osName, workspace)
                .addArgument("run")
                .addArgument("file", binaryFile.toURI().getPath())
                .addArgument("--group-ref", group)
                .addArgument("--api-host", apiHost)
                .addArgument("--ui-host", uiHost)
                .addArgument("--log-level", logLevel.toString().toLowerCase())
                .addArgument("--analysis-type", analysisType.toString().toLowerCase())
                .addArgument("--save-findings")
                .addArgument("--artifacts-dir", artifactDir)
                .addArgument("--output", String.format("%s%sassessment.json", artifactDir, File.pathSeparator))
                .addArgument("--minimum-score", String.valueOf(minimumScore))
                .addArgument("--poll-for-minutes", String.valueOf(pollingDurationMinutes))
                .addArgument("--ci-environment", "jenkins")
                .addToken(token);

        final var exitCode = tool.startProc(launcher, listener).join();

        if (exitCode != 0) {
            listener.getLogger().println("Exit Code: " + exitCode);
            run.setResult(hudson.model.Result.FAILURE);
            throw new AbortException("NowSecure binary finished with nonzero exit code");
        }
    }

    // should be a plugin-unique camel-cased identifier used by workflows
    @Symbol("nowsecureAssessment")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return "NowSecure Assessment Configuration";
        }

        // Has to be of the form 'doCheck<FieldName>'
        // The @QueryParameter annotation injects the value from the form field.
        public FormValidation doCheckBinaryFile(@QueryParameter String binaryFile) {
            if (StringUtils.isBlank(binaryFile)) {
                return FormValidation.error("Target Filename cannot be empty.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckGroup(@QueryParameter String group) {
            if (StringUtils.isBlank(group)) {
                return FormValidation.error("Group Ref cannot be empty.");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckTokenCredentialItems(@QueryParameter String tokenCredentialId) {
            if (StringUtils.isBlank(tokenCredentialId)) {
                return FormValidation.error("Token Credential cannot be empty");
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckApiHost(@QueryParameter String apiHost) {
            if (!StringUtils.isBlank(apiHost)) {
                try {
                    new URI(apiHost).toURL();
                } catch (Exception e) {
                    return FormValidation.error("Cannot be converted to a valid URL");
                }
            }
            return FormValidation.ok();
        }

        public FormValidation doCheckUiHost(@QueryParameter String uiHost) {
            if (!StringUtils.isBlank(uiHost)) {
                try {
                    new URI(uiHost).toURL();
                } catch (Exception e) {
                    return FormValidation.error("Cannot be converted to a valid URL");
                }
            }
            return FormValidation.ok();
        }


        @POST // Has to be of the form 'doFill<FieldName>Items'
        public ListBoxModel doFillTokenCredentialIdItems(
                @AncestorInPath Item item, @QueryParameter String tokenCredentialId) {
            StandardListBoxModel result = new StandardListBoxModel();
            if (item == null) {
                if (!Jenkins.get().hasPermission(Jenkins.ADMINISTER)) {
                    return result.includeCurrentValue(tokenCredentialId);
                }
            } else {
                if (!item.hasPermission(Item.EXTENDED_READ)) {
                    return result.includeCurrentValue(tokenCredentialId);
                }
            }

            return result.includeMatchingAs(
                            hudson.security.ACL.SYSTEM2,
                            Jenkins.get(),
                            StandardCredentials.class,
                            Collections.emptyList(), // No domain requirements
                            CredentialsMatchers.always())
                    .includeCurrentValue(tokenCredentialId);
        }
    }

    @DataBoundSetter
    public void setAnalysisType(AnalysisType analysisType) {
        this.analysisType = analysisType;
    }

    @DataBoundSetter
    public void setLogLevel(LogLevel logLevel) {
        this.logLevel = logLevel;
    }

    @DataBoundSetter
    public void setArtifactDir(String artifactDir) {
        var fixed = Util.fixEmptyAndTrim(artifactDir);
        if (fixed != null) {
            this.artifactDir = fixed;
        }
    }

    @DataBoundSetter
    public void setApiHost(String apiHost) {
        var fixed = Util.fixEmptyAndTrim(apiHost);
        if (fixed != null) {
            this.apiHost = fixed;
        }
    }

    @DataBoundSetter
    public void setUiHost(String uiHost) {
        var fixed = Util.fixEmptyAndTrim(uiHost);
        if (fixed != null) {
            this.uiHost = fixed;
        }
    }

    @DataBoundSetter
    public void setNowsecureCIVersion(String nowsecureCIVersion) {
        this.nowsecureCIVersion = nowsecureCIVersion;
    }

    @DataBoundSetter
    public void setMinimumScore(int minimumScore) {
        this.minimumScore = minimumScore;
    }

    @DataBoundSetter
    public void setPollingDurationMinutes(int pollingDurationMinutes) {
        this.pollingDurationMinutes = pollingDurationMinutes;
    }

	public String getBinaryFilePath() {
		return binaryFilePath;
	}

	public String getGroup() {
		return group;
	}

	public String getTokenCredentialId() {
		return tokenCredentialId;
	}

	public String getArtifactDir() {
		return artifactDir;
	}

	public String getApiHost() {
		return apiHost;
	}

	public String getUiHost() {
		return uiHost;
	}

	public String getNowsecureCIVersion() {
		return nowsecureCIVersion;
	}

	public LogLevel getLogLevel() {
		return logLevel;
	}

	public AnalysisType getAnalysisType() {
		return analysisType;
	}

	public int getMinimumScore() {
		return minimumScore;
	}

	public int getPollingDurationMinutes() {
		return pollingDurationMinutes;
	}

}
