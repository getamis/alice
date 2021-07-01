import groovy.transform.Field
import groovy.json.JsonSlurper

import hudson.AbortException
import org.jenkinsci.plugins.workflow.steps.FlowInterruptedException

// used for stopping previous builds
import hudson.model.Result
import jenkins.model.CauseOfInterruption.UserInterruption

@Library("jenkins-library@v0.21") _

@Field def packageName = "github.com/amis/alice"
@Field def packagePath = "src/${packageName}"

@Field def coverageGoal = "0.80"

if (env.CHANGE_TITLE) {
    currentBuild.rawBuild.project.setDisplayName("${env.BRANCH_NAME} | ${env.CHANGE_TITLE}")
}

properties([
    pipelineTriggers([
        issueCommentTrigger('go jenkins go')
    ]),
])

slack {
    channel = "#amis-build"
    credentialsId = "slack-amis"
    deployment {
        channel = "#amis-build"
    }
}

pipeline {
    agent { 
        kubernetes {
            label "alice-build-agent-${UUID.randomUUID()}"
            yamlFile "jenkins/go-agent-c1.yaml"
            defaultContainer "builder"
        }
    }

    options {
        timestamps()

        checkoutToSubdirectory(packagePath)

        timeout(time: 120, unit: 'MINUTES')

        skipStagesAfterUnstable()

        parallelsAlwaysFailFast()
    }

    post {
      failure {
        script {
          if(env.BRANCH_NAME == 'master'){
            slack.sendDeploymentNotification("${getTargetCluster()}", "@channel")
          } else {
            slack.sendPipelineNotification()
          }
        }
      }

      success {
        script {
          slack.sendPipelineNotification()
        }
      }
    }
    stages {
        stage('tests') {
            when {
                // Run this stage while any one of following conditions is TRUE
                anyOf {
                    // On master branch, force to run
                    branch "master"
                    // Genera case While env.SKIP_TESTS is not 'true'
                    expression { -> env.SKIP_TESTS != 'true' }
                }
            }
            post {
                failure {
                    script {
                        slack.sendTestNotification()
                    }
                }
                fixed {
                    script {
                        slack.sendTestNotification()
                    }
                }
                success {
                    script {
                        slack.sendTestNotification()
                    }
                }
            }
            parallel {
                stage ("build & lint") {
                    agent { 
                        kubernetes {
                            label "alice-build-agent-${UUID.randomUUID()}"
                            yamlFile "jenkins/go-agent-c1.yaml"
                            defaultContainer "builder"
                        }
                    }
                    steps {
                        withGoPackage(packageName) {
                            extractCache(prefix: "es", checksumFile: "go.sum", paths: [".mod"], s3: [bucket: 'base-devops-jenkins-cache',role: 'base-jenkins-es',]) {
                                withGoModuleLocal() {
                                    sh "go mod download"
                                }
                            }
                            withGoModuleLocal() {
                                sh "make tss-example && make lint"
                            }
                        }
                    }
                }

                stage ("tests") {
                    agent { 
                        kubernetes {
                            label "alice-test-agent-${UUID.randomUUID()}"
                            yamlFile "jenkins/go-agent-c2.yaml"
                            defaultContainer "builder"
                        }
                    }
                    post {
                        always {
                            withGoPackage(packageName) {
                                goCoverageReport "coverage.txt"
                                script {
                                    // This is a workaround. These env should be set by GitHub Pull Request Builder.
                                    // Mainly these 2 env will be used in publishCoverageGithub() call.
                                    //
                                    // In order to update status on HEAD commit for PR status check, commit id of HEAD is needed.
                                    // However, env.GIT_COMMIT actually equals to MERGE commit, not HEAD. So can't be used directly in this situation.
                                    env.ghprbGhRepository = "amis/alice"
                                    env.ghprbActualCommit = getOriginalHeadCommit()

                                    // if we are in a PR
                                    if (env.CHANGE_ID) {
                                        // publish coverage comparison result as Github PR status check
                                        publishCoverageGithub(filepath:'build/coverage/cobertura.xml', coverageXmlType: 'cobertura', comparisonOption: [ value: 'optionFixedCoverage', fixedCoverage: coverageGoal ], coverageRateType: 'Line')
                                    }
                                }
                            }
                        }
                    }
                    steps {
                        withGoPackage(packageName) {
                            extractCache(prefix: "es", checksumFile: "go.sum", paths: [".mod"], s3: [bucket: 'base-devops-jenkins-cache',role: 'base-jenkins-es',]) {
                                withGoModuleLocal() {
                                    sh "go mod download"
                                }
                            }
                            withGoModuleLocal() {
                                sh "make unit-test"
                            }
                        }
                    }
                }
            }
        }
    }
}
