// Jenkins-Based DevSecOps Pipeline for Automated Vulnerability Detection
//
// Jenkins + Docker + SonarQube + Kubernetes (kind):
//
// Checkout -> Unit tests + coverage
//   -> Static analysis in parallel: Gitleaks | Bandit | pip-audit | Trivy fs | Trivy k8s manifest | SonarQube
//   -> SonarQube quality gate -> Docker build -> Trivy image scan
//   -> Deploy to Kubernetes "staging" -> DAST (probe + OWASP ZAP) against staging
//   -> Security report -> Security gate -> promote to "production"  (or roll back staging)
//
// Runs on the Jenkins container from infra/docker-compose.yml, which has the
// tools installed and talks to Docker Desktop and the kind cluster.

pipeline {
    agent any

    parameters {
        choice(name: 'TARGET_APP', choices: ['app', 'app_secure'],
               description: 'app = intentionally vulnerable version, app_secure = remediated version')
        booleanParam(name: 'FAIL_ON_HIGH', defaultValue: true,
                     description: 'Fail the build when the security gate fails (otherwise mark it UNSTABLE)')
    }

    triggers {
        // Poll the repository so every new commit is scanned automatically
        pollSCM('H/2 * * * *')
    }

    options {
        timestamps()
        timeout(time: 45, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        // exported explicitly so it is set even on the first run, before parameters are registered
        TARGET_APP    = "${params.TARGET_APP ?: 'app'}"
        PYTHONDONTWRITEBYTECODE = '1'
        APP_VENV      = "${WORKSPACE}/.venv-${params.TARGET_APP ?: 'app'}"
        IMAGE         = "devsecops-${params.TARGET_APP ?: 'app'}:${BUILD_NUMBER}"
        SONAR_PROJECT = "devsecops-${params.TARGET_APP ?: 'app'}"
        KIND_NODE     = "${env.KIND_CLUSTER ?: 'devsecops'}-control-plane"
        STAGING_URL   = "http://${env.KIND_CLUSTER ?: 'devsecops'}-control-plane:30080"
        TRIVY_CACHE   = "/var/jenkins_home/trivy-cache"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                sh 'git log -1 --oneline && rm -rf reports && mkdir -p reports build'
            }
        }

        stage('Build & Unit Tests') {
            steps {
                sh '''
                    [ -x "$APP_VENV/bin/python" ] || python3 -m venv "$APP_VENV"
                    "$APP_VENV/bin/pip" install --quiet --disable-pip-version-check -r "$TARGET_APP/requirements.txt" pytest pytest-cov
                    "$APP_VENV/bin/python" -m pytest tests -v -p no:cacheprovider \
                        --junitxml=reports/junit.xml --cov="$TARGET_APP" --cov-report=xml:reports/coverage.xml
                '''
            }
            post {
                always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' }
            }
        }

        stage('Static Analysis') {
            // Scanners only record findings here; the Security Gate decides pass/fail
            parallel {
                stage('Secrets - Gitleaks') {
                    steps {
                        sh 'gitleaks dir "$TARGET_APP" --config security/.gitleaks.toml --report-format json --report-path reports/gitleaks.json --no-banner --exit-code 0'
                    }
                }
                stage('SAST - Bandit') {
                    steps {
                        sh 'bandit -r "$TARGET_APP" -f json -o reports/bandit.json --exit-zero -q'
                    }
                }
                stage('SCA - pip-audit') {
                    steps {
                        script {
                            int rc = sh(returnStatus: true, script:
                                'pip-audit -r "$TARGET_APP/requirements.txt" --no-deps --disable-pip -f json -o reports/pip-audit.json --progress-spinner off')
                            echo(rc == 0 ? 'pip-audit: no known vulnerable dependencies' : 'pip-audit: vulnerable dependencies found')
                        }
                    }
                }
                stage('SCA/IaC - Trivy fs') {
                    steps {
                        sh 'trivy fs --scanners vuln,secret,misconfig --cache-dir "$TRIVY_CACHE" --skip-dirs "**/__pycache__" --format json --output reports/trivy.json --exit-code 0 --quiet "$TARGET_APP"'
                    }
                }
                stage('K8s manifest - Trivy') {
                    steps {
                        // render the manifest exactly as it will be deployed, then scan it
                        sh '''
                            sed -e "s|__IMAGE__|$IMAGE|" -e "s|__NODEPORT__|30080|" "k8s/$TARGET_APP/deployment.yaml" > build/k8s-staging.yaml
                            trivy config --cache-dir "$TRIVY_CACHE-config" --format json --output reports/trivy-k8s.json --exit-code 0 --quiet build/k8s-staging.yaml
                        '''
                    }
                }
                stage('SAST/Quality - SonarQube') {
                    steps {
                        withSonarQubeEnv('sonarqube') {
                            sh '''
                                sonar-scanner -Dsonar.projectKey="$SONAR_PROJECT" -Dsonar.projectName="DevSecOps $TARGET_APP" \
                                    -Dsonar.sources="$TARGET_APP" -Dsonar.python.coverage.reportPaths=reports/coverage.xml \
                                    -Dsonar.scanner.skipJreProvisioning=true
                            '''
                        }
                    }
                }
            }
        }

        stage('SonarQube Quality Gate') {
            steps {
                timeout(time: 5, unit: 'MINUTES') {
                    script {
                        def qg = waitForQualityGate abortPipeline: false
                        echo "SonarQube quality gate: ${qg.status}"
                    }
                }
                withSonarQubeEnv('sonarqube') {
                    sh 'python3 security/export_sonar.py --project "$SONAR_PROJECT" --out reports/sonarqube.json'
                }
            }
        }

        stage('Docker Build') {
            steps {
                sh 'docker build -t "$IMAGE" "$TARGET_APP"'
            }
        }

        stage('Image Scan - Trivy') {
            steps {
                // OS packages of the image; app dependencies are covered by pip-audit/Trivy fs.
                // --ignore-unfixed: only report CVEs that have a patched version available
                sh 'trivy image --cache-dir "$TRIVY_CACHE" --pkg-types os --ignore-unfixed --format json --output reports/trivy-image.json --exit-code 0 --quiet "$IMAGE"'
            }
        }

        stage('Deploy to Staging') {
            steps {
                sh '''
                    kind load docker-image "$IMAGE" --name "${KIND_CLUSTER:-devsecops}"
                    kubectl apply -n staging -f build/k8s-staging.yaml
                    kubectl -n staging rollout status deployment/devsecops-app --timeout=180s
                    kubectl -n staging get pods -o wide
                '''
            }
        }

        stage('DAST') {
            parallel {
                stage('DAST probe') {
                    steps {
                        sh 'python3 security/dast_probe.py --target-url "$STAGING_URL" --out reports/dast.json'
                    }
                }
                stage('OWASP ZAP baseline') {
                    steps {
                        script {
                            // ZAP runs as a container on the kind network; reports are copied out afterwards
                            int rc = sh(returnStatus: true, script: '''
                                docker rm -f "zap-$BUILD_TAG" >/dev/null 2>&1 || true
                                docker run --name "zap-$BUILD_TAG" --network kind -v "zap-$BUILD_TAG:/zap/wrk" \
                                    zaproxy/zap-stable:2.17.0 zap-baseline.py -t "$STAGING_URL" -J zap.json -I
                            ''')
                            sh '''
                                docker cp "zap-$BUILD_TAG:/zap/wrk/zap.json" reports/zap.json || echo "ZAP report not produced"
                                docker rm -f "zap-$BUILD_TAG" >/dev/null 2>&1 || true
                                docker volume rm "zap-$BUILD_TAG" >/dev/null 2>&1 || true
                            '''
                            echo "ZAP baseline finished with exit code ${rc}"
                        }
                    }
                }
            }
        }

        stage('Security Report') {
            steps {
                sh 'python3 security/generate_report.py --reports reports'
            }
        }

        stage('Security Gate') {
            steps {
                script {
                    int rc = sh(returnStatus: true, script: 'python3 security/quality_gate.py --reports reports')
                    env.GATE_PASSED = (rc == 0).toString()
                    if (rc != 0) {
                        // keep vulnerable releases out of the cluster
                        sh 'kubectl -n staging delete deployment devsecops-app --ignore-not-found'
                        if (params.FAIL_ON_HIGH) {
                            error('Security gate FAILED - release removed from staging, not promoted. Open "Security Report" for details')
                        } else {
                            unstable('Security gate failed (FAIL_ON_HIGH=false, marking UNSTABLE, not promoted)')
                        }
                    }
                }
            }
        }

        stage('Promote to Production') {
            when { expression { env.GATE_PASSED == 'true' } }
            steps {
                sh '''
                    sed -e "s|__IMAGE__|$IMAGE|" -e "s|__NODEPORT__|30081|" "k8s/$TARGET_APP/deployment.yaml" > build/k8s-production.yaml
                    kubectl apply -n production -f build/k8s-production.yaml
                    kubectl -n production rollout status deployment/devsecops-app --timeout=180s
                    kubectl -n production get pods -o wide
                '''
            }
        }
    }

    post {
        always {
            script {
                // record the rollout outcome in the report, then regenerate it
                def promoted = currentBuild.currentResult == 'SUCCESS' && env.GATE_PASSED == 'true'
                writeJSON file: 'reports/deploy.json', json: [
                    image          : env.IMAGE,
                    staging        : env.GATE_PASSED == 'true' ? 'deployed, DAST scanned' : 'deployed for DAST, then removed (gate failed)',
                    production     : promoted ? 'promoted' : 'blocked',
                    staging_url    : 'http://localhost:30080',
                    production_url : 'http://localhost:30081',
                    sonar_dashboard: "http://localhost:9000/dashboard?id=${env.SONAR_PROJECT}",
                ]
                sh 'python3 security/generate_report.py --reports reports || true'
            }
            archiveArtifacts artifacts: 'reports/**, build/**', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [
                reportName           : 'Security Report',
                reportDir            : 'reports',
                reportFiles          : 'security-report.html',
                keepAll              : true,
                alwaysLinkToLastBuild: true,
                allowMissing         : true
            ])
        }
        success  { echo "No blocking vulnerabilities in ${env.TARGET_APP} - promoted to production (http://localhost:30081)." }
        unstable { echo "Vulnerabilities found in ${env.TARGET_APP} - review the Security Report." }
        failure  { echo "Build blocked: ${env.TARGET_APP} did not reach production." }
    }
}
