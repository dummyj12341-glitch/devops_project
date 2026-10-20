// Jenkins-Based DevSecOps Pipeline for Automated Vulnerability Detection
//
// Build -> Test -> Secret scan / SAST / SCA / IaC scan (parallel) -> DAST
//       -> HTML security report -> Security quality gate
//
// Runs on a Windows agent (bat steps). Scanner tools are installed into the
// workspace by scripts\setup_tools.ps1 on the first build and reused after.

pipeline {
    agent any

    parameters {
        choice(name: 'TARGET_APP', choices: ['app', 'app_secure'],
               description: 'app = intentionally vulnerable version, app_secure = remediated version')
        booleanParam(name: 'FAIL_ON_HIGH', defaultValue: true,
                     description: 'Fail the build when the quality gate fails (otherwise mark it UNSTABLE)')
    }

    triggers {
        // Poll the repository so every new commit is scanned automatically
        pollSCM('H/2 * * * *')
    }

    options {
        timestamps()
        timeout(time: 30, unit: 'MINUTES')
        buildDiscarder(logRotator(numToKeepStr: '20'))
        disableConcurrentBuilds()
    }

    environment {
        // exported explicitly so it is set even on the first run, before parameters are registered
        TARGET_APP = "${params.TARGET_APP ?: 'app'}"
        PYTHONDONTWRITEBYTECODE = '1'
        TOOLS    = "${WORKSPACE}\\tools"
        TOOLS_PY = "${WORKSPACE}\\.venv-tools\\Scripts"
        APP_VENV = "${WORKSPACE}\\.venv-${params.TARGET_APP}"
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                bat 'git log -1 --oneline'
            }
        }

        stage('Setup Tools') {
            steps {
                bat 'powershell -NoProfile -ExecutionPolicy Bypass -File scripts\\setup_tools.ps1'
                bat """
                    if not exist "%APP_VENV%\\Scripts\\python.exe" py -3 -m venv "%APP_VENV%"
                    "%APP_VENV%\\Scripts\\python.exe" -m pip install --quiet --disable-pip-version-check -r %TARGET_APP%\\requirements.txt pytest
                    if exist reports rmdir /s /q reports
                    mkdir reports
                """
            }
        }

        stage('Build & Unit Tests') {
            steps {
                bat '"%APP_VENV%\\Scripts\\python.exe" -m pytest tests -v -p no:cacheprovider --junitxml=reports\\junit.xml'
            }
            post {
                always { junit allowEmptyResults: true, testResults: 'reports/junit.xml' }
            }
        }

        stage('Security Scans') {
            // Scanners only record findings here; the Quality Gate decides pass/fail
            parallel {
                stage('Secret Scan - Gitleaks') {
                    steps {
                        bat '"%TOOLS%\\gitleaks.exe" dir %TARGET_APP% --config security\\.gitleaks.toml --report-format json --report-path reports\\gitleaks.json --no-banner --exit-code 0'
                    }
                }
                stage('SAST - Bandit') {
                    steps {
                        bat '"%TOOLS_PY%\\bandit.exe" -r %TARGET_APP% -f json -o reports\\bandit.json --exit-zero -q'
                    }
                }
                stage('SCA - pip-audit') {
                    steps {
                        script {
                            int rc = bat(returnStatus: true, script:
                                '"%TOOLS_PY%\\pip-audit.exe" -r %TARGET_APP%\\requirements.txt --no-deps --disable-pip -f json -o reports\\pip-audit.json --progress-spinner off')
                            echo(rc == 0 ? 'pip-audit: no known vulnerable dependencies' : 'pip-audit: vulnerable dependencies found')
                        }
                    }
                }
                stage('SCA/IaC - Trivy') {
                    steps {
                        bat '"%TOOLS%\\trivy.exe" fs --scanners vuln,secret,misconfig --cache-dir "%TOOLS%\\trivy-cache" --skip-dirs "**/__pycache__" --format json --output reports\\trivy.json --exit-code 0 --quiet %TARGET_APP%'
                    }
                }
            }
        }

        stage('DAST - Dynamic Scan') {
            steps {
                bat '"%TOOLS_PY%\\python.exe" security\\dast_probe.py --app-dir %TARGET_APP% --python "%APP_VENV%\\Scripts\\python.exe" --port 5050 --out reports\\dast.json'
            }
        }

        stage('Security Report') {
            steps {
                bat '"%TOOLS_PY%\\python.exe" security\\generate_report.py --reports reports'
            }
        }

        stage('Security Quality Gate') {
            steps {
                script {
                    int rc = bat(returnStatus: true, script: '"%TOOLS_PY%\\python.exe" security\\quality_gate.py --reports reports')
                    if (rc != 0) {
                        if (params.FAIL_ON_HIGH) {
                            error('Security quality gate FAILED - open "Security Report" on the build page for details')
                        } else {
                            unstable('Security quality gate failed (FAIL_ON_HIGH=false, marking UNSTABLE)')
                        }
                    }
                }
            }
        }
    }

    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            publishHTML(target: [
                reportName           : 'Security Report',
                reportDir            : 'reports',
                reportFiles          : 'security-report.html',
                keepAll              : true,
                alwaysLinkToLastBuild: true,
                allowMissing         : true
            ])
        }
        success  { echo "No blocking vulnerabilities in ${params.TARGET_APP} - safe to deploy." }
        unstable { echo "Vulnerabilities found in ${params.TARGET_APP} - review the Security Report." }
        failure  { echo "Build blocked: ${params.TARGET_APP} has CRITICAL/HIGH vulnerabilities." }
    }
}
