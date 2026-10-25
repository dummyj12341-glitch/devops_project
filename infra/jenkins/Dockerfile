# Jenkins controller with every tool the DevSecOps pipeline needs baked in:
# docker CLI (talks to Docker Desktop through the mounted socket), kubectl,
# kind, Python, Trivy, Gitleaks and the SonarQube scanner.
FROM jenkins/jenkins:2.580.1-lts-jdk21

ARG KUBECTL_VERSION=1.37.1
ARG KIND_VERSION=0.33.0
ARG TRIVY_VERSION=0.76.0
ARG GITLEAKS_VERSION=8.30.1
ARG SONAR_SCANNER_VERSION=8.2.0.6438

USER root
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg unzip python3 python3-venv python3-pip \
 && install -m 0755 -d /etc/apt/keyrings \
 && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
 && echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo $VERSION_CODENAME) stable" > /etc/apt/sources.list.d/docker.list \
 && apt-get update \
 && apt-get install -y --no-install-recommends docker-ce-cli docker-buildx-plugin \
 && rm -rf /var/lib/apt/lists/*

RUN curl -fsSLo /usr/local/bin/kubectl "https://dl.k8s.io/release/v${KUBECTL_VERSION}/bin/linux/amd64/kubectl" \
 && curl -fsSLo /usr/local/bin/kind "https://github.com/kubernetes-sigs/kind/releases/download/v${KIND_VERSION}/kind-linux-amd64" \
 && chmod +x /usr/local/bin/kubectl /usr/local/bin/kind \
 && curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" | tar -xz -C /usr/local/bin trivy \
 && curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks \
 && curl -fsSLo /tmp/scanner.zip "https://repo1.maven.org/maven2/org/sonarsource/scanner/cli/sonar-scanner-cli/${SONAR_SCANNER_VERSION}/sonar-scanner-cli-${SONAR_SCANNER_VERSION}.zip" \
 && unzip -q /tmp/scanner.zip -d /opt && mv /opt/sonar-scanner-* /opt/sonar-scanner \
 && ln -s /opt/sonar-scanner/bin/sonar-scanner /usr/local/bin/sonar-scanner \
 && rm /tmp/scanner.zip

# Scanner Python tools live in their own venv, shared by every build
RUN python3 -m venv /opt/sectools \
 && /opt/sectools/bin/pip install --no-cache-dir bandit==1.9.4 pip-audit==2.10.1

# docker.sock on Docker Desktop is root-owned; the entrypoint wrapper fixes group access
COPY docker-socket-entrypoint.sh /usr/local/bin/docker-socket-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-socket-entrypoint.sh && apt-get update && apt-get install -y --no-install-recommends gosu && rm -rf /var/lib/apt/lists/*

COPY plugins.txt /usr/share/jenkins/ref/plugins.txt
RUN jenkins-plugin-cli --plugin-file /usr/share/jenkins/ref/plugins.txt

COPY casc.yaml /usr/share/jenkins/casc.yaml
ENV CASC_JENKINS_CONFIG=/usr/share/jenkins/casc.yaml \
    JAVA_OPTS="-Djenkins.install.runSetupWizard=false -Dhudson.model.DirectoryBrowserSupport.CSP=\"sandbox; default-src 'none'; img-src 'self' data:; style-src 'self' 'unsafe-inline';\"" \
    PATH="/opt/sectools/bin:${PATH}"

ENTRYPOINT ["/usr/local/bin/docker-socket-entrypoint.sh"]
