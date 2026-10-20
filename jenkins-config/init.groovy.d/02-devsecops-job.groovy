// Creates the "devsecops-pipeline" job: Pipeline script from SCM -> Jenkinsfile.
import hudson.plugins.git.BranchSpec
import hudson.plugins.git.GitSCM
import jenkins.model.Jenkins
import org.jenkinsci.plugins.workflow.cps.CpsScmFlowDefinition
import org.jenkinsci.plugins.workflow.job.WorkflowJob

def jenkins = Jenkins.get()
def name = 'devsecops-pipeline'
def repo = System.getenv('DEVSECOPS_REPO')
def branch = System.getenv('DEVSECOPS_BRANCH') ?: 'main'

if (repo && jenkins.getItem(name) == null) {
    def scm = new GitSCM(GitSCM.createRepoList(repo, null), [new BranchSpec("*/${branch}")], null, null, [])
    def definition = new CpsScmFlowDefinition(scm, 'Jenkinsfile')
    definition.lightweight = true

    def job = jenkins.createProject(WorkflowJob, name)
    job.description = 'Jenkins-Based DevSecOps Pipeline for Automated Vulnerability Detection. ' +
            'Choose TARGET_APP=app (vulnerable) or app_secure (fixed) via "Build with Parameters".'
    job.definition = definition
    job.save()
    println "[devsecops] created job '${name}' from ${repo} (${branch})"
}
