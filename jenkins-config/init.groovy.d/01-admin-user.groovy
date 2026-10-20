// Creates the local admin account on first start (setup wizard is disabled).
import hudson.security.FullControlOnceLoggedInAuthorizationStrategy
import hudson.security.HudsonPrivateSecurityRealm
import jenkins.model.Jenkins

def jenkins = Jenkins.get()
if (!(jenkins.securityRealm instanceof HudsonPrivateSecurityRealm)) {
    def user = System.getenv('JENKINS_ADMIN_USER') ?: 'admin'
    def pass = System.getenv('JENKINS_ADMIN_PASSWORD') ?: 'admin'
    def realm = new HudsonPrivateSecurityRealm(false)
    realm.createAccount(user, pass)
    jenkins.securityRealm = realm

    def strategy = new FullControlOnceLoggedInAuthorizationStrategy()
    strategy.allowAnonymousRead = false
    jenkins.authorizationStrategy = strategy
    jenkins.save()
    println "[devsecops] created admin user '${user}'"
}
