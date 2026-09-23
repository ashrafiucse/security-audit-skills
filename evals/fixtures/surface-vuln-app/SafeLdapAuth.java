import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;
import org.apache.directory.api.ldap.model.ldif.LdapUtils;

public class SafeLdapAuth {
    public boolean login(String uid, String password) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://ldap.corp.example-fake.com");
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        // escaped DN component -> no DN injection
        env.put(Context.SECURITY_PRINCIPAL,
                "uid=" + LdapUtils.escapeDN(uid) + ",ou=people,dc=corp,dc=example-fake,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, password);
        try {
            new InitialDirContext(env);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
