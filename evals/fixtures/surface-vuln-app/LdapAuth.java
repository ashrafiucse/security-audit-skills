import javax.naming.Context;
import javax.naming.directory.InitialDirContext;
import java.util.Hashtable;

public class LdapAuth {
    public boolean login(String uid, String password) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, "ldap://ldap.corp.example-fake.com");
        // anonymous bind accepted as an auth method
        env.put(Context.SECURITY_AUTHENTICATION, "none");
        // DN built by concatenation -> DN injection
        env.put(Context.SECURITY_PRINCIPAL,
                "uid=" + uid + ",ou=people,dc=corp,dc=example-fake,dc=com");
        env.put(Context.SECURITY_CREDENTIALS, password);
        try {
            new InitialDirContext(env);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
}
