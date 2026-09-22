// Fixture: intentionally vulnerable Java endpoints. FAKE data only.
// Expected findings: see expected-findings.md
package com.example.web;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.parser.ParserConfig;
import org.apache.commons.text.StringSubstitutor;
import org.apache.shiro.mgt.DefaultSecurityManager;

public class ApiController {

    // SEC-01: fastjson autoType explicitly enabled + user JSON parsed
    public Object parseProfile(String requestBody) {
        ParserConfig.getGlobalInstance().setAutoTypeSupport(true); // SEC-01a
        return JSON.parseObject(requestBody);                       // SEC-01b: @type honored
    }

    // SEC-02: Text4Shell — user input through default StringSubstitutor
    public String renderTemplate(String userText) {
        StringSubstitutor sub = StringSubstitutor.createDefault();
        return sub.replace(userText); // ${script:...} executes
    }

    // SEC-03: Shiro550 — rememberMe with the hardcoded default key
    public DefaultSecurityManager securityManager() {
        DefaultSecurityManager sm = new DefaultSecurityManager();
        byte[] key = java.util.Base64.getDecoder()
                .decode("kPH+bIxk5D2deZiIxcaaaA=="); // SEC-03: well-known default key
        org.apache.shiro.mgt.AbstractRememberMeManager rem =
                (org.apache.shiro.mgt.AbstractRememberMeManager) sm.getRememberMeManager();
        rem.setCipherKey(key);
        return sm;
    }
}
