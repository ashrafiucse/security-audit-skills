// SAFE counter-examples for java-libs-vuln. An audit must NOT report these.
package com.example.web;

import com.alibaba.fastjson.JSON;
import org.apache.commons.text.StringSubstitutor;
import org.apache.commons.text.lookup.StringLookupFactory;

public class SafeController {

    // SAFE (vs SEC-01): typed parse, no autoType — @type never instantiated
    public Object parseProfile(String requestBody) {
        return JSON.parseObject(requestBody, ProfileDTO.class);
    }

    // SAFE (vs SEC-02): interpolator with NO script/dns/url lookups
    public String renderTemplate(String userText) {
        StringSubstitutor sub = new StringSubstitutor(
                StringLookupFactory.INSTANCE.mapStringLookup(
                        java.util.Map.of("env", "prod"))); // only ${env}
        return sub.replace(userText);
    }

    public static class ProfileDTO {
        public String name;
    }
}
