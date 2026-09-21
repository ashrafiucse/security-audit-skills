// Fixture: intentionally insecure controller.
package com.example.web;

import java.util.List;
import javax.persistence.EntityManager;
import org.springframework.web.bind.annotation.*;

@RestController
public class UserController {

    private final EntityManager em;

    public UserController(EntityManager em) { this.em = em; }

    @GetMapping("/search")
    public List<Object> search(@RequestParam String q) {
        // SEC-07: JPQL built by string concatenation
        return em.createQuery(
            "SELECT u FROM User u WHERE u.name = '" + q + "'").getResultList();
    }

    @GetMapping("/admin/keys")
    public String keys() {
        return "internal";
    }
}
