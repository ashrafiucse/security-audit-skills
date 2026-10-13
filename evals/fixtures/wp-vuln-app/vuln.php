<?php
// WordPress-shaped fixture for the do_shortcode-on-input class (SSTI).
// Plant: do_shortcode() over raw request data — arbitrary shortcode
// execution by unauthenticated attackers (LatePoint CVE-2026-92966 class).

// ---------- SEC-1: do_shortcode on unvalidated request input ----------
add_action('wp_ajax_nopriv_preview_block', function () {
    echo do_shortcode($_POST['content']); // nopriv + client shortcode = unauth execution
    wp_die();
});

// ---------- SEC-2: obfuscated-case PHP command sink ----------
// PHP function calls are case-INSENSITIVE: SyStem() IS system(). The
// case-sensitive sink greps miss this shape entirely (semgrep's php
// exec-use rule went case-insensitive 2026-10 for exactly this).
add_action('wp_ajax_nopriv_diag_ping', function () {
    $out = SyStem('ping -c 1 ' . $_GET['host']); // request data -> shell, mixed-case spelling
    echo "<pre>$out</pre>";
    wp_die();
});
