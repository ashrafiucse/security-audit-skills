<?php
// WordPress-shaped fixture for the do_shortcode-on-input class (SSTI).
// Plant: do_shortcode() over raw request data — arbitrary shortcode
// execution by unauthenticated attackers (LatePoint CVE-2026-92966 class).

// ---------- SEC-1: do_shortcode on unvalidated request input ----------
add_action('wp_ajax_nopriv_preview_block', function () {
    echo do_shortcode($_POST['content']); // nopriv + client shortcode = unauth execution
    wp_die();
});
