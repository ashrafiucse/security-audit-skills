<?php
// SAFE counter-examples for wp-vuln-app. An audit must NOT report these.

// SAFE (vs SEC-1): the shortcode string is a server-side constant — nothing
// client-controlled reaches the template-execution sink
add_action('wp_ajax_nopriv_preview_block', function () {
    echo do_shortcode('[latepoint_booking calendar="main"]'); // hardcoded, not request data
    wp_die();
});
