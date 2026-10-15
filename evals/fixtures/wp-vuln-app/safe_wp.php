<?php
// SAFE counter-examples for wp-vuln-app. An audit must NOT report these.

// SAFE (vs SEC-1): the shortcode string is a server-side constant — nothing
// client-controlled reaches the template-execution sink
add_action('wp_ajax_nopriv_preview_block', function () {
    echo do_shortcode('[latepoint_booking calendar="main"]'); // hardcoded, not request data
    wp_die();
});

// SAFE (vs SEC-2): the command is a fixed literal executed through an
// argument array with escapeshellarg-validated input — and no
// mixed-case spellings of exec sinks anywhere in the file
add_action('wp_ajax_nopriv_diag_ping', function () {
    $host = escapeshellarg($_GET['host']);
    $lines = [];
    exec('ping', array('-c', '1', $host), $lines); // literal command + argument array
    echo '<pre>' . esc_html(implode("\n", $lines)) . '</pre>';
    wp_die();
});
