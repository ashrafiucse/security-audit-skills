<?php
// Fixture: CSRF disabled globally.
namespace App\Http\Middleware;

use Illuminate\Foundation\Http\Middleware\VerifyCsrfToken as Middleware;

class VerifyCsrfToken extends Middleware
{
    // SEC-06: CSRF verification disabled for every route
    protected $except = [
        '*',
    ];
}
