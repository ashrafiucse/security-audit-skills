<?php

use Illuminate\Support\Facades\Route;
use Modules\Marketing\Http\Controllers\SafeLeadController;

// SAFE: the route is the enforcement point — feature middleware + throttle
Route::post('/admin/leads/email/compose', [SafeLeadController::class, 'composeEmail'])
    ->middleware(['auth', 'feature:send-email', 'throttle:blast-compose']);

// SAFE: POST + signed URL + throttle for the side-effecting link
Route::post('/leads/{lead}/send-verification-link', [SafeLeadController::class, 'sendVerificationLink'])
    ->middleware(['signed', 'throttle:6,1']);
