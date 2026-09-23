<?php

use Illuminate\Support\Facades\Route;
use Modules\Marketing\Http\Controllers\LeadController;

// compose route: authenticated, but NO feature middleware and NO throttle —
// the menu hides it for trials; the route stays open
Route::post('/admin/leads/email/compose', [LeadController::class, 'composeEmail'])
    ->middleware(['auth']);

// public GET with a side effect — each hit emails the lead; loop IDs = mail bomb
Route::get('/leads/{lead}/send-verification-link', [LeadController::class, 'sendVerificationLink'])
    ->name('leads.verification-link');
