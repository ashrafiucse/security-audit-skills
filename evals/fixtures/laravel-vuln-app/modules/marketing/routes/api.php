<?php

use Illuminate\Support\Facades\Route;
use Modules\Marketing\Http\Controllers\PublicLeadController;

// public subscribe — no FormRequest, no throttle, no captcha
Route::post('/v1/leads/subscribe', [PublicLeadController::class, 'subscribe']);
