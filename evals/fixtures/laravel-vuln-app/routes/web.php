<?php
// Fixture: routes without protection.
use Illuminate\Support\Facades\Route;
use App\Http\Controllers\UserController;
use App\Http\Controllers\AdminController;

// SEC-04: admin + state-changing routes with no auth middleware
Route::get('/admin/users', [AdminController::class, 'index']);
Route::post('/users', [UserController::class, 'store']);
Route::get('/users/search', [UserController::class, 'search']);
Route::get('/download', [UserController::class, 'download']);
