<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\NewPasswordController;
use App\Http\Controllers\Auth\PasswordResetLinkController;
use App\Http\Controllers\ClientController;
use App\Http\Controllers\ClientDuplicateController;
use App\Http\Controllers\InstructorController;
use App\Http\Controllers\PasswordController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\Settings\EventTypeController;
use App\Http\Controllers\Settings\EventTypePositionController;
use App\Http\Controllers\Settings\UserController;
use Illuminate\Support\Facades\Route;

Route::middleware('guest')->group(function () {
    Route::get('login', [AuthenticatedSessionController::class, 'create'])->name('login');
    Route::post('login', [AuthenticatedSessionController::class, 'store'])->name('login.store');

    Route::get('forgot-password', [PasswordResetLinkController::class, 'create'])->name('password.request');
    Route::post('forgot-password', [PasswordResetLinkController::class, 'store'])
        ->middleware('throttle:6,1')
        ->name('password.email');

    Route::get('reset-password/{token}', [NewPasswordController::class, 'create'])->name('password.reset');
    Route::post('reset-password', [NewPasswordController::class, 'store'])->name('password.store');
});

Route::middleware('auth')->group(function () {
    Route::redirect('/', '/calendar')->name('home');

    Route::inertia('calendar', 'calendar/Index')->name('calendar');

    Route::get('profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::put('profile/password', [PasswordController::class, 'update'])->name('profile.password');

    Route::get('clients/duplicates', ClientDuplicateController::class)->name('clients.duplicates');
    Route::resource('clients', ClientController::class);

    Route::resource('instructors', InstructorController::class)->except(['destroy']);

    Route::prefix('settings')->name('settings.')->group(function () {
        Route::get('event-types', [EventTypeController::class, 'index'])->name('event-types.index');
        Route::post('event-types', [EventTypeController::class, 'store'])->name('event-types.store');
        Route::patch('event-types/{eventType}', [EventTypeController::class, 'update'])->name('event-types.update');
        Route::patch('event-types/{eventType}/position', [EventTypePositionController::class, 'update'])->name('event-types.position');

        Route::resource('users', UserController::class)->except(['show', 'destroy']);
    });

    Route::post('logout', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
});
