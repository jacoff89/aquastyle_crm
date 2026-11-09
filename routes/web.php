<?php

use App\Http\Controllers\Auth\AuthenticatedSessionController;
use App\Http\Controllers\Auth\NewPasswordController;
use App\Http\Controllers\Auth\PasswordResetLinkController;
use App\Http\Controllers\CalendarController;
use App\Http\Controllers\CalendarEventController;
use App\Http\Controllers\ClientCommunicationController;
use App\Http\Controllers\ClientController;
use App\Http\Controllers\ClientDuplicateController;
use App\Http\Controllers\ClientSearchController;
use App\Http\Controllers\EquipmentCategoryController;
use App\Http\Controllers\EquipmentController;
use App\Http\Controllers\EventClientController;
use App\Http\Controllers\EventController;
use App\Http\Controllers\InstructorController;
use App\Http\Controllers\LocationController;
use App\Http\Controllers\NoticeController;
use App\Http\Controllers\NoticeSettingsController;
use App\Http\Controllers\PasswordController;
use App\Http\Controllers\ProfileController;
use App\Http\Controllers\ScheduleRangeController;
use App\Http\Controllers\Settings\EventTypeController;
use App\Http\Controllers\Settings\EventTypePositionController;
use App\Http\Controllers\Settings\ExerciseController;
use App\Http\Controllers\Settings\ExercisePositionController;
use App\Http\Controllers\Settings\UserController;
use App\Http\Controllers\TelegramLinkController;
use App\Http\Controllers\TelegramWebhookController;
use Illuminate\Foundation\Http\Middleware\ValidateCsrfToken;
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

// Telegram posts the bot's updates here; it proves itself with the webhook secret instead of a CSRF token.
Route::post('telegram/webhook', TelegramWebhookController::class)
    ->withoutMiddleware(ValidateCsrfToken::class)
    ->name('telegram.webhook');

Route::middleware('auth')->group(function () {
    Route::redirect('/', '/calendar')->name('home');

    Route::get('calendar', CalendarController::class)->name('calendar');
    Route::get('calendar/events', CalendarEventController::class)->name('calendar.events');

    Route::post('events', [EventController::class, 'store'])->name('events.store');
    Route::patch('events/{event}', [EventController::class, 'update'])->name('events.update');

    Route::get('events/{event}/clients', [EventClientController::class, 'index'])->name('events.clients.index');
    Route::post('events/{event}/clients', [EventClientController::class, 'store'])->name('events.clients.store');
    Route::patch('events/{event}/clients/{client}', [EventClientController::class, 'update'])
        ->withTrashed()
        ->name('events.clients.update');

    Route::get('notifications', [NoticeController::class, 'index'])->name('notices.index');
    Route::post('notifications/read-all', [NoticeController::class, 'readAll'])->name('notices.read-all');
    Route::get('notifications/settings', [NoticeSettingsController::class, 'edit'])->name('notices.settings.edit');
    Route::put('notifications/settings', [NoticeSettingsController::class, 'update'])->name('notices.settings.update');
    Route::post('notifications/telegram', [TelegramLinkController::class, 'store'])->name('notices.telegram.store');
    Route::delete('notifications/telegram', [TelegramLinkController::class, 'destroy'])->name('notices.telegram.destroy');
    Route::post('notifications/{notice}/open', [NoticeController::class, 'open'])->name('notices.open');

    Route::get('profile', [ProfileController::class, 'edit'])->name('profile.edit');
    Route::patch('profile', [ProfileController::class, 'update'])->name('profile.update');
    Route::put('profile/password', [PasswordController::class, 'update'])->name('profile.password');

    Route::get('clients/duplicates', ClientDuplicateController::class)->name('clients.duplicates');
    Route::get('clients/search', ClientSearchController::class)->name('clients.search');
    Route::resource('clients', ClientController::class);
    Route::post('clients/{client}/communications', [ClientCommunicationController::class, 'store'])->name('clients.communications.store');
    Route::patch('communications/{communication}', [ClientCommunicationController::class, 'update'])->name('communications.update');
    Route::delete('communications/{communication}', [ClientCommunicationController::class, 'destroy'])->name('communications.destroy');

    Route::patch('schedule-range', [ScheduleRangeController::class, 'update'])->name('schedule-range.update');
    Route::resource('instructors', InstructorController::class)->except(['destroy']);

    Route::get('locations', [LocationController::class, 'index'])->name('locations.index');
    Route::post('locations', [LocationController::class, 'store'])->name('locations.store');
    Route::patch('locations/{location}', [LocationController::class, 'update'])->name('locations.update');

    Route::resource('equipment', EquipmentController::class)->except(['show', 'destroy']);
    Route::post('equipment-categories', [EquipmentCategoryController::class, 'store'])->name('equipment-categories.store');
    Route::patch('equipment-categories/{category}', [EquipmentCategoryController::class, 'update'])->name('equipment-categories.update');

    Route::prefix('settings')->name('settings.')->group(function () {
        Route::get('event-types', [EventTypeController::class, 'index'])->name('event-types.index');
        Route::post('event-types', [EventTypeController::class, 'store'])->name('event-types.store');
        Route::patch('event-types/{eventType}', [EventTypeController::class, 'update'])->name('event-types.update');
        Route::patch('event-types/{eventType}/position', [EventTypePositionController::class, 'update'])->name('event-types.position');

        Route::get('exercises', [ExerciseController::class, 'index'])->name('exercises.index');
        Route::post('exercises', [ExerciseController::class, 'store'])->name('exercises.store');
        Route::patch('exercises/{exercise}', [ExerciseController::class, 'update'])->name('exercises.update');
        Route::patch('exercises/{exercise}/position', [ExercisePositionController::class, 'update'])->name('exercises.position');

        Route::resource('users', UserController::class)->except(['show', 'destroy']);
    });

    Route::post('logout', [AuthenticatedSessionController::class, 'destroy'])->name('logout');
});
