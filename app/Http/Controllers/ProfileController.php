<?php

namespace App\Http\Controllers;

use App\Actions\ListInstructorSchedule;
use App\Enums\ScheduleRange;
use App\Events\Users\UserUpdated;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The signed-in user's own profile: name and phone, and the schedule when they are an instructor.
 */
class ProfileController extends Controller
{
    public function edit(Request $request, ListInstructorSchedule $schedule): Response
    {
        $user = $request->user();

        return Inertia::render('profile/Edit', [
            'profile' => [
                'name' => $user->name,
                'email' => $user->email,
                'phone' => $user->phone,
                'role' => $user->rolesLabel(),
            ],
            'schedule' => $user->isInstructor() ? $schedule->handle($user, $user->preferredScheduleRange()) : null,
            'scheduleRange' => $user->preferredScheduleRange()->value,
            'scheduleRanges' => ScheduleRange::options(),
        ]);
    }

    public function update(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'phone' => ['nullable', 'string', 'max:32'],
        ]);

        $request->user()->update($validated);

        UserUpdated::dispatchChanges($request->user(), $request->user());

        return back()->with('status', 'Профиль сохранён.');
    }
}
