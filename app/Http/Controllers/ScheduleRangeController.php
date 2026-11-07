<?php

namespace App\Http\Controllers;

use App\Enums\ScheduleRange;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Validation\Rule;

/**
 * Remembers how far ahead the signed-in user wants to see an instructor's schedule.
 * It is a preference of the interface, not a change of the account, so no domain event announces it.
 */
class ScheduleRangeController extends Controller
{
    public function update(Request $request): RedirectResponse
    {
        $validated = $request->validate([
            'range' => ['required', Rule::enum(ScheduleRange::class)],
        ]);

        $user = $request->user();
        $user->schedule_range = ScheduleRange::from($validated['range']);
        $user->save();

        return back();
    }
}
