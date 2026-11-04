<?php

namespace App\Http\Controllers\Settings;

use App\Http\Controllers\Controller;
use App\Models\Exercise;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

/**
 * Position of an exercise in the list, which is also its order when attaching it to a client.
 */
class ExercisePositionController extends Controller
{
    public function update(Request $request, Exercise $exercise): RedirectResponse
    {
        Gate::authorize('update', $exercise);

        $validated = $request->validate([
            'direction' => ['required', Rule::in(['up', 'down'])],
        ]);

        match ($validated['direction']) {
            'up' => $exercise->moveUp(),
            'down' => $exercise->moveDown(),
        };

        return back();
    }
}
