<?php

namespace App\Http\Controllers\Settings;

use App\Http\Controllers\Controller;
use App\Models\EventType;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

/**
 * Position of a type in the list, which is also its order in calendar forms.
 */
class EventTypePositionController extends Controller
{
    public function update(Request $request, EventType $eventType): RedirectResponse
    {
        Gate::authorize('update', $eventType);

        $validated = $request->validate([
            'direction' => ['required', Rule::in(['up', 'down'])],
        ]);

        match ($validated['direction']) {
            'up' => $eventType->moveUp(),
            'down' => $eventType->moveDown(),
        };

        return back();
    }
}
