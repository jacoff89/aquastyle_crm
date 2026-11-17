<?php

namespace App\Http\Controllers\Settings;

use App\Events\Settings\ClientStatusesReordered;
use App\Http\Controllers\Controller;
use App\Models\ClientStatus;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

/**
 * Position of a status in the list, which is also its order in the client form.
 */
class ClientStatusPositionController extends Controller
{
    public function update(Request $request, ClientStatus $clientStatus): RedirectResponse
    {
        Gate::authorize('update', $clientStatus);

        $validated = $request->validate([
            'direction' => ['required', Rule::in(['up', 'down'])],
        ]);

        $moved = match ($validated['direction']) {
            'up' => $clientStatus->moveUp(),
            'down' => $clientStatus->moveDown(),
        };

        if ($moved) {
            ClientStatusesReordered::dispatch($clientStatus, $validated['direction'], $request->user());
        }

        return back();
    }
}
