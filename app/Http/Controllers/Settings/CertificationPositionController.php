<?php

namespace App\Http\Controllers\Settings;

use App\Events\Settings\CertificationsReordered;
use App\Http\Controllers\Controller;
use App\Models\Certification;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;
use Illuminate\Validation\Rule;

/**
 * Position of a certification in the list, which is also its order in the client form and card.
 */
class CertificationPositionController extends Controller
{
    public function update(Request $request, Certification $certification): RedirectResponse
    {
        Gate::authorize('update', $certification);

        $validated = $request->validate([
            'direction' => ['required', Rule::in(['up', 'down'])],
        ]);

        $moved = match ($validated['direction']) {
            'up' => $certification->moveUp(),
            'down' => $certification->moveDown(),
        };

        if ($moved) {
            CertificationsReordered::dispatch($certification, $validated['direction'], $request->user());
        }

        return back();
    }
}
