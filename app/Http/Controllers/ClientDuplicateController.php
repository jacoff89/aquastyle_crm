<?php

namespace App\Http\Controllers;

use App\Models\Client;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

/**
 * Looks up clients that already have a given phone, so the client form can
 * show a warning with links to their cards before anything is saved.
 */
class ClientDuplicateController extends Controller
{
    public function __invoke(Request $request): JsonResponse
    {
        Gate::authorize('viewAny', Client::class);

        $validated = $request->validate([
            'phone' => ['required', 'string', 'max:32'],
            'except' => ['nullable', 'integer'],
        ]);

        $duplicates = Client::query()
            ->samePhoneAs($validated['phone'])
            ->when($validated['except'] ?? null, fn ($query, int $id) => $query->whereKeyNot($id))
            ->orderBy('last_name')
            ->orderBy('first_name')
            ->limit(5)
            ->get();

        return response()->json([
            'duplicates' => $duplicates->map(fn (Client $client): array => [
                'id' => $client->id,
                'name' => $client->fullName(),
                'phone' => $client->phone,
            ])->values(),
        ]);
    }
}
