<?php

namespace App\Http\Controllers;

use App\Models\Client;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

/**
 * Finds clients by name, phone or email for the search box in the event window,
 * where a client is picked to be booked on the event. Returns the ten best matches.
 */
class ClientSearchController extends Controller
{
    private const LIMIT = 10;

    public function __invoke(Request $request): JsonResponse
    {
        Gate::authorize('viewAny', Client::class);

        $validated = $request->validate([
            'q' => ['nullable', 'string', 'max:100'],
        ]);

        $term = trim((string) ($validated['q'] ?? ''));

        if ($term === '') {
            return response()->json(['clients' => []]);
        }

        $clients = Client::query()
            ->search($term)
            ->orderBy('last_name')
            ->orderBy('first_name')
            ->orderBy('id')
            ->limit(self::LIMIT)
            ->get();

        return response()->json([
            'clients' => $clients->map(fn (Client $client): array => [
                'id' => $client->id,
                'name' => $client->fullName(),
                'phone' => $client->phone,
            ])->values(),
        ]);
    }
}
