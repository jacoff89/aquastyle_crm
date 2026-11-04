<?php

namespace App\Http\Controllers;

use App\Http\Requests\Locations\StoreLocationRequest;
use App\Http\Requests\Locations\UpdateLocationRequest;
use App\Models\Location;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The list of locations. Locations are hidden rather than deleted, so the equipment
 * kept there does not lose its place.
 */
class LocationController extends Controller
{
    public function index(): Response
    {
        Gate::authorize('viewAny', Location::class);

        return Inertia::render('locations/Index', [
            'locations' => Location::query()
                ->withCount('equipment')
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get()
                ->map(fn (Location $location): array => [
                    'id' => $location->id,
                    'name' => $location->name,
                    'address' => $location->address,
                    'isActive' => $location->is_active,
                    'equipmentCount' => $location->equipment_count,
                ]),
        ]);
    }

    public function store(StoreLocationRequest $request): RedirectResponse
    {
        $location = Location::create($request->validated());

        return back()->with('status', "Локация «{$location->name}» добавлена.");
    }

    public function update(UpdateLocationRequest $request, Location $location): RedirectResponse
    {
        $location->update($request->validated());

        $status = match (true) {
            $location->wasChanged('is_active') && $location->is_active => "Локация «{$location->name}» снова предлагается в занятиях.",
            $location->wasChanged('is_active') => "Локация «{$location->name}» скрыта: в занятиях она больше не предлагается.",
            $location->wasChanged(['name', 'address']) => "Локация «{$location->name}» сохранена.",
            default => null,
        };

        return back()->with('status', $status);
    }
}
