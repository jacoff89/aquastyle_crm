<?php

namespace App\Http\Controllers;

use App\Enums\EquipmentStatus;
use App\Http\Requests\Equipment\StoreEquipmentRequest;
use App\Http\Requests\Equipment\UpdateEquipmentRequest;
use App\Models\Equipment;
use App\Models\EquipmentCategory;
use App\Models\Location;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Collection;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The equipment registry. Each item is kept at a location and may be assigned to an instructor.
 * Items are written off rather than deleted.
 */
class EquipmentController extends Controller
{
    public function index(): Response
    {
        Gate::authorize('viewAny', Equipment::class);

        return Inertia::render('equipment/Index', [
            'equipment' => Equipment::query()
                ->with(['category:id,name', 'location:id,name', 'instructor:id,name,last_name'])
                ->orderBy('name')
                ->orderBy('inventory_number')
                ->get()
                ->map(fn (Equipment $item): array => [
                    'id' => $item->id,
                    'name' => $item->name,
                    'categoryId' => $item->category_id,
                    'categoryName' => $item->category?->name,
                    'inventoryNumber' => $item->inventory_number,
                    'size' => $item->size,
                    'status' => $item->status->value,
                    'statusLabel' => $item->status->label(),
                    'locationId' => $item->location_id,
                    'locationName' => $item->location?->name,
                    'instructorId' => $item->instructor_id,
                    'instructorName' => $item->instructor === null ? null : $this->fullName($item->instructor),
                ]),
            ...$this->options(),
        ]);
    }

    public function create(): Response
    {
        Gate::authorize('create', Equipment::class);

        return Inertia::render('equipment/Form', [
            'item' => null,
            ...$this->options(),
        ]);
    }

    public function store(StoreEquipmentRequest $request): RedirectResponse
    {
        $item = Equipment::create($request->validated());

        return redirect()->route('equipment.index')->with('status', "Снаряжение «{$item->name}» добавлено в реестр.");
    }

    public function edit(Equipment $equipment): Response
    {
        Gate::authorize('update', $equipment);

        return Inertia::render('equipment/Form', [
            'item' => [
                'id' => $equipment->id,
                'name' => $equipment->name,
                'categoryId' => $equipment->category_id,
                'inventoryNumber' => $equipment->inventory_number,
                'size' => $equipment->size,
                'status' => $equipment->status->value,
                'locationId' => $equipment->location_id,
                'instructorId' => $equipment->instructor_id,
                'notes' => $equipment->notes,
            ],
            ...$this->options(),
        ]);
    }

    public function update(UpdateEquipmentRequest $request, Equipment $equipment): RedirectResponse
    {
        $equipment->update($request->validated());

        return redirect()->route('equipment.index')->with('status', "Изменения сохранены: {$equipment->name}.");
    }

    /**
     * Categories, locations, instructors and statuses to choose from. Hidden locations and deactivated
     * instructors are included, marked, so that items which already have them show them.
     *
     * @return array{categories: Collection<int, array{id: int, name: string}>, locations: Collection<int, array{id: int, name: string, isActive: bool}>, instructors: Collection<int, array{id: int, name: string, isActive: bool}>, statuses: list<array{value: string, label: string}>}
     */
    private function options(): array
    {
        return [
            'categories' => EquipmentCategory::query()
                ->orderBy('name')
                ->get()
                ->map(fn (EquipmentCategory $category): array => [
                    'id' => $category->id,
                    'name' => $category->name,
                ]),
            'locations' => Location::query()
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get()
                ->map(fn (Location $location): array => [
                    'id' => $location->id,
                    'name' => $location->name,
                    'isActive' => $location->is_active,
                ]),
            'instructors' => User::instructors()
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get()
                ->map(fn (User $instructor): array => [
                    'id' => $instructor->id,
                    'name' => $this->fullName($instructor),
                    'isActive' => $instructor->is_active,
                ]),
            'statuses' => EquipmentStatus::options(),
        ];
    }

    private function fullName(User $instructor): string
    {
        return trim("{$instructor->name} {$instructor->last_name}");
    }
}
