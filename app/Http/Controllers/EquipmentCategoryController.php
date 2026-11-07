<?php

namespace App\Http\Controllers;

use App\Events\Equipment\EquipmentCategoryCreated;
use App\Events\Equipment\EquipmentCategoryUpdated;
use App\Http\Requests\Equipment\StoreEquipmentCategoryRequest;
use App\Http\Requests\Equipment\UpdateEquipmentCategoryRequest;
use App\Models\EquipmentCategory;
use Illuminate\Http\RedirectResponse;

/**
 * Categories of the equipment registry. They have no page of their own:
 * they are added and renamed from the equipment page.
 */
class EquipmentCategoryController extends Controller
{
    public function store(StoreEquipmentCategoryRequest $request): RedirectResponse
    {
        $category = EquipmentCategory::create($request->validated());

        EquipmentCategoryCreated::dispatch($category, $request->user());

        return back()->with('status', "Категория «{$category->name}» добавлена.");
    }

    public function update(UpdateEquipmentCategoryRequest $request, EquipmentCategory $category): RedirectResponse
    {
        $category->update($request->validated());

        EquipmentCategoryUpdated::dispatchChanges($category, $request->user());

        return back()->with('status', $category->wasChanged('name') ? "Категория переименована в «{$category->name}»." : null);
    }
}
