<?php

namespace App\Policies;

use App\Models\EquipmentCategory;
use App\Models\User;

/**
 * Categories belong to the equipment registry, which only administrators maintain.
 */
class EquipmentCategoryPolicy
{
    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, EquipmentCategory $category): bool
    {
        return $user->isAdmin();
    }
}
