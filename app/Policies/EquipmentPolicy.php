<?php

namespace App\Policies;

use App\Models\Equipment;
use App\Models\User;

/**
 * Administrators and instructors both see the equipment registry; only administrators maintain it.
 */
class EquipmentPolicy
{
    public function viewAny(User $user): bool
    {
        return true;
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, Equipment $equipment): bool
    {
        return $user->isAdmin();
    }
}
