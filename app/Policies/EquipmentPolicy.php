<?php

namespace App\Policies;

use App\Models\Equipment;
use App\Models\User;

/**
 * Only administrators maintain the equipment registry.
 */
class EquipmentPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
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
