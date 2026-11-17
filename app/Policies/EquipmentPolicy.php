<?php

namespace App\Policies;

use App\Models\Equipment;
use App\Models\User;

/**
 * Administrators and instructors both see the equipment registry and may change an item's status;
 * only administrators maintain the rest of it.
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

    public function updateStatus(User $user, Equipment $equipment): bool
    {
        return $user->isAdmin() || $user->isInstructor();
    }

    public function update(User $user, Equipment $equipment): bool
    {
        return $user->isAdmin();
    }
}
