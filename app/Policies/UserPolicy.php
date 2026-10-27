<?php

namespace App\Policies;

use App\Models\User;

/**
 * Only administrators manage user accounts (administrators and instructors).
 * Accounts are deactivated rather than deleted, so their history stays intact.
 */
class UserPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
    }

    public function view(User $user, User $model): bool
    {
        return $user->isAdmin();
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, User $model): bool
    {
        return $user->isAdmin();
    }
}
