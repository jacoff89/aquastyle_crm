<?php

namespace App\Policies;

use App\Models\User;

/**
 * Only administrators manage user accounts (administrators and instructors).
 */
class UserPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
    }

    public function view(User $user, User $model): bool
    {
        return $user->isAdmin() || $user->is($model);
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, User $model): bool
    {
        return $user->isAdmin();
    }

    /**
     * Administrators can't delete their own account to avoid losing access.
     */
    public function delete(User $user, User $model): bool
    {
        return $user->isAdmin() && ! $user->is($model);
    }
}
