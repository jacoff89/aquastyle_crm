<?php

namespace App\Policies;

use App\Models\Exercise;
use App\Models\User;

/**
 * Only administrators maintain the list of exercises.
 */
class ExercisePolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, Exercise $exercise): bool
    {
        return $user->isAdmin();
    }
}
