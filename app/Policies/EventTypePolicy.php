<?php

namespace App\Policies;

use App\Models\EventType;
use App\Models\User;

/**
 * Only administrators maintain the list of event types.
 */
class EventTypePolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, EventType $eventType): bool
    {
        return $user->isAdmin();
    }
}
