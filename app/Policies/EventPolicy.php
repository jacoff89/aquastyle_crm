<?php

namespace App\Policies;

use App\Models\Event;
use App\Models\User;

/**
 * Administrators and instructors both see the whole calendar and create,
 * edit, move and cancel events. Events are cancelled rather than deleted.
 */
class EventPolicy
{
    public function viewAny(User $user): bool
    {
        return true;
    }

    public function create(User $user): bool
    {
        return true;
    }

    public function update(User $user, Event $event): bool
    {
        return true;
    }
}
