<?php

namespace App\Policies;

use App\Models\Event;
use App\Models\User;

/**
 * Administrators and instructors both see the whole calendar, create, edit, move
 * and cancel events, and book clients on them. Events are cancelled rather than deleted.
 *
 * Marking who came is the exception: administrators do it on any event, instructors
 * only on the events they take part in.
 */
class EventPolicy
{
    public function viewAny(User $user): bool
    {
        return true;
    }

    public function view(User $user, Event $event): bool
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

    public function manageClients(User $user, Event $event): bool
    {
        return true;
    }

    public function markAttendance(User $user, Event $event): bool
    {
        return $user->isAdmin() || $event->instructors()->whereKey($user->getKey())->exists();
    }
}
