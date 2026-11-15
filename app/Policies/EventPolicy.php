<?php

namespace App\Policies;

use App\Models\Event;
use App\Models\User;

/**
 * Administrators and instructors both see the whole calendar, create, edit, move
 * and cancel events, and book clients on them.
 *
 * Marking who came is the exception: administrators do it on any event, instructors
 * only on the events they take part in.
 *
 * Moving a client to another event and deleting an event belong to administrators and
 * to the lead instructor: a move needs the lead of both events, a deletion the lead of
 * the event. An event is deleted only while it has no clients at all, which the
 * DeleteEvent action checks.
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

    public function delete(User $user, Event $event): bool
    {
        return $user->isAdmin() || $event->isLedBy($user);
    }

    public function manageClients(User $user, Event $event): bool
    {
        return true;
    }

    public function markAttendance(User $user, Event $event): bool
    {
        return $user->isAdmin() || $event->instructors()->whereKey($user->getKey())->exists();
    }

    /**
     * Whether the user moves clients out of the event at all; which events they may move
     * them to is told by transferClient().
     */
    public function transferClientsFrom(User $user, Event $event): bool
    {
        return $user->isAdmin() || $event->isLedBy($user);
    }

    /**
     * Whether the user moves a client from one event to the other.
     */
    public function transferClient(User $user, Event $from, Event $to): bool
    {
        return $user->isAdmin() || ($from->isLedBy($user) && $to->isLedBy($user));
    }
}
