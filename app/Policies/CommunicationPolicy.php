<?php

namespace App\Policies;

use App\Models\Client;
use App\Models\Communication;
use App\Models\User;

/**
 * Administrators and instructors both add communications. Instructors edit and
 * delete only their own; administrators edit and delete any.
 *
 * The calendar of every communication is for administrators only; instructors
 * see communications on the client's card.
 */
class CommunicationPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
    }

    public function create(User $user, Client $client): bool
    {
        return true;
    }

    public function update(User $user, Communication $communication): bool
    {
        return $user->isAdmin() || $communication->created_by === $user->id;
    }

    public function delete(User $user, Communication $communication): bool
    {
        return $this->update($user, $communication);
    }
}
