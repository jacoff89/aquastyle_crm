<?php

namespace App\Policies;

use App\Models\ClientStatus;
use App\Models\User;

/**
 * Only administrators maintain the list of client statuses. Choosing them for a client is part of editing the client.
 */
class ClientStatusPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, ClientStatus $clientStatus): bool
    {
        return $user->isAdmin();
    }
}
