<?php

namespace App\Policies;

use App\Models\Client;
use App\Models\User;

/**
 * Administrators and instructors both work with the client list: view, add and edit.
 * Only administrators delete a client.
 */
class ClientPolicy
{
    public function viewAny(User $user): bool
    {
        return true;
    }

    public function view(User $user, Client $client): bool
    {
        return true;
    }

    public function create(User $user): bool
    {
        return true;
    }

    public function update(User $user, Client $client): bool
    {
        return true;
    }

    public function delete(User $user, Client $client): bool
    {
        return $user->isAdmin();
    }
}
