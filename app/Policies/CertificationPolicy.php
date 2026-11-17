<?php

namespace App\Policies;

use App\Models\Certification;
use App\Models\User;

/**
 * Only administrators maintain the list of certifications. Choosing them for a client is part of editing the client.
 */
class CertificationPolicy
{
    public function viewAny(User $user): bool
    {
        return $user->isAdmin();
    }

    public function create(User $user): bool
    {
        return $user->isAdmin();
    }

    public function update(User $user, Certification $certification): bool
    {
        return $user->isAdmin();
    }
}
