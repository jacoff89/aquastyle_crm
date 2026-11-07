<?php

namespace App\Events\Users;

use App\Events\AbstractDomainEvent;
use App\Models\User;

/**
 * A deactivated account was made active again: its owner can sign in.
 */
class UserActivated extends AbstractDomainEvent
{
    public function __construct(public User $user, ?User $actor)
    {
        parent::__construct($actor);
    }
}
