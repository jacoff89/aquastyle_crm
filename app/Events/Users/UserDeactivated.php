<?php

namespace App\Events\Users;

use App\Events\AbstractDomainEvent;
use App\Models\User;

/**
 * An account was deactivated: its owner can no longer sign in, but stays in the history of past events.
 */
class UserDeactivated extends AbstractDomainEvent
{
    public function __construct(public User $user, ?User $actor)
    {
        parent::__construct($actor);
    }
}
