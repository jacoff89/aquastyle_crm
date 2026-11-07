<?php

namespace App\Events\Users;

use App\Events\AbstractDomainEvent;
use App\Models\User;

/**
 * An account was created: in the user settings, on the instructors page or with app:create-admin
 * (then without an actor).
 */
class UserCreated extends AbstractDomainEvent
{
    public function __construct(public User $user, ?User $actor)
    {
        parent::__construct($actor);
    }
}
