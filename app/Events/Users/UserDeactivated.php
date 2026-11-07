<?php

namespace App\Events\Users;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        return new EventDescription("Учётная запись {$this->user->fullName()} деактивирована", self::accountUrl($this->user), [$this->user->id], route('profile.edit'));
    }
}
