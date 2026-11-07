<?php

namespace App\Events\Users;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        return new EventDescription(
            "Новая учётная запись: {$this->user->fullName()} (".mb_strtolower($this->user->rolesLabel()).')',
            self::accountUrl($this->user), [$this->user->id], route('profile.edit'),
        );
    }
}
