<?php

namespace App\Events\Users;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\User;

/**
 * An account's password was changed: by its owner in the profile, or set by an administrator.
 * A reset through the emailed link is announced by Laravel's own Illuminate\Auth\Events\PasswordReset.
 */
class UserPasswordChanged extends AbstractDomainEvent
{
    public function __construct(public User $user, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Whether the owner changed the password themselves rather than an administrator.
     */
    public function changedByOwner(): bool
    {
        return $this->actor?->is($this->user) ?? false;
    }

    public function describe(): ?EventDescription
    {
        return new EventDescription("Изменён пароль учётной записи {$this->user->fullName()}", self::accountUrl($this->user), [$this->user->id], route('profile.edit'));
    }
}
