<?php

namespace App\Events\Users;

use App\Enums\Role;
use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\User;

/**
 * An account was given other roles, e.g. an instructor became an administrator as well.
 * The new roles are on the user; the previous ones are carried here.
 */
class UserRolesChanged extends AbstractDomainEvent
{
    /**
     * @param  list<Role>  $previousRoles
     */
    public function __construct(public User $user, public array $previousRoles, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        $previous = implode(', ', array_map(fn (Role $role): string => mb_strtolower($role->label()), $this->previousRoles));

        return new EventDescription(
            "Роли учётной записи {$this->user->fullName()}: ".mb_strtolower($this->user->rolesLabel())." (были: {$previous})",
            self::accountUrl($this->user), [$this->user->id], route('profile.edit'),
        );
    }
}
