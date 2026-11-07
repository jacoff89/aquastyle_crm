<?php

namespace App\Events\Users;

use App\Enums\Role;
use App\Events\AbstractDomainEvent;
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
}
