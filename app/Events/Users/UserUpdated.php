<?php

namespace App\Events\Users;

use App\Enums\Role;
use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\User;

/**
 * An account was changed: by an administrator in the user settings or on the instructors page,
 * or by its owner in the profile. The changes that matter on their own are announced by their own
 * events as well: UserActivated, UserDeactivated, UserRolesChanged and UserPasswordChanged.
 * The password itself never appears in the change set.
 */
class UserUpdated extends AbstractDomainEvent
{
    public function __construct(public User $user, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the account changed, followed by the events for activation,
     * roles and password. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(User $user, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($user);

        if ($changes->isNotEmpty()) {
            static::dispatch($user, $changes, $actor);
        }

        if ($changes->has('is_active')) {
            $user->is_active ? UserActivated::dispatch($user, $actor) : UserDeactivated::dispatch($user, $actor);
        }

        if ($changes->has('roles')) {
            UserRolesChanged::dispatch($user, array_map(Role::from(...), $changes->old('roles') ?? []), $actor);
        }

        if ($user->wasChanged('password')) {
            UserPasswordChanged::dispatch($user, $actor);
        }
    }
}
