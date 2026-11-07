<?php

namespace App\Policies;

use App\Models\Notice;
use App\Models\User;

/**
 * Administrators open every notice; anyone else only the notices that concern them.
 */
class NoticePolicy
{
    public function view(User $user, Notice $notice): bool
    {
        return $notice->isVisibleTo($user);
    }
}
