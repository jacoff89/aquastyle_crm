<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Models\Exercise;
use App\Models\User;

/**
 * An exercise was added in the settings.
 */
class ExerciseCreated extends AbstractDomainEvent
{
    public function __construct(public Exercise $exercise, ?User $actor)
    {
        parent::__construct($actor);
    }
}
