<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Models\Exercise;
use App\Models\User;

/**
 * An exercise was moved one place up or down the list. The list is renumbered with a bulk
 * update, which Eloquent's model events do not see, so this event is the only trace of it.
 */
class ExercisesReordered extends AbstractDomainEvent
{
    /**
     * @param  'up'|'down'  $direction
     */
    public function __construct(public Exercise $exercise, public string $direction, ?User $actor)
    {
        parent::__construct($actor);
    }
}
