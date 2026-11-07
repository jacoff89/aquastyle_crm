<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\Exercise;
use App\Models\User;

/**
 * An exercise was renamed, hidden or shown again. A change of its event types is
 * announced by ExerciseEventTypesChanged.
 */
class ExerciseUpdated extends AbstractDomainEvent
{
    public function __construct(public Exercise $exercise, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the exercise changed. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Exercise $exercise, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($exercise);

        if ($changes->isNotEmpty()) {
            static::dispatch($exercise, $changes, $actor);
        }
    }
}
