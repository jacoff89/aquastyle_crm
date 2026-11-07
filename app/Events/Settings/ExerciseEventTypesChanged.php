<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Models\Exercise;
use App\Models\User;

/**
 * The event types an exercise is offered for changed.
 */
class ExerciseEventTypesChanged extends AbstractDomainEvent
{
    /**
     * @param  list<int>  $attachedEventTypeIds
     * @param  list<int>  $detachedEventTypeIds
     */
    public function __construct(
        public Exercise $exercise,
        public array $attachedEventTypeIds,
        public array $detachedEventTypeIds,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the result of syncing the exercise's event types, unless nothing changed.
     *
     * @param  array{attached: array<int, int|string>, detached: array<int, int|string>, updated: array<int, int|string>}  $changes
     */
    public static function dispatchFor(Exercise $exercise, array $changes, ?User $actor): void
    {
        if ($changes['attached'] === [] && $changes['detached'] === []) {
            return;
        }

        static::dispatch(
            $exercise,
            array_map(intval(...), array_values($changes['attached'])),
            array_map(intval(...), array_values($changes['detached'])),
            $actor,
        );
    }
}
