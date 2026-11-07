<?php

namespace App\Events\Bookings;

use App\Events\AbstractDomainEvent;
use App\Models\EventClient;
use App\Models\User;

/**
 * Exercises were attached to a client on an event, or taken off.
 */
class BookingExercisesChanged extends AbstractDomainEvent
{
    /**
     * @param  list<int>  $attachedExerciseIds
     * @param  list<int>  $detachedExerciseIds
     */
    public function __construct(
        public EventClient $booking,
        public array $attachedExerciseIds,
        public array $detachedExerciseIds,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the result of syncing the booking's exercises, unless nothing changed.
     *
     * @param  array{attached: array<int, int|string>, detached: array<int, int|string>, updated: array<int, int|string>}  $changes
     */
    public static function dispatchFor(EventClient $booking, array $changes, ?User $actor): void
    {
        if ($changes['attached'] === [] && $changes['detached'] === []) {
            return;
        }

        static::dispatch(
            $booking,
            array_map(intval(...), array_values($changes['attached'])),
            array_map(intval(...), array_values($changes['detached'])),
            $actor,
        );
    }
}
