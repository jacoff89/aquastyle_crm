<?php

namespace App\Events\Bookings;

use App\Enums\AttendanceStatus;
use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Models\EventClient;
use App\Models\User;

/**
 * A client's booking on an event was changed: their status or the note.
 * A new status is announced by BookingStatusChanged as well; the exercises,
 * which live in their own table, by BookingExercisesChanged.
 */
class BookingUpdated extends AbstractDomainEvent
{
    public function __construct(public EventClient $booking, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the booking changed, followed by the new status if it changed.
     * A save that changed nothing is not announced.
     */
    public static function dispatchChanges(EventClient $booking, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($booking);

        if ($changes->isEmpty()) {
            return;
        }

        static::dispatch($booking, $changes, $actor);

        if ($changes->has('status')) {
            BookingStatusChanged::dispatch($booking, AttendanceStatus::from($changes->old('status')), $actor);
        }
    }
}
