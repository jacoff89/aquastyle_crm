<?php

namespace App\Events\Bookings;

use App\Enums\AttendanceStatus;
use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\EventClient;
use App\Models\User;

/**
 * A client's status on an event changed: they came, did not come, cancelled or were booked again.
 * The new status is on the booking; the previous one is carried here.
 */
class BookingStatusChanged extends AbstractDomainEvent
{
    public function __construct(public EventClient $booking, public AttendanceStatus $previousStatus, ?User $actor)
    {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        $event = $this->booking->event;
        $status = mb_strtolower($this->booking->status->label());
        $previous = mb_strtolower($this->previousStatus->label());

        return new EventDescription(
            "Клиент {$this->booking->client->fullName()} на занятии ".self::calendarEventLabel($event).": {$status} (было: {$previous})",
            self::calendarUrl($event),
            self::instructorIdsOf($event),
        );
    }
}
