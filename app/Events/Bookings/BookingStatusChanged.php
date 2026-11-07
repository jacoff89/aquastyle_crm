<?php

namespace App\Events\Bookings;

use App\Enums\AttendanceStatus;
use App\Events\AbstractDomainEvent;
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
}
