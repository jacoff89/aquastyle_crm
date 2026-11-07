<?php

namespace App\Events\Bookings;

use App\Events\AbstractDomainEvent;
use App\Models\EventClient;
use App\Models\User;

/**
 * A client was booked on an event. The booking holds both the event and the client.
 */
class ClientBooked extends AbstractDomainEvent
{
    public function __construct(public EventClient $booking, ?User $actor)
    {
        parent::__construct($actor);
    }
}
