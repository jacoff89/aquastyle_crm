<?php

namespace App\Events\Bookings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        $event = $this->booking->event;

        return new EventDescription(
            "Клиент {$this->booking->client->fullName()} записан на занятие ".self::calendarEventLabel($event),
            self::calendarUrl($event),
            self::instructorIdsOf($event),
        );
    }
}
