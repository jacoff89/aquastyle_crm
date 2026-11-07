<?php

namespace App\Events\CalendarEvents;

use App\Enums\EventStatus;
use App\Events\AbstractDomainEvent;
use App\Models\Event;
use App\Models\User;

/**
 * An event was marked as having taken place.
 */
class CalendarEventCompleted extends AbstractDomainEvent
{
    public function __construct(public Event $event, public EventStatus $previousStatus, ?User $actor)
    {
        parent::__construct($actor);
    }
}
