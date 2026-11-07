<?php

namespace App\Events\CalendarEvents;

use App\Enums\EventStatus;
use App\Events\AbstractDomainEvent;
use App\Models\Event;
use App\Models\User;

/**
 * A cancelled event, or one marked as having taken place, was brought back to planned.
 */
class CalendarEventReopened extends AbstractDomainEvent
{
    public function __construct(public Event $event, public EventStatus $previousStatus, ?User $actor)
    {
        parent::__construct($actor);
    }
}
