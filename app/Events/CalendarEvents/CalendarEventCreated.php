<?php

namespace App\Events\CalendarEvents;

use App\Events\AbstractDomainEvent;
use App\Models\Event;
use App\Models\User;

/**
 * An event was added to the calendar. It is dispatched once its instructors are assigned;
 * the assignment itself is announced by CalendarEventInstructorsChanged as well.
 */
class CalendarEventCreated extends AbstractDomainEvent
{
    public function __construct(public Event $event, ?User $actor)
    {
        parent::__construct($actor);
    }
}
