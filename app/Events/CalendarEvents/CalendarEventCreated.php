<?php

namespace App\Events\CalendarEvents;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        $lead = $this->event->leadInstructor();

        return new EventDescription(
            'Новое занятие '.self::calendarEventLabel($this->event).($lead === null ? '' : ", ведущий {$lead->fullName()}"),
            self::calendarUrl($this->event),
            self::instructorIdsOf($this->event),
        );
    }
}
