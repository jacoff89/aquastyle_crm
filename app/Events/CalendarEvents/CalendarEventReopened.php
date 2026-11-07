<?php

namespace App\Events\CalendarEvents;

use App\Enums\EventStatus;
use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        return new EventDescription('Занятие '.self::calendarEventLabel($this->event).' снова запланировано', self::calendarUrl($this->event), self::instructorIdsOf($this->event));
    }
}
