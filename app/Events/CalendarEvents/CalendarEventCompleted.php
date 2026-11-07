<?php

namespace App\Events\CalendarEvents;

use App\Enums\EventStatus;
use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
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

    public function describe(): ?EventDescription
    {
        return new EventDescription('Проведено занятие '.self::calendarEventLabel($this->event), self::calendarUrl($this->event), self::instructorIdsOf($this->event));
    }
}
