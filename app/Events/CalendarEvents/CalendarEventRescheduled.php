<?php

namespace App\Events\CalendarEvents;

use App\Actions\FindInstructorConflicts;
use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Event;
use App\Models\User;
use Carbon\CarbonImmutable;

/**
 * An event got another start or end: it was moved or resized in the calendar, or its time was edited.
 * The new time is on the event; the previous one is carried here.
 */
class CalendarEventRescheduled extends AbstractDomainEvent
{
    public function __construct(
        public Event $event,
        public CarbonImmutable $previousStartsAt,
        public CarbonImmutable $previousEndsAt,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    public function describe(): ?EventDescription
    {
        $previous = FindInstructorConflicts::period($this->previousStartsAt, $this->previousEndsAt);
        $current = FindInstructorConflicts::period($this->event->starts_at, $this->event->ends_at);

        return new EventDescription(
            "Занятие «{$this->event->displayTitle()}» перенесено с {$previous} на {$current}",
            self::calendarUrl($this->event),
            self::instructorIdsOf($this->event),
        );
    }
}
