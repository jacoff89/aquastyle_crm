<?php

namespace App\Events\CalendarEvents;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Event;
use App\Models\User;

/**
 * An event without clients was deleted. Events are deleted for good, so a queued listener could
 * not load the model back; the event carries what its description needs instead.
 */
class CalendarEventDeleted extends AbstractDomainEvent
{
    /**
     * @param  string  $label  the event as it reads in a notice, see DescribesEvents::calendarEventLabel()
     * @param  string  $calendarUrl  the day of the event in the calendar
     * @param  list<int>  $instructorIds  the lead instructor and the assistants
     */
    public function __construct(
        public int $eventId,
        public string $label,
        public string $calendarUrl,
        public array $instructorIds,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the deletion. Call it before delete(), while the event still has its instructors.
     */
    public static function dispatchFor(Event $event, ?User $actor): void
    {
        static::dispatch($event->getKey(), self::calendarEventLabel($event), self::calendarUrl($event), self::instructorIdsOf($event), $actor);
    }

    public function describe(): ?EventDescription
    {
        return new EventDescription("Удалено занятие {$this->label}", $this->calendarUrl, $this->instructorIds);
    }
}
