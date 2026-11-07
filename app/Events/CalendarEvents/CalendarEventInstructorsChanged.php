<?php

namespace App\Events\CalendarEvents;

use App\Events\AbstractDomainEvent;
use App\Models\Event;
use App\Models\User;

/**
 * The instructors of an event changed: someone was put on it, taken off it, or switched between
 * lead and assistant. It is dispatched for a new event too, with all of its instructors attached,
 * so one listener can tell every instructor about every assignment.
 */
class CalendarEventInstructorsChanged extends AbstractDomainEvent
{
    /**
     * @param  list<int>  $attachedInstructorIds  instructors put on the event
     * @param  list<int>  $detachedInstructorIds  instructors taken off the event
     * @param  list<int>  $roleChangedInstructorIds  instructors who stayed but became the lead or an assistant
     */
    public function __construct(
        public Event $event,
        public array $attachedInstructorIds,
        public array $detachedInstructorIds,
        public array $roleChangedInstructorIds,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the result of Event::assignInstructors(), unless nothing changed.
     *
     * @param  array{attached: list<int>, detached: list<int>, updated: list<int>}  $changes
     */
    public static function dispatchFor(Event $event, array $changes, ?User $actor): void
    {
        if ($changes['attached'] === [] && $changes['detached'] === [] && $changes['updated'] === []) {
            return;
        }

        static::dispatch($event, $changes['attached'], $changes['detached'], $changes['updated'], $actor);
    }
}
