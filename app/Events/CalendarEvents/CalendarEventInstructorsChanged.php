<?php

namespace App\Events\CalendarEvents;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Event;
use App\Models\User;

/**
 * The instructors of an event changed: someone was put on it, taken off it, or switched between
 * lead and assistant. It is dispatched for a new event too, with all of its instructors attached
 * and `forNewEvent` set, so a listener can follow every assignment; it gives no description then,
 * because the description of CalendarEventCreated already reaches the instructors of the new event.
 */
class CalendarEventInstructorsChanged extends AbstractDomainEvent
{
    /**
     * @param  list<int>  $attachedInstructorIds  instructors put on the event
     * @param  list<int>  $detachedInstructorIds  instructors taken off the event
     * @param  list<int>  $roleChangedInstructorIds  instructors who stayed but became the lead or an assistant
     * @param  bool  $forNewEvent  whether the instructors were assigned to an event that was just created
     */
    public function __construct(
        public Event $event,
        public array $attachedInstructorIds,
        public array $detachedInstructorIds,
        public array $roleChangedInstructorIds,
        ?User $actor,
        public bool $forNewEvent = false,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the result of Event::assignInstructors(), unless nothing changed.
     *
     * @param  array{attached: list<int>, detached: list<int>, updated: list<int>}  $changes
     */
    public static function dispatchFor(Event $event, array $changes, ?User $actor, bool $forNewEvent = false): void
    {
        if ($changes['attached'] === [] && $changes['detached'] === [] && $changes['updated'] === []) {
            return;
        }

        static::dispatch($event, $changes['attached'], $changes['detached'], $changes['updated'], $actor, $forNewEvent);
    }

    public function describe(): ?EventDescription
    {
        if ($this->forNewEvent) {
            return null;
        }

        $this->event->load('instructors');
        $parts = [];

        if ($this->attachedInstructorIds !== []) {
            $parts[] = 'назначены '.$this->instructorsWithRoles($this->attachedInstructorIds);
        }

        if ($this->detachedInstructorIds !== []) {
            $parts[] = 'сняты '.self::userNames($this->detachedInstructorIds);
        }

        if ($this->roleChangedInstructorIds !== []) {
            $parts[] = 'сменили роль '.$this->instructorsWithRoles($this->roleChangedInstructorIds);
        }

        return new EventDescription(
            'Инструкторы занятия '.self::calendarEventLabel($this->event).': '.implode('; ', $parts),
            self::calendarUrl($this->event),
            [...$this->attachedInstructorIds, ...$this->detachedInstructorIds, ...$this->roleChangedInstructorIds],
        );
    }

    /**
     * "Иван Петров (ведущий), Анна (помощник)" for those of the given instructors who are on the event.
     *
     * @param  list<int>  $instructorIds
     */
    private function instructorsWithRoles(array $instructorIds): string
    {
        return $this->event->instructors
            ->whereIn('id', $instructorIds)
            ->map(fn (User $instructor): string => $instructor->fullName().' ('.mb_strtolower($instructor->pivot->role->label()).')')
            ->implode(', ');
    }
}
