<?php

namespace App\Events\Settings;

use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\EventType;
use App\Models\Exercise;
use App\Models\User;

/**
 * The event types an exercise is offered for changed.
 */
class ExerciseEventTypesChanged extends AbstractDomainEvent
{
    /**
     * @param  list<int>  $attachedEventTypeIds
     * @param  list<int>  $detachedEventTypeIds
     */
    public function __construct(
        public Exercise $exercise,
        public array $attachedEventTypeIds,
        public array $detachedEventTypeIds,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the result of syncing the exercise's event types, unless nothing changed.
     *
     * @param  array{attached: array<int, int|string>, detached: array<int, int|string>, updated: array<int, int|string>}  $changes
     */
    public static function dispatchFor(Exercise $exercise, array $changes, ?User $actor): void
    {
        if ($changes['attached'] === [] && $changes['detached'] === []) {
            return;
        }

        static::dispatch(
            $exercise,
            array_map(intval(...), array_values($changes['attached'])),
            array_map(intval(...), array_values($changes['detached'])),
            $actor,
        );
    }

    public function describe(): ?EventDescription
    {
        $parts = [];

        if ($this->attachedEventTypeIds !== []) {
            $parts[] = 'добавлены типы '.self::eventTypeNames($this->attachedEventTypeIds);
        }

        if ($this->detachedEventTypeIds !== []) {
            $parts[] = 'убраны типы '.self::eventTypeNames($this->detachedEventTypeIds);
        }

        return new EventDescription("Упражнение «{$this->exercise->name}»: ".implode('; ', $parts), route('settings.exercises.index'));
    }

    /**
     * @param  list<int>  $eventTypeIds
     */
    private static function eventTypeNames(array $eventTypeIds): string
    {
        return EventType::query()->whereKey($eventTypeIds)->ordered()->get()
            ->map(fn (EventType $eventType): string => "«{$eventType->full_name}»")
            ->implode(', ');
    }
}
