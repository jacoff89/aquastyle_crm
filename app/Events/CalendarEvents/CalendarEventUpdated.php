<?php

namespace App\Events\CalendarEvents;

use App\Enums\EventStatus;
use App\Events\AbstractDomainEvent;
use App\Events\ChangeSet;
use App\Events\EventDescription;
use App\Models\Event;
use App\Models\User;
use Carbon\CarbonImmutable;

/**
 * An event in the calendar was edited: moved, resized, given another status or other details.
 * The changes that matter on their own are announced by their own events as well:
 * CalendarEventRescheduled, CalendarEventCancelled, CalendarEventCompleted and CalendarEventReopened.
 * A change of instructors is announced by CalendarEventInstructorsChanged.
 */
class CalendarEventUpdated extends AbstractDomainEvent
{
    /**
     * The event's attributes as they are named in a notice. Attributes without a label
     * (or announced by an event of their own) are not mentioned.
     *
     * @var array<string, string>
     */
    private const LABELS = [
        'title' => 'название',
        'event_type_id' => 'тип',
        'location' => 'место',
        'capacity' => 'количество мест',
        'notes' => 'заметки',
    ];

    public function __construct(public Event $event, public ChangeSet $changes, ?User $actor)
    {
        parent::__construct($actor);
    }

    /**
     * Announce what the last save of the event changed, followed by the events for a new time
     * and a new status. A save that changed nothing is not announced.
     */
    public static function dispatchChanges(Event $event, ?User $actor): void
    {
        $changes = ChangeSet::fromModel($event);

        if ($changes->isEmpty()) {
            return;
        }

        static::dispatch($event, $changes, $actor);

        if ($changes->has('starts_at', 'ends_at')) {
            CalendarEventRescheduled::dispatch(
                $event,
                $changes->has('starts_at') ? CarbonImmutable::parse($changes->old('starts_at')) : $event->starts_at->toImmutable(),
                $changes->has('ends_at') ? CarbonImmutable::parse($changes->old('ends_at')) : $event->ends_at->toImmutable(),
                $actor,
            );
        }

        if ($changes->has('status')) {
            $previousStatus = EventStatus::from($changes->old('status'));

            match ($event->status) {
                EventStatus::Cancelled => CalendarEventCancelled::dispatch($event, $previousStatus, $actor),
                EventStatus::Done => CalendarEventCompleted::dispatch($event, $previousStatus, $actor),
                EventStatus::Planned => CalendarEventReopened::dispatch($event, $previousStatus, $actor),
            };
        }
    }

    public function describe(): ?EventDescription
    {
        $changed = self::changedLabels($this->changes, self::LABELS);

        if ($changed === null) {
            return null;
        }

        return new EventDescription('Изменено занятие '.self::calendarEventLabel($this->event).": {$changed}", self::calendarUrl($this->event), self::instructorIdsOf($this->event));
    }
}
