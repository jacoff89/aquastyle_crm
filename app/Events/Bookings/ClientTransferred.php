<?php

namespace App\Events\Bookings;

use App\Enums\AttendanceStatus;
use App\Events\AbstractDomainEvent;
use App\Events\EventDescription;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\User;

/**
 * A client was moved from one event to another. The booking is the same row, now on the new event.
 *
 * The event the client left is carried as its label and its instructors rather than as a model:
 * once it has no clients it may be deleted before a queued listener loads it back.
 */
class ClientTransferred extends AbstractDomainEvent
{
    /**
     * @param  list<int>  $fromInstructorIds
     */
    public function __construct(
        public EventClient $booking,
        public int $fromEventId,
        public string $fromEventLabel,
        public array $fromInstructorIds,
        public AttendanceStatus $previousStatus,
        ?User $actor,
    ) {
        parent::__construct($actor);
    }

    /**
     * Announce the move, describing the event the client left as it is before the move.
     */
    public static function dispatchFor(EventClient $booking, Event $from, AttendanceStatus $previousStatus, ?User $actor): void
    {
        static::dispatch($booking, $from->getKey(), self::calendarEventLabel($from), self::instructorIdsOf($from), $previousStatus, $actor);
    }

    public function describe(): ?EventDescription
    {
        $event = $this->booking->event;

        return new EventDescription(
            "Клиент {$this->booking->client->fullName()} перенесён с занятия {$this->fromEventLabel} на ".self::calendarEventLabel($event),
            self::calendarUrl($event),
            [...self::instructorIdsOf($event), ...$this->fromInstructorIds],
        );
    }
}
