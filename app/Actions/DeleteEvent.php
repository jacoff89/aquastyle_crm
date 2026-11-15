<?php

namespace App\Actions;

use App\Events\CalendarEvents\CalendarEventDeleted;
use App\Models\Event;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Deletes an event for good. Only an event without clients can go: a client who cancelled
 * keeps it too, so the history of every booking stays. Its instructors go with it.
 * The deletion is announced with CalendarEventDeleted.
 */
class DeleteEvent
{
    /**
     * @throws ValidationException
     */
    public function handle(Event $event, ?User $actor): void
    {
        DB::transaction(function () use ($event, $actor): void {
            // Locking the event makes a booking made at the same moment either come first and stop the deletion, or wait for it.
            $event = Event::query()->whereKey($event->getKey())->lockForUpdate()->firstOrFail();

            if ($event->bookings()->exists()) {
                throw ValidationException::withMessages(['event' => 'На занятии есть клиенты — перенесите их на другое занятие или отмените занятие.']);
            }

            CalendarEventDeleted::dispatchFor($event, $actor);

            $event->delete();
        });
    }
}
