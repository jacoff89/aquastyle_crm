<?php

namespace App\Actions;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Events\Bookings\BookingExercisesChanged;
use App\Events\Bookings\BookingUpdated;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Changes a client's status on an event, and optionally the note and the exercises on the booking.
 * Bringing a client who cancelled or did not come back takes a place again, so it needs
 * a free one. The statuses of a cancelled event are frozen: its clients can only be
 * marked as cancelled.
 *
 * The changes are announced with BookingUpdated, BookingStatusChanged and BookingExercisesChanged.
 */
class ChangeClientAttendance
{
    /**
     * @param  array{status: AttendanceStatus, notes?: ?string, exercise_ids?: list<int>}  $changes
     *
     * @throws ValidationException
     */
    public function handle(Event $event, EventClient $booking, array $changes, ?User $actor): EventClient
    {
        return DB::transaction(function () use ($event, $booking, $changes, $actor): EventClient {
            // Locking the event makes two people taking the last place at once take turns.
            $event = Event::query()->whereKey($event->getKey())->lockForUpdate()->firstOrFail();
            $booking->refresh();
            $status = $changes['status'];

            if ($status !== $booking->status) {
                if ($event->status === EventStatus::Cancelled && $status !== AttendanceStatus::Cancelled) {
                    throw ValidationException::withMessages(['status' => 'Занятие отменено, статус клиента изменить нельзя.']);
                }

                if ($status->occupiesPlace() && ! $booking->status->occupiesPlace() && ! $event->hasFreePlace()) {
                    throw ValidationException::withMessages(['status' => 'На занятии нет свободных мест.']);
                }
            }

            $booking->status = $status;

            if (array_key_exists('notes', $changes)) {
                $booking->notes = $changes['notes'];
            }

            $booking->save();
            BookingUpdated::dispatchChanges($booking, $actor);

            if (array_key_exists('exercise_ids', $changes)) {
                BookingExercisesChanged::dispatchFor($booking, $booking->exercises()->sync($changes['exercise_ids']), $actor);
            }

            return $booking;
        });
    }
}
