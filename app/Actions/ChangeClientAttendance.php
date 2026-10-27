<?php

namespace App\Actions;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Models\Event;
use App\Models\EventClient;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Changes a client's status on an event, and optionally the note on the booking.
 * Bringing a client who cancelled or did not come back takes a place again, so it needs
 * a free one. The statuses of a cancelled event are frozen: its clients can only be
 * marked as cancelled.
 */
class ChangeClientAttendance
{
    /**
     * @param  array{status: AttendanceStatus, notes?: ?string}  $changes
     *
     * @throws ValidationException
     */
    public function handle(Event $event, EventClient $booking, array $changes): EventClient
    {
        return DB::transaction(function () use ($event, $booking, $changes): EventClient {
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

            return $booking;
        });
    }
}
