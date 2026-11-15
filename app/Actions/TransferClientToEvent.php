<?php

namespace App\Actions;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Events\Bookings\ClientTransferred;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Moves a client's booking from one event to another. The booking row itself moves,
 * so its note and exercises go with it, and the client is booked on the new event.
 *
 * Only a planned event takes the client, past ones included; it must have a free place and
 * not have the client already. A client who came or did not come stays where it happened.
 * The move is announced with ClientTransferred.
 */
class TransferClientToEvent
{
    /**
     * @throws ValidationException
     */
    public function handle(Event $from, EventClient $booking, Event $to, ?User $actor): EventClient
    {
        if ($from->is($to)) {
            throw ValidationException::withMessages(['target_event_id' => 'Выберите другое занятие.']);
        }

        return DB::transaction(function () use ($from, $booking, $to, $actor): EventClient {
            // Both events are locked in the same order, so two moves in opposite directions take turns instead of deadlocking.
            $events = Event::query()->whereKey([$from->getKey(), $to->getKey()])->orderBy('id')->lockForUpdate()->get()->keyBy('id');
            $from = $events->get($from->getKey()) ?? throw ValidationException::withMessages(['target_event_id' => 'Занятие не найдено.']);
            $to = $events->get($to->getKey()) ?? throw ValidationException::withMessages(['target_event_id' => 'Занятие не найдено.']);
            $booking->refresh();

            if ((int) $booking->event_id !== (int) $from->getKey()) {
                throw ValidationException::withMessages(['target_event_id' => 'Клиента уже нет в списке этого занятия.']);
            }

            if (! $booking->status->isTransferable()) {
                throw ValidationException::withMessages(['target_event_id' => 'Клиент уже отмечен на занятии, перенести его нельзя.']);
            }

            if ($to->status !== EventStatus::Planned) {
                throw ValidationException::withMessages(['target_event_id' => 'Перенести можно только на запланированное занятие.']);
            }

            if ($to->bookings()->where('client_id', $booking->client_id)->exists()) {
                throw ValidationException::withMessages(['target_event_id' => 'Клиент уже есть в списке этого занятия.']);
            }

            if (! $to->hasFreePlace()) {
                throw ValidationException::withMessages(['target_event_id' => 'На занятии нет свободных мест.']);
            }

            $previousStatus = $booking->status;
            $booking->event()->associate($to);
            $booking->status = AttendanceStatus::Booked;
            $booking->save();

            ClientTransferred::dispatchFor($booking, $from, $previousStatus, $actor);

            return $booking;
        });
    }
}
