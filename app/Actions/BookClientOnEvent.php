<?php

namespace App\Actions;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Events\Bookings\ClientBooked;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\User;
use Illuminate\Support\Facades\DB;
use Illuminate\Validation\ValidationException;

/**
 * Books a client on an event. A cancelled event takes no bookings, a client is booked
 * only once, and an event with a capacity stops taking bookings when it is full.
 * The booking is announced with ClientBooked.
 */
class BookClientOnEvent
{
    /**
     * @throws ValidationException
     */
    public function handle(Event $event, Client $client, ?User $actor, ?string $notes = null): EventClient
    {
        return DB::transaction(function () use ($event, $client, $actor, $notes): EventClient {
            // Locking the event makes two people booking the last place at once take turns.
            $event = Event::query()->whereKey($event->getKey())->lockForUpdate()->firstOrFail();

            if ($event->status === EventStatus::Cancelled) {
                throw ValidationException::withMessages(['client_id' => 'Занятие отменено, записать клиента нельзя.']);
            }

            if ($event->bookings()->whereBelongsTo($client)->exists()) {
                throw ValidationException::withMessages(['client_id' => 'Клиент уже есть в списке этого занятия.']);
            }

            if (! $event->hasFreePlace()) {
                throw ValidationException::withMessages(['client_id' => 'На занятии нет свободных мест.']);
            }

            $booking = $event->bookings()->create([
                'client_id' => $client->getKey(),
                'status' => AttendanceStatus::Booked,
                'notes' => $notes,
            ]);

            ClientBooked::dispatch($booking, $actor);

            return $booking;
        });
    }
}
