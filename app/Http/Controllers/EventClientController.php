<?php

namespace App\Http\Controllers;

use App\Actions\BookClientOnEvent;
use App\Actions\ChangeClientAttendance;
use App\Http\Requests\Events\BookClientRequest;
use App\Http\Requests\Events\UpdateEventClientRequest;
use App\Http\Resources\EventClientResource;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Gate;

/**
 * The clients of one event, as the event window shows them: who is booked, who came.
 * Every answer is the whole list with the places taken, so the window needs no second request.
 *
 * Booking a client and changing a booking are open to both roles. Recording who came
 * (or did not) is limited to administrators and the event's own instructors.
 */
class EventClientController extends Controller
{
    public function index(Request $request, Event $event): JsonResponse
    {
        Gate::authorize('view', $event);

        return $this->listing($request, $event);
    }

    public function store(BookClientRequest $request, Event $event, BookClientOnEvent $bookClient): JsonResponse
    {
        $bookClient->handle($event, $request->client(), $request->validated('notes'));

        return $this->listing($request, $event, 201);
    }

    public function update(UpdateEventClientRequest $request, Event $event, Client $client, ChangeClientAttendance $changeAttendance): JsonResponse
    {
        $booking = $event->bookings()->whereBelongsTo($client)->firstOrFail();

        $recordsAttendance = $booking->status->isAttendanceMark() || $request->status()->isAttendanceMark();
        Gate::authorize($recordsAttendance ? 'markAttendance' : 'manageClients', $event);

        $changeAttendance->handle($event, $booking, $request->changes());

        return $this->listing($request, $event);
    }

    private function listing(Request $request, Event $event, int $status = 200): JsonResponse
    {
        $bookings = $event->bookings()
            ->select('event_client.*')
            ->join('clients', 'clients.id', '=', 'event_client.client_id')
            ->with('client')
            ->orderBy('clients.last_name')
            ->orderBy('clients.first_name')
            ->orderBy('clients.middle_name')
            ->orderBy('event_client.id')
            ->get();

        return EventClientResource::collection($bookings)
            ->additional(['meta' => [
                'capacity' => $event->capacity,
                'occupied' => $bookings->filter(fn (EventClient $booking): bool => $booking->status->occupiesPlace())->count(),
                'canManage' => $request->user()->can('manageClients', $event),
                'canMarkAttendance' => $request->user()->can('markAttendance', $event),
            ]])
            ->response()
            ->setStatusCode($status);
    }
}
