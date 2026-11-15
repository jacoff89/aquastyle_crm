<?php

namespace App\Http\Controllers;

use App\Actions\BookClientOnEvent;
use App\Actions\ChangeClientAttendance;
use App\Actions\TransferClientToEvent;
use App\Enums\EventStatus;
use App\Http\Requests\Events\BookClientRequest;
use App\Http\Requests\Events\TransferClientRequest;
use App\Http\Requests\Events\UpdateEventClientRequest;
use App\Http\Resources\EventClientResource;
use App\Http\Resources\TransferTargetResource;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use App\Models\Exercise;
use Illuminate\Database\Eloquent\Builder;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Http\Resources\Json\AnonymousResourceCollection;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Gate;

/**
 * The clients of one event, as the event window shows them: who is booked, who came.
 * Every answer is the whole list with the places taken, so the window needs no second request.
 * The exercises offered are the active ones of the event's type (or of its parent).
 *
 * Booking a client and changing a booking are open to both roles. Recording who came
 * (or did not) is limited to administrators and the event's own instructors.
 *
 * Moving a client to another event is for administrators, and for an instructor who leads
 * both events: the events offered for the move are the ones the person may move the client to.
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
        $bookClient->handle($event, $request->client(), $request->user(), $request->validated('notes'));

        return $this->listing($request, $event, 201);
    }

    public function update(UpdateEventClientRequest $request, Event $event, Client $client, ChangeClientAttendance $changeAttendance): JsonResponse
    {
        $booking = $event->bookings()->whereBelongsTo($client)->firstOrFail();

        $recordsAttendance = $booking->status->isAttendanceMark() || $request->status()->isAttendanceMark();
        Gate::authorize($recordsAttendance ? 'markAttendance' : 'manageClients', $event);

        $changeAttendance->handle($event, $booking, $request->changes(), $request->user());

        return $this->listing($request, $event);
    }

    /**
     * The planned events of the given day the client can be moved to: every one for an administrator,
     * the ones the instructor leads otherwise. Full events and events that already have the client
     * are listed too, marked, so that the person sees why they are not offered.
     */
    public function transferTargets(Request $request, Event $event, Client $client): AnonymousResourceCollection
    {
        Gate::authorize('transferClientsFrom', $event);

        $validated = $request->validate([
            'date' => ['required', 'date_format:Y-m-d'],
        ]);

        $day = Carbon::createFromFormat('Y-m-d', $validated['date'])->startOfDay();

        $targets = Event::query()
            ->with(['type', 'instructors'])
            ->withOccupiedPlacesCount()
            ->withExists(['bookings as has_client' => fn (Builder $bookings) => $bookings->whereBelongsTo($client)])
            ->overlapping($day, $day->copy()->addDay())
            ->where('status', EventStatus::Planned->value)
            ->whereKeyNot($event->getKey())
            ->unless($request->user()->isAdmin(), fn (Builder $query) => $query->ledBy($request->user()))
            ->orderBy('starts_at')
            ->orderBy('id')
            ->get();

        return TransferTargetResource::collection($targets);
    }

    /**
     * Moves the client to the chosen event and answers with the list of the event they left.
     */
    public function transfer(TransferClientRequest $request, Event $event, Client $client, TransferClientToEvent $transferClient): JsonResponse
    {
        $target = $request->targetEvent();
        Gate::authorize('transferClient', [$event, $target]);

        $booking = $event->bookings()->whereBelongsTo($client)->firstOrFail();
        $transferClient->handle($event, $booking, $target, $request->user());

        return $this->listing($request, $event);
    }

    private function listing(Request $request, Event $event, int $status = 200): JsonResponse
    {
        $bookings = $event->bookings()
            ->select('event_client.*')
            ->join('clients', 'clients.id', '=', 'event_client.client_id')
            ->with(['client', 'exercises'])
            ->orderBy('clients.last_name')
            ->orderBy('clients.first_name')
            ->orderBy('clients.middle_name')
            ->orderBy('event_client.id')
            ->get();

        $offeredExercises = Exercise::query()->active()->forEventType($event->type)->ordered()->get();

        EventClient::loadExercisesDoneElsewhere($bookings, $offeredExercises->modelKeys());

        return EventClientResource::collection($bookings)
            ->additional(['meta' => [
                'capacity' => $event->capacity,
                'occupied' => $bookings->filter(fn (EventClient $booking): bool => $booking->status->occupiesPlace())->count(),
                'canManage' => $request->user()->can('manageClients', $event),
                'canMarkAttendance' => $request->user()->can('markAttendance', $event),
                'canTransfer' => $request->user()->can('transferClientsFrom', $event),
                'exercises' => $offeredExercises
                    ->map(fn (Exercise $exercise): array => ['id' => $exercise->id, 'name' => $exercise->name])
                    ->all(),
            ]])
            ->response()
            ->setStatusCode($status);
    }
}
