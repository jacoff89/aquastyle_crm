<?php

namespace App\Http\Controllers;

use App\Enums\AttendanceStatus;
use App\Enums\EventStatus;
use App\Http\Requests\Clients\StoreClientRequest;
use App\Http\Requests\Clients\UpdateClientRequest;
use App\Models\Client;
use App\Models\Event;
use App\Models\EventClient;
use Carbon\CarbonInterface;
use Illuminate\Database\Eloquent\Relations\BelongsToMany;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The client directory. Clients are soft-deleted, so past classes keep their client.
 *
 * The event window adds a client with a JSON request and gets the new client back,
 * so the person does not leave the calendar.
 */
class ClientController extends Controller
{
    private const PER_PAGE = 25;

    private const HISTORY_LIMIT = 50;

    /**
     * Sort keys offered in the list header, mapped to the columns they order by.
     *
     * @var array<string, list<string>>
     */
    private const SORTS = [
        'name' => ['last_name', 'first_name', 'middle_name'],
        'phone' => ['phone_digits'],
        'created' => ['created_at'],
    ];

    public function index(Request $request): Response
    {
        Gate::authorize('viewAny', Client::class);

        $search = trim((string) $request->query('search', ''));
        $sort = array_key_exists((string) $request->query('sort'), self::SORTS) ? (string) $request->query('sort') : 'name';
        $direction = $request->query('direction') === 'desc' ? 'desc' : 'asc';

        $query = Client::query()->search($search);

        foreach (self::SORTS[$sort] as $column) {
            $query->orderBy($column, $direction);
        }

        $clients = $query->orderBy('id', $direction)->paginate(self::PER_PAGE)->withQueryString();

        return Inertia::render('clients/Index', [
            'clients' => [
                'data' => $clients->getCollection()->map(fn (Client $client): array => [
                    'id' => $client->id,
                    'name' => $client->fullName(),
                    'phone' => $client->phone,
                    'email' => $client->email,
                    'createdAtLabel' => $client->created_at->format('d.m.Y'),
                ])->values(),
                'currentPage' => $clients->currentPage(),
                'lastPage' => $clients->lastPage(),
                'total' => $clients->total(),
                'from' => $clients->firstItem(),
                'to' => $clients->lastItem(),
                'previousPageUrl' => $clients->previousPageUrl(),
                'nextPageUrl' => $clients->nextPageUrl(),
            ],
            'filters' => [
                'search' => $search,
                'sort' => $sort,
                'direction' => $direction,
            ],
        ]);
    }

    public function create(): Response
    {
        Gate::authorize('create', Client::class);

        return Inertia::render('clients/Form', [
            'client' => null,
        ]);
    }

    public function store(StoreClientRequest $request): RedirectResponse|JsonResponse
    {
        $client = new Client(Arr::except($request->validated(), ['confirm_duplicate']));
        $client->creator()->associate($request->user());
        $client->save();

        if ($request->wantsJson()) {
            return response()->json([
                'client' => [
                    'id' => $client->id,
                    'name' => $client->fullName(),
                    'phone' => $client->phone,
                ],
            ], 201);
        }

        return redirect()->route('clients.show', $client)->with('status', "Добавлен клиент: {$client->fullName()}.");
    }

    public function show(Request $request, Client $client): Response
    {
        Gate::authorize('view', $client);

        $now = now();

        return Inertia::render('clients/Show', [
            'client' => [
                ...$this->formData($client),
                'fullName' => $client->fullName(),
                'birthDateLabel' => $client->birth_date?->format('d.m.Y'),
            ],
            'canDelete' => $request->user()->can('delete', $client),
            'upcoming' => $this->upcomingBookings($client, $now)->get()->map($this->bookingRow(...))->values(),
            'history' => $this->pastBookings($client, $now)->limit(self::HISTORY_LIMIT)->get()->map($this->bookingRow(...))->values(),
            'historyTotal' => $this->pastBookings($client, $now)->count(),
        ]);
    }

    public function edit(Client $client): Response
    {
        Gate::authorize('update', $client);

        return Inertia::render('clients/Form', [
            'client' => $this->formData($client),
        ]);
    }

    public function update(UpdateClientRequest $request, Client $client): RedirectResponse
    {
        $client->update(Arr::except($request->validated(), ['confirm_duplicate']));

        return redirect()->route('clients.show', $client)->with('status', "Изменения сохранены: {$client->fullName()}.");
    }

    public function destroy(Client $client): RedirectResponse
    {
        Gate::authorize('delete', $client);

        $client->delete();

        return redirect()->route('clients.index')->with('status', "Клиент удалён: {$client->fullName()}. История занятий сохранится.");
    }

    /**
     * @return array{id: int, lastName: string, firstName: string, middleName: ?string, phone: string, email: ?string, birthDate: ?string, notes: ?string}
     */
    private function formData(Client $client): array
    {
        return [
            'id' => $client->id,
            'lastName' => $client->last_name,
            'firstName' => $client->first_name,
            'middleName' => $client->middle_name,
            'phone' => $client->phone,
            'email' => $client->email,
            'birthDate' => $client->birth_date?->format('Y-m-d'),
            'notes' => $client->notes,
        ];
    }

    /**
     * The client's bookings that are still ahead: booked, on an event that has not ended
     * and is not cancelled. The soonest first.
     *
     * @return BelongsToMany<Event, Client, EventClient, 'pivot'>
     */
    private function upcomingBookings(Client $client, CarbonInterface $now): BelongsToMany
    {
        return $client->events()
            ->where('event_client.status', AttendanceStatus::Booked->value)
            ->where('events.status', '!=', EventStatus::Cancelled->value)
            ->where('events.ends_at', '>=', $now)
            ->with(['type', 'instructors'])
            ->orderBy('events.starts_at')
            ->orderBy('events.id');
    }

    /**
     * Everything that is not upcoming: classes that took place, cancelled events and
     * bookings the client cancelled. The latest first.
     *
     * @return BelongsToMany<Event, Client, EventClient, 'pivot'>
     */
    private function pastBookings(Client $client, CarbonInterface $now): BelongsToMany
    {
        return $client->events()
            ->where(fn ($query) => $query
                ->where('event_client.status', '!=', AttendanceStatus::Booked->value)
                ->orWhere('events.status', EventStatus::Cancelled->value)
                ->orWhere('events.ends_at', '<', $now))
            ->with(['type', 'instructors'])
            ->orderByDesc('events.starts_at')
            ->orderByDesc('events.id');
    }

    /**
     * One line of the client's classes: when, what and where, and what happened to the client.
     *
     * @return array<string, mixed>
     */
    private function bookingRow(Event $event): array
    {
        $isMultiDay = ! $event->starts_at->isSameDay($event->ends_at);

        return [
            'eventId' => $event->id,
            'title' => $event->displayTitle(),
            'dateLabel' => $event->starts_at->format('d.m.Y'),
            'timeLabel' => $event->starts_at->format('H:i').($isMultiDay ? ' – '.$event->ends_at->format('d.m H:i') : '–'.$event->ends_at->format('H:i')),
            'location' => $event->location,
            'leadInstructor' => $event->leadInstructor()?->name,
            'isEventCancelled' => $event->status === EventStatus::Cancelled,
            'status' => $event->pivot->status->value,
            'statusLabel' => $event->pivot->status->label(),
            'calendarUrl' => route('calendar', ['view' => 'day', 'date' => $event->starts_at->format('Y-m-d')]),
        ];
    }
}
