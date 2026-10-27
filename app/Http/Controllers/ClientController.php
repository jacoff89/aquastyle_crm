<?php

namespace App\Http\Controllers;

use App\Http\Requests\Clients\StoreClientRequest;
use App\Http\Requests\Clients\UpdateClientRequest;
use App\Models\Client;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * The client directory. Clients are soft-deleted, so past classes keep their client.
 */
class ClientController extends Controller
{
    private const PER_PAGE = 25;

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

    public function store(StoreClientRequest $request): RedirectResponse
    {
        $client = new Client(Arr::except($request->validated(), ['confirm_duplicate']));
        $client->creator()->associate($request->user());
        $client->save();

        return redirect()->route('clients.show', $client)->with('status', "Добавлен клиент: {$client->fullName()}.");
    }

    public function show(Request $request, Client $client): Response
    {
        Gate::authorize('view', $client);

        return Inertia::render('clients/Show', [
            'client' => [
                ...$this->formData($client),
                'fullName' => $client->fullName(),
                'birthDateLabel' => $client->birth_date?->format('d.m.Y'),
            ],
            'canDelete' => $request->user()->can('delete', $client),
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
}
