<?php

namespace App\Http\Controllers\Settings;

use App\Events\Settings\ClientStatusCreated;
use App\Events\Settings\ClientStatusUpdated;
use App\Http\Controllers\Controller;
use App\Http\Requests\Settings\StoreClientStatusRequest;
use App\Http\Requests\Settings\UpdateClientStatusRequest;
use App\Models\ClientStatus;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

class ClientStatusController extends Controller
{
    public function index(): Response
    {
        Gate::authorize('viewAny', ClientStatus::class);

        return Inertia::render('settings/client-statuses/Index', [
            'clientStatuses' => ClientStatus::query()->withCount('clients')->ordered()->get()
                ->map(fn (ClientStatus $clientStatus): array => [
                    'id' => $clientStatus->id,
                    'name' => $clientStatus->name,
                    'isActive' => $clientStatus->is_active,
                    'clientsCount' => $clientStatus->clients_count,
                ]),
        ]);
    }

    public function store(StoreClientStatusRequest $request): RedirectResponse
    {
        $clientStatus = ClientStatus::create($request->validated());

        ClientStatusCreated::dispatch($clientStatus, $request->user());

        return back()->with('status', "Статус «{$clientStatus->name}» добавлен.");
    }

    public function update(UpdateClientStatusRequest $request, ClientStatus $clientStatus): RedirectResponse
    {
        $clientStatus->update($request->validated());
        ClientStatusUpdated::dispatchChanges($clientStatus, $request->user());

        $status = match (true) {
            $clientStatus->wasChanged('name') => "Статус переименован в «{$clientStatus->name}».",
            $clientStatus->wasChanged('is_active') && $clientStatus->is_active => "Статус «{$clientStatus->name}» снова можно выбрать для клиента.",
            $clientStatus->wasChanged('is_active') => "Статус «{$clientStatus->name}» скрыт: у кого он уже стоит, он останется, но выбрать его заново нельзя.",
            default => null,
        };

        return back()->with('status', $status);
    }
}
