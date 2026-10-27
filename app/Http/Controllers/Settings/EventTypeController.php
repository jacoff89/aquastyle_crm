<?php

namespace App\Http\Controllers\Settings;

use App\Http\Controllers\Controller;
use App\Http\Requests\Settings\StoreEventTypeRequest;
use App\Http\Requests\Settings\UpdateEventTypeRequest;
use App\Models\EventType;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

class EventTypeController extends Controller
{
    public function index(): Response
    {
        Gate::authorize('viewAny', EventType::class);

        return Inertia::render('settings/event-types/Index', [
            'eventTypes' => EventType::query()
                ->ordered()
                ->get()
                ->map(fn (EventType $eventType): array => [
                    'id' => $eventType->id,
                    'name' => $eventType->name,
                    'isActive' => $eventType->is_active,
                ]),
        ]);
    }

    public function store(StoreEventTypeRequest $request): RedirectResponse
    {
        $eventType = EventType::create($request->validated());

        return back()->with('status', "Тип «{$eventType->name}» добавлен.");
    }

    public function update(UpdateEventTypeRequest $request, EventType $eventType): RedirectResponse
    {
        $eventType->update($request->validated());

        $status = match (true) {
            $eventType->wasChanged('name') => "Тип переименован в «{$eventType->name}».",
            $eventType->wasChanged('is_active') && $eventType->is_active => "Тип «{$eventType->name}» снова доступен для новых занятий.",
            $eventType->wasChanged('is_active') => "Тип «{$eventType->name}» скрыт: для новых занятий его не будет.",
            default => null,
        };

        return back()->with('status', $status);
    }
}
