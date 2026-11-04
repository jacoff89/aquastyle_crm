<?php

namespace App\Http\Controllers\Settings;

use App\Http\Controllers\Controller;
use App\Http\Requests\Settings\StoreExerciseRequest;
use App\Http\Requests\Settings\UpdateExerciseRequest;
use App\Models\EventType;
use App\Models\Exercise;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

class ExerciseController extends Controller
{
    public function index(): Response
    {
        Gate::authorize('viewAny', Exercise::class);

        return Inertia::render('settings/exercises/Index', [
            'exercises' => Exercise::query()->with('eventTypes:id')->ordered()->get()
                ->map(fn (Exercise $exercise): array => [
                    'id' => $exercise->id,
                    'name' => $exercise->name,
                    'isActive' => $exercise->is_active,
                    'eventTypeIds' => $exercise->eventTypes->modelKeys(),
                ]),
            'eventTypes' => EventType::inTreeOrder()
                ->map(fn (EventType $eventType): array => [
                    'id' => $eventType->id,
                    'parentId' => $eventType->parent_id,
                    'name' => $eventType->name,
                    'isActive' => $eventType->is_active,
                ]),
        ]);
    }

    public function store(StoreExerciseRequest $request): RedirectResponse
    {
        $exercise = Exercise::create($request->validated());

        return back()->with('status', "Упражнение «{$exercise->name}» добавлено.");
    }

    public function update(UpdateExerciseRequest $request, Exercise $exercise): RedirectResponse
    {
        $exercise->update($request->safe()->except('event_type_ids'));

        $typesChanged = $request->has('event_type_ids')
            && collect($exercise->eventTypes()->sync($request->eventTypeIds()))->flatten()->isNotEmpty();

        $status = match (true) {
            $typesChanged => "Типы занятий для «{$exercise->name}» сохранены.",
            $exercise->wasChanged('name') => "Упражнение переименовано в «{$exercise->name}».",
            $exercise->wasChanged('is_active') && $exercise->is_active => "Упражнение «{$exercise->name}» снова доступно для выбора.",
            $exercise->wasChanged('is_active') => "Упражнение «{$exercise->name}» скрыто: выбрать его для клиента больше нельзя.",
            default => null,
        };

        return back()->with('status', $status);
    }
}
