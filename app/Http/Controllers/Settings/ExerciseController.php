<?php

namespace App\Http\Controllers\Settings;

use App\Http\Controllers\Controller;
use App\Http\Requests\Settings\StoreExerciseRequest;
use App\Http\Requests\Settings\UpdateExerciseRequest;
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
            'exercises' => Exercise::query()->ordered()->get()
                ->map(fn (Exercise $exercise): array => [
                    'id' => $exercise->id,
                    'name' => $exercise->name,
                    'isActive' => $exercise->is_active,
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
        $exercise->update($request->validated());

        $status = match (true) {
            $exercise->wasChanged('name') => "Упражнение переименовано в «{$exercise->name}».",
            $exercise->wasChanged('is_active') && $exercise->is_active => "Упражнение «{$exercise->name}» снова доступно для выбора.",
            $exercise->wasChanged('is_active') => "Упражнение «{$exercise->name}» скрыто: выбрать его для клиента больше нельзя.",
            default => null,
        };

        return back()->with('status', $status);
    }
}
