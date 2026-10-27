<?php

namespace App\Http\Controllers;

use App\Enums\EventStatus;
use App\Enums\Role;
use App\Http\Requests\Instructors\StoreInstructorRequest;
use App\Http\Requests\Instructors\UpdateInstructorRequest;
use App\Models\Event;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Support\Arr;
use Illuminate\Support\Carbon;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Instructors are users with the instructor role. They are deactivated rather
 * than deleted, so past classes keep their instructor.
 */
class InstructorController extends Controller
{
    public function index(): Response
    {
        Gate::authorize('viewAny', User::class);

        return Inertia::render('instructors/Index', [
            'instructors' => User::instructors()
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get()
                ->map(fn (User $instructor): array => [
                    'id' => $instructor->id,
                    'name' => $instructor->name,
                    'email' => $instructor->email,
                    'phone' => $instructor->phone,
                    'color' => $instructor->color,
                    'isActive' => $instructor->is_active,
                ]),
        ]);
    }

    public function create(): Response
    {
        Gate::authorize('create', User::class);

        return Inertia::render('instructors/Form', [
            'instructor' => null,
        ]);
    }

    public function store(StoreInstructorRequest $request): RedirectResponse
    {
        $instructor = new User(Arr::except($request->validated(), ['password']));
        $instructor->password = $request->validated('password');
        $instructor->role = Role::Instructor;
        $instructor->creator()->associate($request->user());
        $instructor->save();

        return redirect()->route('instructors.show', $instructor)->with('status', "Добавлен инструктор: {$instructor->name}.");
    }

    public function show(User $instructor): Response
    {
        Gate::authorize('view', $instructor);

        return Inertia::render('instructors/Show', [
            'instructor' => [
                'id' => $instructor->id,
                'name' => $instructor->name,
                'email' => $instructor->email,
                'phone' => $instructor->phone,
                'color' => $instructor->color,
                'notes' => $instructor->notes,
                'isActive' => $instructor->is_active,
            ],
            'schedule' => $this->schedule($instructor),
        ]);
    }

    public function edit(User $instructor): Response
    {
        Gate::authorize('update', $instructor);

        return Inertia::render('instructors/Form', [
            'instructor' => [
                'id' => $instructor->id,
                'name' => $instructor->name,
                'email' => $instructor->email,
                'phone' => $instructor->phone,
                'color' => $instructor->color,
                'notes' => $instructor->notes,
                'isActive' => $instructor->is_active,
            ],
        ]);
    }

    public function update(UpdateInstructorRequest $request, User $instructor): RedirectResponse
    {
        $instructor->fill(Arr::except($request->validated(), ['password']));

        if ($request->filled('password')) {
            $instructor->password = $request->validated('password');
        }

        $instructor->save();

        return redirect()->route('instructors.show', $instructor)->with('status', "Изменения сохранены: {$instructor->name}.");
    }

    /**
     * The instructor's events from today for the next two weeks, cancelled ones included.
     *
     * @return list<array{id: int, title: string, date: string, dateLabel: string, time: string, role: string, location: ?string, status: string, statusLabel: string, isCancelled: bool}>
     */
    private function schedule(User $instructor): array
    {
        $from = Carbon::today();

        return Event::query()
            ->with(['type', 'instructors' => fn ($query) => $query->whereKey($instructor->id)])
            ->withInstructor($instructor)
            ->overlapping($from, $from->copy()->addDays(14))
            ->orderBy('starts_at')
            ->get()
            ->map(fn (Event $event): array => [
                'id' => $event->id,
                'title' => $event->displayTitle(),
                'date' => $event->starts_at->format('Y-m-d'),
                'dateLabel' => $event->starts_at->translatedFormat('D, j F'),
                'time' => $event->starts_at->format('H:i').'–'.$event->ends_at->format('H:i'),
                'role' => $event->instructors->first()?->pivot->role->label() ?? '',
                'location' => $event->location,
                'status' => $event->status->value,
                'statusLabel' => $event->status->label(),
                'isCancelled' => $event->status === EventStatus::Cancelled,
            ])
            ->all();
    }
}
