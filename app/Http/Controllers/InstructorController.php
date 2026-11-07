<?php

namespace App\Http\Controllers;

use App\Actions\ListInstructorSchedule;
use App\Enums\Role;
use App\Enums\ScheduleRange;
use App\Events\Users\UserCreated;
use App\Events\Users\UserUpdated;
use App\Http\Requests\Instructors\StoreInstructorRequest;
use App\Http\Requests\Instructors\UpdateInstructorRequest;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

/**
 * Instructors are users with the instructor role, administrators who teach included.
 * They are deactivated rather than deleted, so past classes keep their instructor.
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
                    'lastName' => $instructor->last_name,
                    'lastName' => $instructor->last_name,
                    'email' => $instructor->email,
                    'phone' => $instructor->phone,
                    'color' => $instructor->color,
                    'isActive' => $instructor->is_active,
                    'isAdmin' => $instructor->isAdmin(),
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
        $instructor->roles = [Role::Instructor];
        $instructor->creator()->associate($request->user());
        $instructor->save();

        UserCreated::dispatch($instructor, $request->user());

        return redirect()->route('instructors.show', $instructor)->with('status', "Добавлен инструктор: {$instructor->name}.");
    }

    public function show(Request $request, User $instructor, ListInstructorSchedule $schedule): Response
    {
        Gate::authorize('view', $instructor);

        $range = $request->user()->preferredScheduleRange();

        return Inertia::render('instructors/Show', [
            'instructor' => [
                'id' => $instructor->id,
                'name' => $instructor->name,
                'lastName' => $instructor->last_name,
                'email' => $instructor->email,
                'phone' => $instructor->phone,
                'color' => $instructor->color,
                'notes' => $instructor->notes,
                'isActive' => $instructor->is_active,
                'equipmentCount' => $instructor->equipment()->count(),
            ],
            'schedule' => $schedule->handle($instructor, $range),
            'scheduleRange' => $range->value,
            'scheduleRanges' => ScheduleRange::options(),
        ]);
    }

    public function edit(Request $request, User $instructor): Response
    {
        Gate::authorize('update', $instructor);

        return Inertia::render('instructors/Form', [
            'instructor' => [
                'id' => $instructor->id,
                'name' => $instructor->name,
                'lastName' => $instructor->last_name,
                'email' => $instructor->email,
                'phone' => $instructor->phone,
                'color' => $instructor->color,
                'notes' => $instructor->notes,
                'isActive' => $instructor->is_active,
                'isCurrentUser' => $instructor->is($request->user()),
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

        UserUpdated::dispatchChanges($instructor, $request->user());

        return redirect()->route('instructors.show', $instructor)->with('status', "Изменения сохранены: {$instructor->name}.");
    }
}
