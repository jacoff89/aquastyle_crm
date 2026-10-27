<?php

namespace App\Http\Controllers\Settings;

use App\Enums\Role;
use App\Http\Controllers\Controller;
use App\Http\Requests\Settings\StoreUserRequest;
use App\Http\Requests\Settings\UpdateUserRequest;
use App\Models\User;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Gate;
use Inertia\Inertia;
use Inertia\Response;

class UserController extends Controller
{
    public function index(Request $request): Response
    {
        Gate::authorize('viewAny', User::class);

        return Inertia::render('settings/users/Index', [
            'users' => User::query()
                ->orderByDesc('is_active')
                ->orderBy('name')
                ->get()
                ->map(fn (User $user): array => [
                    'id' => $user->id,
                    'name' => $user->name,
                    'email' => $user->email,
                    'phone' => $user->phone,
                    'roleLabel' => $user->role->label(),
                    'isActive' => $user->is_active,
                    'isCurrentUser' => $user->is($request->user()),
                ]),
        ]);
    }

    public function create(): Response
    {
        Gate::authorize('create', User::class);

        return Inertia::render('settings/users/Form', [
            'user' => null,
            'roles' => $this->roleOptions(),
        ]);
    }

    public function store(StoreUserRequest $request): RedirectResponse
    {
        $user = new User(Arr::except($request->validated(), ['password']));
        $user->password = $request->validated('password');
        $user->creator()->associate($request->user());
        $user->save();

        return redirect()->route('settings.users.index')->with('status', "Добавлена учётная запись: {$user->name}.");
    }

    public function edit(Request $request, User $user): Response
    {
        Gate::authorize('update', $user);

        return Inertia::render('settings/users/Form', [
            'user' => [
                'id' => $user->id,
                'name' => $user->name,
                'email' => $user->email,
                'phone' => $user->phone,
                'role' => $user->role->value,
                'isActive' => $user->is_active,
                'notes' => $user->notes,
                'isCurrentUser' => $user->is($request->user()),
            ],
            'roles' => $this->roleOptions(),
        ]);
    }

    public function update(UpdateUserRequest $request, User $user): RedirectResponse
    {
        $user->fill(Arr::except($request->validated(), ['password']));

        if ($request->filled('password')) {
            $user->password = $request->validated('password');
        }

        $user->save();

        return redirect()->route('settings.users.index')->with('status', "Изменения сохранены: {$user->name}.");
    }

    /**
     * @return list<array{value: string, label: string}>
     */
    private function roleOptions(): array
    {
        return array_map(
            fn (Role $role): array => ['value' => $role->value, 'label' => $role->label()],
            Role::cases(),
        );
    }
}
