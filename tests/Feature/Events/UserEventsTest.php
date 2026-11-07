<?php

namespace Tests\Feature\Events;

use App\Enums\Role;
use App\Events\Users\UserActivated;
use App\Events\Users\UserCreated;
use App\Events\Users\UserDeactivated;
use App\Events\Users\UserPasswordChanged;
use App\Events\Users\UserRolesChanged;
use App\Events\Users\UserUpdated;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Illuminate\Support\Facades\Event;
use Tests\TestCase;

/**
 * Creating and changing accounts announces domain events, wherever it happens:
 * the user settings, the instructors page, the profile and the console.
 */
class UserEventsTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function accountPayload(User $user, array $overrides = []): array
    {
        return [
            'name' => $user->name,
            'last_name' => $user->last_name,
            'email' => $user->email,
            'phone' => $user->phone,
            'roles' => $user->roles->map(fn (Role $role): string => $role->value)->all(),
            'color' => $user->color,
            'is_active' => $user->is_active,
            'notes' => $user->notes,
            ...$overrides,
        ];
    }

    public function test_an_account_created_in_the_settings_is_announced(): void
    {
        $admin = User::factory()->admin()->create();
        Event::fake([UserCreated::class]);

        $this->actingAs($admin)->post('/settings/users', [
            'name' => 'Анна',
            'email' => 'anna@aquastyle74.ru',
            'roles' => ['admin'],
            'password' => 'diving-2026',
            'password_confirmation' => 'diving-2026',
        ])->assertSessionHasNoErrors();

        Event::assertDispatched(UserCreated::class, fn (UserCreated $event): bool => $event->user->email === 'anna@aquastyle74.ru' && $event->actor->is($admin));
    }

    public function test_an_instructor_added_on_the_instructors_page_is_announced(): void
    {
        $admin = User::factory()->admin()->create();
        Event::fake([UserCreated::class]);

        $this->actingAs($admin)->post('/instructors', [
            'name' => 'Ирина',
            'email' => 'irina@aquastyle74.ru',
            'color' => '#0891b2',
            'password' => 'diving-2026',
            'password_confirmation' => 'diving-2026',
        ])->assertSessionHasNoErrors();

        Event::assertDispatched(UserCreated::class, fn (UserCreated $event): bool => $event->user->email === 'irina@aquastyle74.ru' && $event->actor->is($admin));
    }

    public function test_an_administrator_created_from_the_console_is_announced_without_an_actor(): void
    {
        Event::fake([UserCreated::class]);

        $this->artisan('app:create-admin', ['--name' => 'Анна', '--email' => 'anna@aquastyle74.ru'])
            ->expectsQuestion('Пароль (не короче 8 символов)', 'secret-password')
            ->expectsQuestion('Повторите пароль', 'secret-password')
            ->assertSuccessful();

        Event::assertDispatched(UserCreated::class, fn (UserCreated $event): bool => $event->user->email === 'anna@aquastyle74.ru' && $event->actor === null);
    }

    public function test_editing_an_account_announces_what_changed_without_the_password(): void
    {
        $admin = User::factory()->admin()->create();
        $user = User::factory()->create(['phone' => '+7 900 000-00-00']);
        Event::fake([UserUpdated::class, UserPasswordChanged::class]);

        $this->actingAs($admin)
            ->put("/settings/users/{$user->id}", $this->accountPayload($user, ['phone' => '+7 912 345-67-89', 'password' => 'new-password-1', 'password_confirmation' => 'new-password-1']))
            ->assertSessionHasNoErrors();

        Event::assertDispatched(UserUpdated::class, fn (UserUpdated $event): bool => $event->user->is($user)
            && $event->changes->toArray() === ['phone' => ['old' => '+7 900 000-00-00', 'new' => '+7 912 345-67-89']]
            && $event->actor->is($admin));
        Event::assertDispatched(UserPasswordChanged::class, fn (UserPasswordChanged $event): bool => $event->user->is($user) && ! $event->changedByOwner());
    }

    public function test_deactivating_and_activating_an_account_is_announced(): void
    {
        $admin = User::factory()->admin()->create();
        $user = User::factory()->create();
        Event::fake([UserActivated::class, UserDeactivated::class]);

        $this->actingAs($admin)->put("/settings/users/{$user->id}", $this->accountPayload($user, ['is_active' => false]))->assertSessionHasNoErrors();
        Event::assertDispatched(UserDeactivated::class, fn (UserDeactivated $event): bool => $event->user->is($user) && $event->actor->is($admin));
        Event::assertNotDispatched(UserActivated::class);

        $this->put("/instructors/{$user->id}", $this->accountPayload($user->refresh(), ['is_active' => true]))->assertSessionHasNoErrors();
        Event::assertDispatched(UserActivated::class, fn (UserActivated $event): bool => $event->user->is($user));
    }

    public function test_new_roles_are_announced_with_the_previous_ones(): void
    {
        $admin = User::factory()->admin()->create();
        $user = User::factory()->create(['roles' => [Role::Instructor]]);
        Event::fake([UserRolesChanged::class]);

        $this->actingAs($admin)->put("/settings/users/{$user->id}", $this->accountPayload($user, ['roles' => ['admin', 'instructor']]))->assertSessionHasNoErrors();

        Event::assertDispatched(UserRolesChanged::class, fn (UserRolesChanged $event): bool => $event->user->is($user)
            && $event->previousRoles === [Role::Instructor]);
    }

    public function test_editing_an_account_without_changes_is_not_announced(): void
    {
        $admin = User::factory()->admin()->create();
        $user = User::factory()->create();
        Event::fake([UserUpdated::class, UserPasswordChanged::class]);

        $this->actingAs($admin)->put("/settings/users/{$user->id}", $this->accountPayload($user))->assertSessionHasNoErrors();

        Event::assertNotDispatched(UserUpdated::class);
        Event::assertNotDispatched(UserPasswordChanged::class);
    }

    public function test_changes_in_the_own_profile_are_announced(): void
    {
        $user = User::factory()->create(['name' => 'Ира']);
        Event::fake([UserUpdated::class]);

        $this->actingAs($user)->patch('/profile', ['name' => 'Ирина', 'phone' => $user->phone])->assertSessionHasNoErrors();

        Event::assertDispatched(UserUpdated::class, fn (UserUpdated $event): bool => $event->changes->toArray() === ['name' => ['old' => 'Ира', 'new' => 'Ирина']]
            && $event->actor->is($user));
    }

    public function test_changing_the_own_password_announces_only_the_password_change(): void
    {
        $user = User::factory()->create();
        Event::fake([UserUpdated::class, UserPasswordChanged::class]);

        $this->actingAs($user)->put('/profile/password', [
            'current_password' => 'password',
            'password' => 'new-password-1',
            'password_confirmation' => 'new-password-1',
        ])->assertSessionHasNoErrors();

        Event::assertDispatched(UserPasswordChanged::class, fn (UserPasswordChanged $event): bool => $event->user->is($user) && $event->changedByOwner());
        Event::assertNotDispatched(UserUpdated::class);
    }

    public function test_choosing_the_schedule_range_is_not_announced(): void
    {
        $user = User::factory()->create();
        Event::fake([UserUpdated::class]);

        $this->actingAs($user)->patch('/schedule-range', ['range' => '1m'])->assertRedirect();

        Event::assertNotDispatched(UserUpdated::class);
    }
}
