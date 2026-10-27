<?php

namespace Tests\Feature\Http\Middleware;

use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class HandleInertiaRequestsTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_signed_in_user_and_role_are_shared_with_every_page(): void
    {
        $admin = User::factory()->admin()->create(['name' => 'Анна Петрова']);

        $this->actingAs($admin)
            ->get('/calendar')
            ->assertInertia(fn (Assert $page) => $page
                ->component('calendar/Index')
                ->where('auth.user.name', 'Анна Петрова')
                ->where('auth.user.roles', ['admin'])
                ->where('auth.user.roleLabel', 'Администратор')
                ->where('can.manageUsers', true)
                ->where('can.manageInstructors', true)
                ->where('can.manageEventTypes', true));
    }

    public function test_administrator_who_teaches_has_both_roles_in_the_menu(): void
    {
        $this->actingAs(User::factory()->adminInstructor()->create())
            ->get('/calendar')
            ->assertInertia(fn (Assert $page) => $page
                ->where('auth.user.roles', ['admin', 'instructor'])
                ->where('auth.user.roleLabel', 'Администратор, инструктор')
                ->where('can.manageUsers', true));
    }

    public function test_instructor_does_not_get_settings_in_the_menu(): void
    {
        $this->actingAs(User::factory()->create())
            ->get('/calendar')
            ->assertInertia(fn (Assert $page) => $page
                ->where('auth.user.roleLabel', 'Инструктор')
                ->where('can.manageUsers', false)
                ->where('can.manageInstructors', false)
                ->where('can.manageEventTypes', false));
    }
}
