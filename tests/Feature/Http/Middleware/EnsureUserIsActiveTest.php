<?php

namespace Tests\Feature\Http\Middleware;

use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Tests\TestCase;

class EnsureUserIsActiveTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_deactivated_user_is_logged_out_on_next_request(): void
    {
        $user = User::factory()->create();
        $this->actingAs($user)->get('/calendar')->assertOk();

        $user->update(['is_active' => false]);

        $this->get('/calendar')
            ->assertRedirect('/login')
            ->assertSessionHasErrors(['email' => 'Учётная запись отключена. Обратитесь к администратору.']);

        $this->assertGuest();
    }
}
