<?php

namespace Tests\Feature\Settings;

use App\Models\Client;
use App\Models\ClientStatus;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class ClientStatusControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_sees_statuses_in_list_order_with_hidden_ones_and_their_clients_count(): void
    {
        $hidden = ClientStatus::factory()->hidden()->create(['name' => 'Ждёт сертификат']);
        $pool = ClientStatus::factory()->create(['name' => 'Закрытая вода']);
        Client::factory()->count(2)->create(['client_status_id' => $pool->id]);
        Client::factory()->create(['client_status_id' => $pool->id])->delete();

        $this->actingAs(User::factory()->admin()->create())
            ->get('/settings/client-statuses')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('settings/client-statuses/Index')
                ->where('clientStatuses', [
                    ['id' => $hidden->id, 'name' => 'Ждёт сертификат', 'isActive' => false, 'clientsCount' => 0],
                    ['id' => $pool->id, 'name' => 'Закрытая вода', 'isActive' => true, 'clientsCount' => 2],
                ]));
    }

    public function test_admin_adds_status_to_the_end_of_the_list(): void
    {
        $first = ClientStatus::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/client-statuses', ['name' => '  Ждёт сертификат  '])
            ->assertSessionHas('status', 'Статус «Ждёт сертификат» добавлен.');

        $added = ClientStatus::query()->where('name', 'Ждёт сертификат')->sole();
        $this->assertTrue($added->is_active);
        $this->assertSame([$first->id, $added->id], ClientStatus::query()->ordered()->pluck('id')->all());
    }

    public function test_status_name_is_required_and_unique(): void
    {
        ClientStatus::factory()->create(['name' => 'Ждёт сертификат']);
        $other = ClientStatus::factory()->create(['name' => 'Закрытая вода']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->post('/settings/client-statuses', ['name' => ' '])->assertSessionHasErrors(['name' => 'Поле «Название» обязательно для заполнения.']);
        $this->actingAs($admin)->post('/settings/client-statuses', ['name' => 'Ждёт сертификат'])->assertSessionHasErrors('name');
        $this->actingAs($admin)->patch("/settings/client-statuses/{$other->id}", ['name' => 'Ждёт сертификат'])->assertSessionHasErrors('name');

        $this->assertDatabaseCount('client_statuses', 2);
        $this->assertSame('Закрытая вода', $other->fresh()->name);
    }

    public function test_admin_renames_hides_and_returns_status(): void
    {
        $status = ClientStatus::factory()->create(['name' => 'Старое']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->patch("/settings/client-statuses/{$status->id}", ['name' => 'Новое'])
            ->assertSessionHas('status', 'Статус переименован в «Новое».');
        $this->actingAs($admin)
            ->patch("/settings/client-statuses/{$status->id}", ['is_active' => false])
            ->assertSessionHas('status', 'Статус «Новое» скрыт: у кого он уже стоит, он останется, но выбрать его заново нельзя.');
        $this->assertFalse($status->fresh()->is_active);

        $this->actingAs($admin)
            ->patch("/settings/client-statuses/{$status->id}", ['is_active' => true])
            ->assertSessionHas('status', 'Статус «Новое» снова можно выбрать для клиента.');
        $this->assertTrue($status->fresh()->is_active);
    }

    public function test_admin_moves_status_up_and_down(): void
    {
        $first = ClientStatus::factory()->create();
        $second = ClientStatus::factory()->create();
        $third = ClientStatus::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/settings/client-statuses/{$third->id}/position", ['direction' => 'up'])->assertRedirect();
        $this->assertSame([$first->id, $third->id, $second->id], ClientStatus::query()->ordered()->pluck('id')->all());

        $this->actingAs($admin)->patch("/settings/client-statuses/{$first->id}/position", ['direction' => 'down'])->assertRedirect();
        $this->assertSame([$third->id, $first->id, $second->id], ClientStatus::query()->ordered()->pluck('id')->all());
    }

    public function test_moving_past_the_ends_of_the_list_changes_nothing(): void
    {
        $first = ClientStatus::factory()->create();
        $last = ClientStatus::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/settings/client-statuses/{$first->id}/position", ['direction' => 'up'])->assertRedirect();
        $this->actingAs($admin)->patch("/settings/client-statuses/{$last->id}/position", ['direction' => 'down'])->assertRedirect();
        $this->actingAs($admin)->patch("/settings/client-statuses/{$last->id}/position", ['direction' => 'sideways'])->assertSessionHasErrors('direction');

        $this->assertSame([$first->id, $last->id], ClientStatus::query()->ordered()->pluck('id')->all());
    }

    public function test_instructor_can_not_open_add_change_or_move_statuses(): void
    {
        $status = ClientStatus::factory()->create();
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->get('/settings/client-statuses')->assertForbidden();
        $this->actingAs($instructor)->post('/settings/client-statuses', ['name' => 'Новое'])->assertForbidden();
        $this->actingAs($instructor)->patch("/settings/client-statuses/{$status->id}", ['is_active' => false])->assertForbidden();
        $this->actingAs($instructor)->patch("/settings/client-statuses/{$status->id}/position", ['direction' => 'up'])->assertForbidden();

        $this->assertDatabaseCount('client_statuses', 1);
        $this->assertTrue($status->fresh()->is_active);
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/settings/client-statuses')->assertRedirect('/login');
    }
}
