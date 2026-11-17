<?php

namespace Tests\Feature\Settings;

use App\Models\Certification;
use App\Models\Client;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

class CertificationControllerTest extends TestCase
{
    use LazilyRefreshDatabase;

    public function test_admin_sees_certifications_in_list_order_with_hidden_ones_and_their_clients_count(): void
    {
        $hidden = Certification::factory()->hidden()->create(['name' => 'Сухой костюм']);
        $diver = Certification::factory()->create(['name' => 'Дайвер']);
        Client::factory()->count(2)->hasAttached($diver)->create();
        Client::factory()->hasAttached($diver)->create()->delete();

        $this->actingAs(User::factory()->admin()->create())
            ->get('/settings/certifications')
            ->assertOk()
            ->assertInertia(fn (Assert $page) => $page
                ->component('settings/certifications/Index')
                ->where('certifications', [
                    ['id' => $hidden->id, 'name' => 'Сухой костюм', 'isActive' => false, 'clientsCount' => 0],
                    ['id' => $diver->id, 'name' => 'Дайвер', 'isActive' => true, 'clientsCount' => 2],
                ]));
    }

    public function test_admin_adds_certification_to_the_end_of_the_list(): void
    {
        $first = Certification::factory()->create();

        $this->actingAs(User::factory()->admin()->create())
            ->post('/settings/certifications', ['name' => '  Сухой костюм  '])
            ->assertSessionHas('status', 'Сертификация «Сухой костюм» добавлена.');

        $added = Certification::query()->where('name', 'Сухой костюм')->sole();
        $this->assertTrue($added->is_active);
        $this->assertSame([$first->id, $added->id], Certification::query()->ordered()->pluck('id')->all());
    }

    public function test_certification_name_is_required_and_unique(): void
    {
        Certification::factory()->create(['name' => 'Сухой костюм']);
        $other = Certification::factory()->create(['name' => 'Дайвер']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->post('/settings/certifications', ['name' => ' '])->assertSessionHasErrors(['name' => 'Поле «Название» обязательно для заполнения.']);
        $this->actingAs($admin)->post('/settings/certifications', ['name' => 'Сухой костюм'])->assertSessionHasErrors('name');
        $this->actingAs($admin)->patch("/settings/certifications/{$other->id}", ['name' => 'Сухой костюм'])->assertSessionHasErrors('name');

        $this->assertDatabaseCount('certifications', 2);
        $this->assertSame('Дайвер', $other->fresh()->name);
    }

    public function test_admin_renames_hides_and_returns_certification(): void
    {
        $certification = Certification::factory()->create(['name' => 'Старое']);
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)
            ->patch("/settings/certifications/{$certification->id}", ['name' => 'Новое'])
            ->assertSessionHas('status', 'Сертификация переименована в «Новое».');
        $this->actingAs($admin)
            ->patch("/settings/certifications/{$certification->id}", ['is_active' => false])
            ->assertSessionHas('status', 'Сертификация «Новое» скрыта: у кого она уже есть, она останется, но выбрать её заново нельзя.');
        $this->assertFalse($certification->fresh()->is_active);

        $this->actingAs($admin)
            ->patch("/settings/certifications/{$certification->id}", ['is_active' => true])
            ->assertSessionHas('status', 'Сертификация «Новое» снова доступна для выбора.');
        $this->assertTrue($certification->fresh()->is_active);
    }

    public function test_admin_moves_certification_up_and_down(): void
    {
        $first = Certification::factory()->create();
        $second = Certification::factory()->create();
        $third = Certification::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/settings/certifications/{$third->id}/position", ['direction' => 'up'])->assertRedirect();
        $this->assertSame([$first->id, $third->id, $second->id], Certification::query()->ordered()->pluck('id')->all());

        $this->actingAs($admin)->patch("/settings/certifications/{$first->id}/position", ['direction' => 'down'])->assertRedirect();
        $this->assertSame([$third->id, $first->id, $second->id], Certification::query()->ordered()->pluck('id')->all());
    }

    public function test_moving_past_the_ends_of_the_list_changes_nothing(): void
    {
        $first = Certification::factory()->create();
        $last = Certification::factory()->create();
        $admin = User::factory()->admin()->create();

        $this->actingAs($admin)->patch("/settings/certifications/{$first->id}/position", ['direction' => 'up'])->assertRedirect();
        $this->actingAs($admin)->patch("/settings/certifications/{$last->id}/position", ['direction' => 'down'])->assertRedirect();
        $this->actingAs($admin)->patch("/settings/certifications/{$last->id}/position", ['direction' => 'sideways'])->assertSessionHasErrors('direction');

        $this->assertSame([$first->id, $last->id], Certification::query()->ordered()->pluck('id')->all());
    }

    public function test_instructor_can_not_open_add_change_or_move_certifications(): void
    {
        $certification = Certification::factory()->create();
        $instructor = User::factory()->create();

        $this->actingAs($instructor)->get('/settings/certifications')->assertForbidden();
        $this->actingAs($instructor)->post('/settings/certifications', ['name' => 'Новое'])->assertForbidden();
        $this->actingAs($instructor)->patch("/settings/certifications/{$certification->id}", ['is_active' => false])->assertForbidden();
        $this->actingAs($instructor)->patch("/settings/certifications/{$certification->id}/position", ['direction' => 'up'])->assertForbidden();

        $this->assertDatabaseCount('certifications', 1);
        $this->assertTrue($certification->fresh()->is_active);
    }

    public function test_guest_is_redirected_to_login(): void
    {
        $this->get('/settings/certifications')->assertRedirect('/login');
    }
}
