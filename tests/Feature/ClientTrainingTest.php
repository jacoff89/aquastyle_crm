<?php

namespace Tests\Feature;

use App\Models\Certification;
use App\Models\Client;
use App\Models\ClientStatus;
use App\Models\User;
use Illuminate\Foundation\Testing\LazilyRefreshDatabase;
use Inertia\Testing\AssertableInertia as Assert;
use Tests\TestCase;

/**
 * A client's status (one at a time) and certifications (any number), chosen in the client form
 * from the lists administrators maintain.
 */
class ClientTrainingTest extends TestCase
{
    use LazilyRefreshDatabase;

    /**
     * @param  array<string, mixed>  $overrides
     * @return array<string, mixed>
     */
    private function payload(array $overrides = []): array
    {
        return ['last_name' => 'Иванов', 'first_name' => 'Пётр', 'phone' => '+7 912 345-67-89', ...$overrides];
    }

    /**
     * @return list<int>
     */
    private function certificationIdsOf(Client $client): array
    {
        return $client->certifications()->pluck('certifications.id')->sort()->values()->all();
    }

    public function test_client_is_added_with_a_status_and_certifications(): void
    {
        $status = ClientStatus::factory()->create();
        $diver = Certification::factory()->create();
        $drySuit = Certification::factory()->create();

        $this->actingAs(User::factory()->create())
            ->post('/clients', $this->payload(['client_status_id' => $status->id, 'certification_ids' => [$diver->id, $drySuit->id]]))
            ->assertSessionHasNoErrors()
            ->assertRedirect();

        $client = Client::sole();
        $this->assertSame($status->id, $client->client_status_id);
        $this->assertSame([$diver->id, $drySuit->id], $this->certificationIdsOf($client));
    }

    public function test_editing_replaces_certifications_and_clears_the_status(): void
    {
        $diver = Certification::factory()->create();
        $drySuit = Certification::factory()->create();
        $client = Client::factory()->hasAttached($diver)->create(['client_status_id' => ClientStatus::factory()->create()->id]);

        $this->actingAs(User::factory()->create())
            ->put("/clients/{$client->id}", $this->payload(['client_status_id' => null, 'certification_ids' => [$drySuit->id]]))
            ->assertSessionHasNoErrors();

        $this->assertNull($client->fresh()->client_status_id);
        $this->assertSame([$drySuit->id], $this->certificationIdsOf($client));
    }

    public function test_saving_without_certifications_in_the_request_keeps_them(): void
    {
        $diver = Certification::factory()->create();
        $client = Client::factory()->hasAttached($diver)->create();

        $this->actingAs(User::factory()->create())->put("/clients/{$client->id}", $this->payload())->assertSessionHasNoErrors();

        $this->assertSame([$diver->id], $this->certificationIdsOf($client));
    }

    public function test_hidden_status_and_certification_can_not_be_newly_chosen(): void
    {
        $hiddenStatus = ClientStatus::factory()->hidden()->create();
        $hiddenCertification = Certification::factory()->hidden()->create();
        $client = Client::factory()->create();

        $this->actingAs(User::factory()->create())
            ->put("/clients/{$client->id}", $this->payload(['client_status_id' => $hiddenStatus->id, 'certification_ids' => [$hiddenCertification->id]]))
            ->assertSessionHasErrors([
                'client_status_id' => 'Этот статус нельзя выбрать: его скрыли или удалили.',
                'certification_ids.0' => 'Одну из сертификаций нельзя выбрать: её скрыли или удалили.',
            ]);

        $this->assertNull($client->fresh()->client_status_id);
        $this->assertSame([], $this->certificationIdsOf($client));
    }

    public function test_client_keeps_a_hidden_status_and_certification_they_already_have(): void
    {
        $hiddenStatus = ClientStatus::factory()->hidden()->create();
        $hiddenCertification = Certification::factory()->hidden()->create();
        $client = Client::factory()->hasAttached($hiddenCertification)->create(['client_status_id' => $hiddenStatus->id]);

        $this->actingAs(User::factory()->create())
            ->put("/clients/{$client->id}", $this->payload(['client_status_id' => $hiddenStatus->id, 'certification_ids' => [$hiddenCertification->id]]))
            ->assertSessionHasNoErrors();

        $this->assertSame($hiddenStatus->id, $client->fresh()->client_status_id);
        $this->assertSame([$hiddenCertification->id], $this->certificationIdsOf($client));
    }

    public function test_repeated_certification_is_refused(): void
    {
        $diver = Certification::factory()->create();

        $this->actingAs(User::factory()->create())
            ->post('/clients', $this->payload(['certification_ids' => [$diver->id, $diver->id]]))
            ->assertSessionHasErrors('certification_ids.0');

        $this->assertDatabaseCount('clients', 0);
    }

    public function test_form_offers_visible_options_in_list_order_and_hidden_ones_the_client_has(): void
    {
        $waiting = ClientStatus::factory()->create(['name' => 'Ждёт сертификат']);
        $hiddenStatus = ClientStatus::factory()->hidden()->create(['name' => 'Старый курс']);
        ClientStatus::factory()->hidden()->create();
        $drySuit = Certification::factory()->create(['name' => 'Сухой костюм']);
        $hiddenCertification = Certification::factory()->hidden()->create(['name' => 'Ночной дайвер']);
        Certification::factory()->hidden()->create();
        $client = Client::factory()->hasAttached($hiddenCertification)->create(['client_status_id' => $hiddenStatus->id]);
        $user = User::factory()->create();

        $this->actingAs($user)
            ->get("/clients/{$client->id}/edit")
            ->assertInertia(fn (Assert $page) => $page
                ->where('client.clientStatusId', $hiddenStatus->id)
                ->where('client.certificationIds', [$hiddenCertification->id])
                ->where('statuses', [
                    ['id' => $waiting->id, 'name' => 'Ждёт сертификат', 'isActive' => true],
                    ['id' => $hiddenStatus->id, 'name' => 'Старый курс', 'isActive' => false],
                ])
                ->where('certifications', [
                    ['id' => $drySuit->id, 'name' => 'Сухой костюм', 'isActive' => true],
                    ['id' => $hiddenCertification->id, 'name' => 'Ночной дайвер', 'isActive' => false],
                ]));

        $this->actingAs($user)
            ->get('/clients/create')
            ->assertInertia(fn (Assert $page) => $page
                ->where('statuses', [['id' => $waiting->id, 'name' => 'Ждёт сертификат', 'isActive' => true]])
                ->where('certifications', [['id' => $drySuit->id, 'name' => 'Сухой костюм', 'isActive' => true]]));
    }

    public function test_card_shows_the_status_and_certifications_in_list_order(): void
    {
        $status = ClientStatus::factory()->create(['name' => 'Проходит курс плавучести']);
        $diver = Certification::factory()->create(['name' => 'Дайвер']);
        $drySuit = Certification::factory()->create(['name' => 'Сухой костюм']);
        $client = Client::factory()->hasAttached([$drySuit, $diver])->create(['client_status_id' => $status->id]);

        $this->actingAs(User::factory()->create())
            ->get("/clients/{$client->id}")
            ->assertInertia(fn (Assert $page) => $page
                ->where('client.statusName', 'Проходит курс плавучести')
                ->where('client.certificationNames', ['Дайвер', 'Сухой костюм']));
    }

    public function test_client_list_shows_the_status_of_parents_and_children(): void
    {
        $status = ClientStatus::factory()->create(['name' => 'Ждёт сертификат']);
        $parent = Client::factory()->create(['last_name' => 'Авдеев']);
        Client::factory()->create(['parent_id' => $parent->id, 'client_status_id' => $status->id]);

        $this->actingAs(User::factory()->create())
            ->get('/clients')
            ->assertInertia(fn (Assert $page) => $page
                ->where('clients.data.0.statusName', null)
                ->where('clients.data.1.statusName', 'Ждёт сертификат'));
    }
}
